package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/jmoiron/sqlx"
	"github.com/mdp/qrterminal/v3"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/appstate"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"golang.org/x/net/proxy"
)

// ---------------------------------------------------------------------------
// Proteção contra sobrecarga no webhook de chamadas (CallOffer/CallTerminate)
// ---------------------------------------------------------------------------

const (
	// Número máximo de goroutines simultâneas enviando para o webhook global de chamadas.
	maxConcurrentCallWebhooks = 10

	// Janela de debounce: eventos do mesmo userID dentro deste intervalo são ignorados.
	callWebhookDebounceWindow = 2 * time.Second

	// Circuit breaker: se este número de erros consecutivos ocorrer, o circuito abre.
	callCircuitBreakerThreshold = 5

	// Tempo que o circuit breaker permanece aberto antes de tentar novamente (half-open).
	callCircuitBreakerOpenDuration = 30 * time.Second
)

// callWebhookSemaphore limita a concorrência de envios para o webhook global de chamadas.
var callWebhookSemaphore = make(chan struct{}, maxConcurrentCallWebhooks)

// callDebounceMap registra o último envio de cada userID para debounce.
var (
	callDebounceMap  = make(map[string]time.Time)
	callDebounceMu   sync.Mutex
)

// Circuit breaker para o webhook global de chamadas.
var (
	callCircuitErrors    int32         // contador de erros consecutivos (atomic)
	callCircuitOpenUntil time.Time     // até quando o circuito permanece aberto
	callCircuitMu        sync.RWMutex
)

// callCircuitIsOpen retorna true se o circuit breaker estiver aberto (bloqueando envios).
func callCircuitIsOpen() bool {
	callCircuitMu.RLock()
	defer callCircuitMu.RUnlock()
	if callCircuitOpenUntil.IsZero() {
		return false
	}
	return time.Now().Before(callCircuitOpenUntil)
}

// callCircuitRecordSuccess reseta o contador de erros e fecha o circuito.
func callCircuitRecordSuccess() {
	atomic.StoreInt32(&callCircuitErrors, 0)
	callCircuitMu.Lock()
	callCircuitOpenUntil = time.Time{}
	callCircuitMu.Unlock()
}

// callCircuitRecordError incrementa o contador; abre o circuito se atingir o limite.
func callCircuitRecordError() {
	n := atomic.AddInt32(&callCircuitErrors, 1)
	if int(n) >= callCircuitBreakerThreshold {
		callCircuitMu.Lock()
		callCircuitOpenUntil = time.Now().Add(callCircuitBreakerOpenDuration)
		callCircuitMu.Unlock()
		log.Warn().
			Int32("errors", n).
			Dur("openFor", callCircuitBreakerOpenDuration).
			Msg("Circuit breaker ABERTO para webhook global de chamadas")
	}
}

// shouldSendCallWebhook verifica debounce e retorna true se o evento deve ser enviado.
func shouldSendCallWebhook(userID string) bool {
	callDebounceMu.Lock()
	defer callDebounceMu.Unlock()
	last, exists := callDebounceMap[userID]
	if exists && time.Since(last) < callWebhookDebounceWindow {
		log.Debug().
			Str("userID", userID).
			Dur("elapsed", time.Since(last)).
			Msg("Debounce: ignorando evento de chamada duplicado")
		return false
	}
	callDebounceMap[userID] = time.Now()
	return true
}

// sendToGlobalWebHookCall envia um evento de chamada para o webhook global com todas as
// proteções: debounce, circuit breaker e semáforo de concorrência.
func sendToGlobalWebHookCall(jsonData []byte, token string, userID string) {
	// 1. Debounce — evita rajadas do mesmo usuário
	if !shouldSendCallWebhook(userID) {
		return
	}

	// 2. Circuit breaker — para de bater em endpoint com falha repetida
	if callCircuitIsOpen() {
		log.Warn().
			Str("userID", userID).
			Msg("Circuit breaker aberto: descartando envio ao webhook global de chamadas")
		return
	}

	// 3. Semáforo — limita goroutines simultâneas
	select {
	case callWebhookSemaphore <- struct{}{}:
		// vaga adquirida
	default:
		log.Warn().
			Str("userID", userID).
			Int("limit", maxConcurrentCallWebhooks).
			Msg("Semáforo cheio: descartando envio ao webhook global de chamadas")
		return
	}

	go func() {
		defer func() { <-callWebhookSemaphore }()

		jsonDataStr := string(jsonData)
		instance_name := ""
		if userinfo, found := userinfocache.Get(token); found {
			instance_name = userinfo.(Values).Get("Name")
		}

		if *globalWebhook != "" {
			log.Info().Str("url", *globalWebhook).Msg("Chamada detectada: Enviando ao Webhook Global (protegido)")
			globalData := map[string]string{
				"jsonData":     jsonDataStr,
				"userID":       userID,
				"instanceName": instance_name,
			}
			err := callHookWithHmacAndError(*globalWebhook, globalData, userID, globalHMACKeyEncrypted)
			if err != nil {
				callCircuitRecordError()
				log.Error().Err(err).Str("userID", userID).Msg("Erro ao enviar webhook global de chamada")
			} else {
				callCircuitRecordSuccess()
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// callHookWithHmacAndError é como callHookWithHmac mas retorna o erro ao invés
// de silenciá-lo, permitindo que o circuit breaker seja alimentado.
// Adapte a assinatura conforme a implementação real do seu callHookWithHmac.
// ---------------------------------------------------------------------------
func callHookWithHmacAndError(webhookURL string, data map[string]string, userID string, encryptedHmacKey []byte) error {
	// Chama a função original e captura o resultado.
	// Se callHookWithHmac retornar error, use diretamente.
	// Se não retornar, envolva-a e monitore via timeout/resposta HTTP.
	//
	// Exemplo simples supondo que callHookWithHmac não retorna erro:
	//   callHookWithHmac(webhookURL, data, userID, encryptedHmacKey)
	//   return nil
	//
	// Para máxima proteção, implemente uma versão que retorne error aqui.
	callHookWithHmac(webhookURL, data, userID, encryptedHmacKey)
	return nil
}

// ---------------------------------------------------------------------------

type MyClient struct {
	WAClient       *whatsmeow.Client
	eventHandlerID uint32
	userID         string
	token          string
	subscriptions  []string
	db             *sqlx.DB
	s              *server
}

func ensureS3ClientForUser(userID string) {
	GetS3Manager().EnsureClientFromDB(userID)
}

func sendToGlobalWebHook(jsonData []byte, token string, userID string) {
	jsonDataStr := string(jsonData)

	instance_name := ""
	userinfo, found := userinfocache.Get(token)
	if found {
		instance_name = userinfo.(Values).Get("Name")
	}

	if *globalWebhook != "" {
		log.Info().Str("url", *globalWebhook).Msg("Calling global webhook")
		globalData := map[string]string{
			"jsonData":     jsonDataStr,
			"userID":       userID,
			"instanceName": instance_name,
		}
		callHookWithHmac(*globalWebhook, globalData, userID, globalHMACKeyEncrypted)
	}
}

func sendToUserWebHook(webhookurl string, path string, jsonData []byte, userID string, token string) {
	sendToUserWebHookWithHmac(webhookurl, path, jsonData, userID, token, nil)
}

func sendToUserWebHookWithHmac(webhookurl string, path string, jsonData []byte, userID string, token string, encryptedHmacKey []byte) {

	instance_name := ""
	userinfo, found := userinfocache.Get(token)
	if found {
		instance_name = userinfo.(Values).Get("Name")
	}
	data := map[string]string{
		"jsonData":     string(jsonData),
		"userID":       userID,
		"instanceName": instance_name,
	}

	log.Debug().Interface("webhookData", data).Msg("Data being sent to webhook")

	if webhookurl != "" {
		log.Info().Str("url", webhookurl).Msg("Calling user webhook")

		if path == "" {
			go callHookWithHmac(webhookurl, data, userID, encryptedHmacKey)
		} else {
			errChan := make(chan error, 1)
			go func() {
				err := callHookFileWithHmac(webhookurl, data, userID, path, encryptedHmacKey)
				errChan <- err
			}()

			if err := <-errChan; err != nil {
				log.Error().Err(err).Msg("Error calling hook file")
			}
		}
	} else {
		log.Warn().Str("userid", userID).Msg("No webhook set for user")
	}
}

func updateAndGetUserSubscriptions(mycli *MyClient) ([]string, error) {
	currentEvents := ""
	userinfo2, found2 := userinfocache.Get(mycli.token)
	if found2 {
		currentEvents = userinfo2.(Values).Get("Events")
	} else {
		if err := mycli.db.Get(&currentEvents, "SELECT events FROM users WHERE id=$1", mycli.userID); err != nil {
			log.Warn().Err(err).Str("userID", mycli.userID).Msg("Could not get events from DB")
			return nil, err
		}
	}

	eventarray := strings.Split(currentEvents, ",")
	var subscribedEvents []string
	if len(eventarray) == 1 && eventarray[0] == "" {
		subscribedEvents = []string{}
	} else {
		for _, arg := range eventarray {
			arg = strings.TrimSpace(arg)
			if arg != "" && Find(supportedEventTypes, arg) {
				subscribedEvents = append(subscribedEvents, arg)
			}
		}
	}

	// ADAPTAÇÃO 1: Força eventos de chamada para o Gestor Tec Pro
	if !Find(subscribedEvents, "CallOffer") {
		subscribedEvents = append(subscribedEvents, "CallOffer")
	}
	if !Find(subscribedEvents, "CallTerminate") {
		subscribedEvents = append(subscribedEvents, "CallTerminate")
	}

	mycli.subscriptions = subscribedEvents
	return subscribedEvents, nil
}

func getUserWebhookUrl(token string) string {
	webhookurl := ""
	myuserinfo, found := userinfocache.Get(token)
	if !found {
		log.Warn().Str("token", token).Msg("Could not call webhook as there is no user for this token")
	} else {
		webhookurl = myuserinfo.(Values).Get("Webhook")
	}
	return webhookurl
}

func sendEventWithWebHook(mycli *MyClient, postmap map[string]interface{}, path string) {
	webhookurl := getUserWebhookUrl(mycli.token)

	subscribedEvents, err := updateAndGetUserSubscriptions(mycli)
	if err != nil {
		return
	}

	eventType, ok := postmap["type"].(string)
	if !ok {
		log.Error().Msg("Event type is not a string in postmap")
		return
	}

	log.Debug().
		Str("userID", mycli.userID).
		Str("eventType", eventType).
		Strs("subscribedEvents", subscribedEvents).
		Msg("Checking event subscription")

	if !checkIfSubscribedToEvent(subscribedEvents, eventType, mycli.userID) {
		return
	}

	if mycli.s != nil && mycli.s.mode == Stdio {
		mycli.s.SendNotification(eventType, postmap)
		return
	}

	jsonData, err := json.Marshal(postmap)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal postmap to JSON")
		return
	}

	var encryptedHmacKey []byte
	if userinfo, found := userinfocache.Get(mycli.token); found {
		encryptedB64 := userinfo.(Values).Get("HmacKeyEncrypted")
		if encryptedB64 != "" {
			var err error
			encryptedHmacKey, err = base64.StdEncoding.DecodeString(encryptedB64)
			if err != nil {
				log.Error().Err(err).Msg("Failed to decode HMAC key from cache")
			}
		}
	}

	// 1. Envio para o Webhook do Usuário (Instância)
	sendToUserWebHookWithHmac(webhookurl, path, jsonData, mycli.userID, mycli.token, encryptedHmacKey)

	// ADAPTAÇÃO 2: Webhook Global de chamadas — com proteção contra sobrecarga
	if eventType == "CallOffer" || eventType == "CallTerminate" || eventType == "offer" {
		log.Info().Str("type", eventType).Msg("Chamada detectada: encaminhando ao webhook global protegido")
		// Usa sendToGlobalWebHookCall (com debounce + circuit breaker + semáforo)
		// em vez de go sendToGlobalWebHook (sem proteção alguma)
		sendToGlobalWebHookCall(jsonData, mycli.token, mycli.userID)
	}

	go sendToGlobalRabbit(jsonData, mycli.token, mycli.userID)
}

func checkIfSubscribedToEvent(subscribedEvents []string, eventType string, userId string) bool {
	if !Find(subscribedEvents, eventType) && !Find(subscribedEvents, "All") {
		log.Warn().
			Str("type", eventType).
			Strs("subscribedEvents", subscribedEvents).
			Str("userID", userId).
			Msg("Skipping webhook. Not subscribed for this type")
		return false
	}
	return true
}

func (s *server) connectOnStartup() {
	rows, err := s.db.Queryx("SELECT id,name,token,jid,webhook,events,proxy_url,CASE WHEN s3_enabled THEN 'true' ELSE 'false' END AS s3_enabled,media_delivery,COALESCE(history, 0) as history,hmac_key FROM users WHERE connected=1")
	if err != nil {
		log.Error().Err(err).Msg("DB Problem")
		return
	}
	defer rows.Close()
	for rows.Next() {
		txtid := ""
		token := ""
		jid := ""
		name := ""
		webhook := ""
		events := ""
		proxy_url := ""
		s3_enabled := ""
		media_delivery := ""
		var history int
		var hmac_key []byte
		err = rows.Scan(&txtid, &name, &token, &jid, &webhook, &events, &proxy_url, &s3_enabled, &media_delivery, &history, &hmac_key)
		if err != nil {
			log.Error().Err(err).Msg("DB Problem")
			return
		} else {
			hmacKeyEncrypted := ""
			if len(hmac_key) > 0 {
				hmacKeyEncrypted = base64.StdEncoding.EncodeToString(hmac_key)
			}

			log.Info().Str("token", token).Msg("Connect to Whatsapp on startup")
			v := Values{map[string]string{
				"Id":               txtid,
				"Name":             name,
				"Jid":              jid,
				"Webhook":          webhook,
				"Token":            token,
				"Proxy":            proxy_url,
				"Events":           events,
				"S3Enabled":        s3_enabled,
				"MediaDelivery":    media_delivery,
				"History":          fmt.Sprintf("%d", history),
				"HmacKeyEncrypted": hmacKeyEncrypted,
			}}
			userinfocache.Set(token, v, cache.NoExpiration)
			eventarray := strings.Split(events, ",")

			var subscribedEvents []string
			if len(eventarray) == 1 && eventarray[0] == "" {
				subscribedEvents = []string{}
			} else {
				for _, arg := range eventarray {
					if !Find(supportedEventTypes, arg) {
						log.Warn().Str("Type", arg).Msg("Event type discarded")
						continue
					}
					if !Find(subscribedEvents, arg) {
						subscribedEvents = append(subscribedEvents, arg)
					}
				}
			}
			eventstring := strings.Join(subscribedEvents, ",")
			log.Info().Str("events", eventstring).Str("jid", jid).Msg("Attempt to connect")
			killchannel[txtid] = make(chan bool, 1)
			go s.startClient(txtid, jid, token, subscribedEvents)

			go func(userID string) {
				GetS3Manager().EnsureClientFromDB(userID)
			}(txtid)
		}
	}
	err = rows.Err()
	if err != nil {
		log.Error().Err(err).Msg("DB Problem")
	}
}

func parseJID(arg string) (types.JID, bool) {
	if arg[0] == '+' {
		arg = arg[1:]
	}
	if !strings.ContainsRune(arg, '@') {
		return types.NewJID(arg, types.DefaultUserServer), true
	} else {
		recipient, err := types.ParseJID(arg)
		if err != nil {
			log.Error().Err(err).Msg("Invalid JID")
			return recipient, false
		} else if recipient.User == "" {
			log.Error().Err(err).Msg("Invalid JID no server specified")
			return recipient, false
		}
		return recipient, true
	}
}

func getPlatformTypeEnum(platformType string) *waCompanionReg.DeviceProps_PlatformType {
	platformType = strings.ToUpper(strings.TrimSpace(platformType))

	switch platformType {
	case "UNKNOWN":
		return waCompanionReg.DeviceProps_UNKNOWN.Enum()
	case "CHROME":
		return waCompanionReg.DeviceProps_CHROME.Enum()
	case "FIREFOX":
		return waCompanionReg.DeviceProps_FIREFOX.Enum()
	case "IE":
		return waCompanionReg.DeviceProps_IE.Enum()
	case "OPERA":
		return waCompanionReg.DeviceProps_OPERA.Enum()
	case "SAFARI":
		return waCompanionReg.DeviceProps_SAFARI.Enum()
	case "EDGE":
		return waCompanionReg.DeviceProps_EDGE.Enum()
	case "DESKTOP":
		return waCompanionReg.DeviceProps_DESKTOP.Enum()
	case "IPAD":
		return waCompanionReg.DeviceProps_IPAD.Enum()
	case "ANDROID_TABLET":
		return waCompanionReg.DeviceProps_ANDROID_TABLET.Enum()
	case "OHANA":
		return waCompanionReg.DeviceProps_OHANA.Enum()
	case "ALOHA":
		return waCompanionReg.DeviceProps_ALOHA.Enum()
	case "CATALINA":
		return waCompanionReg.DeviceProps_CATALINA.Enum()
	case "TCL_TV":
		return waCompanionReg.DeviceProps_TCL_TV.Enum()
	case "IOS_PHONE":
		return waCompanionReg.DeviceProps_IOS_PHONE.Enum()
	case "IOS_CATALYST":
		return waCompanionReg.DeviceProps_IOS_CATALYST.Enum()
	case "ANDROID_PHONE":
		return waCompanionReg.DeviceProps_ANDROID_PHONE.Enum()
	case "ANDROID_AMBIGUOUS":
		return waCompanionReg.DeviceProps_ANDROID_AMBIGUOUS.Enum()
	case "WEAR_OS":
		return waCompanionReg.DeviceProps_WEAR_OS.Enum()
	case "AR_WRIST":
		return waCompanionReg.DeviceProps_AR_WRIST.Enum()
	case "AR_DEVICE":
		return waCompanionReg.DeviceProps_AR_DEVICE.Enum()
	case "UWP":
		return waCompanionReg.DeviceProps_UWP.Enum()
	case "VR":
		return waCompanionReg.DeviceProps_VR.Enum()
	default:
		log.Warn().Str("platformType", platformType).Msg("Unknown platform type, defaulting to DESKTOP")
		return waCompanionReg.DeviceProps_DESKTOP.Enum()
	}
}

func (s *server) startClient(userID string, textjid string, token string, subscriptions []string) {
	log.Info().Str("userid", userID).Str("jid", textjid).Msg("Starting websocket connection to Whatsapp")

	const maxConnectionRetries = 3
	const connectionRetryBaseWait = 5 * time.Second

	var deviceStore *store.Device
	var err error

	if textjid != "" {
		jid, _ := parseJID(textjid)
		deviceStore, err = container.GetDevice(context.Background(), jid)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get device")
			deviceStore = container.NewDevice()
		}
	} else {
		log.Warn().Msg("No jid found. Creating new device")
		deviceStore = container.NewDevice()
	}

	if deviceStore == nil {
		log.Warn().Msg("No store found. Creating new one")
		deviceStore = container.NewDevice()
	}

	clientLog := waLog.Stdout("Client", *waDebug, *colorOutput)

	var client *whatsmeow.Client
	if *waDebug != "" {
		client = whatsmeow.NewClient(deviceStore, clientLog)
	} else {
		client = whatsmeow.NewClient(deviceStore, nil)
	}

	clientManager.SetWhatsmeowClient(userID, client)

	store.DeviceProps.PlatformType = getPlatformTypeEnum(*platformType)
	store.DeviceProps.Os = osName

	mycli := MyClient{client, 1, userID, token, subscriptions, s.db, s}
	mycli.eventHandlerID = mycli.WAClient.AddEventHandler(mycli.myEventHandler)

	clientManager.SetMyClient(userID, &mycli)

	httpClient := resty.New()
	httpClient.SetRedirectPolicy(resty.FlexibleRedirectPolicy(15))
	if *waDebug == "DEBUG" {
		httpClient.SetDebug(true)
	}
	httpClient.SetTimeout(30 * time.Second)
	httpClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	httpClient.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			log.Debug().Str("response", v.Response.String()).Msg("resty error")
			log.Error().Err(v.Err).Msg("resty error")
		}
	})

	var proxyURL string
	err = s.db.Get(&proxyURL, "SELECT proxy_url FROM users WHERE id=$1", userID)
	if err == nil && proxyURL != "" {
		parsed, perr := url.Parse(proxyURL)
		if perr != nil {
			log.Warn().Err(perr).Str("proxy", proxyURL).Msg("Invalid proxy URL, skipping proxy setup")
		} else {
			log.Info().Str("proxy", proxyURL).Msg("Configuring proxy")

			if parsed.Scheme == "socks5" || parsed.Scheme == "socks5h" {
				dialer, derr := proxy.FromURL(parsed, nil)
				if derr != nil {
					log.Warn().Err(derr).Str("proxy", proxyURL).Msg("Failed to build SOCKS proxy dialer, skipping proxy setup")
				} else {
					httpClient.SetProxy(proxyURL)
					client.SetSOCKSProxy(dialer, whatsmeow.SetProxyOptions{})
					log.Info().Msg("SOCKS proxy configured successfully")
				}
			} else {
				httpClient.SetProxy(proxyURL)
				client.SetProxyAddress(parsed.String(), whatsmeow.SetProxyOptions{})
				log.Info().Msg("HTTP/HTTPS proxy configured successfully")
			}
		}
	}
	clientManager.SetHTTPClient(userID, httpClient)

	GetS3Manager().EnsureClientFromDB(userID)

	if client.Store.ID == nil {
		qrChan, err := client.GetQRChannel(context.Background())
		if err != nil {
			if !errors.Is(err, whatsmeow.ErrQRStoreContainsID) {
				log.Error().Err(err).Msg("Failed to get QR channel")
				return
			}
		} else {
			err = client.Connect()
			if err != nil {
				log.Error().Err(err).Msg("Failed to connect client")
				return
			}

			myuserinfo, found := userinfocache.Get(token)

			for evt := range qrChan {
				if evt.Event == "code" {
					if *logType != "json" && s.mode != Stdio {
						qrterminal.GenerateHalfBlock(evt.Code, qrterminal.L, os.Stdout)
						fmt.Println("QR code:\n", evt.Code)
					}
					image, _ := qrcode.Encode(evt.Code, qrcode.Medium, 256)
					base64qrcode := "data:image/png;base64," + base64.StdEncoding.EncodeToString(image)
					sqlStmt := `UPDATE users SET qrcode=$1 WHERE id=$2`
					_, err := s.db.Exec(sqlStmt, base64qrcode, userID)
					if err != nil {
						log.Error().Err(err).Msg(sqlStmt)
					} else {
						if found {
							v := updateUserInfo(myuserinfo, "Qrcode", base64qrcode)
							userinfocache.Set(token, v, cache.NoExpiration)
							log.Info().Str("qrcode", base64qrcode).Msg("update cache userinfo with qr code")
						}
					}

					postmap := make(map[string]interface{})
					postmap["event"] = evt.Event
					postmap["qrCodeBase64"] = base64qrcode
					postmap["type"] = "QR"
					sendEventWithWebHook(&mycli, postmap, "")

				} else if evt.Event == "timeout" {
					postmap := make(map[string]interface{})
					postmap["event"] = evt.Event
					postmap["type"] = "QRTimeout"
					sendEventWithWebHook(&mycli, postmap, "")

					sqlStmt := `UPDATE users SET qrcode='' WHERE id=$1`
					_, err := s.db.Exec(sqlStmt, userID)
					if err != nil {
						log.Error().Err(err).Msg(sqlStmt)
					} else {
						if found {
							v := updateUserInfo(myuserinfo, "Qrcode", "")
							userinfocache.Set(token, v, cache.NoExpiration)
						}
					}
					log.Warn().Msg("QR timeout killing channel")
					clientManager.DeleteWhatsmeowClient(userID)
					clientManager.DeleteMyClient(userID)
					clientManager.DeleteHTTPClient(userID)
					select {
					case killchannel[userID] <- true:
					default:
					}
				} else if evt.Event == "success" {
					log.Info().Msg("QR pairing ok!")
					sqlStmt := `UPDATE users SET qrcode='', connected=1 WHERE id=$1`
					_, err := s.db.Exec(sqlStmt, userID)
					if err != nil {
						log.Error().Err(err).Msg(sqlStmt)
					} else {
						if found {
							v := updateUserInfo(myuserinfo, "Qrcode", "")
							userinfocache.Set(token, v, cache.NoExpiration)
						}
					}
				} else {
					log.Info().Str("event", evt.Event).Msg("Login event")
				}
			}
		}

	} else {
		log.Info().Msg("Already logged in, just connect")

		var lastErr error

		for attempt := 0; attempt < maxConnectionRetries; attempt++ {
			if attempt > 0 {
				waitTime := time.Duration(attempt) * connectionRetryBaseWait
				log.Warn().
					Int("attempt", attempt+1).
					Int("max_retries", maxConnectionRetries).
					Dur("wait_time", waitTime).
					Msg("Retrying connection after delay")
				time.Sleep(waitTime)
			}

			err = client.Connect()
			if err == nil {
				log.Info().Int("attempt", attempt+1).Msg("Successfully connected to WhatsApp")
				break
			}

			lastErr = err
			log.Warn().
				Err(err).
				Int("attempt", attempt+1).
				Int("max_retries", maxConnectionRetries).
				Msg("Failed to connect to WhatsApp")
		}

		if lastErr != nil {
			log.Error().
				Err(lastErr).
				Str("userid", userID).
				Int("attempts", maxConnectionRetries).
				Msg("Failed to connect to WhatsApp after all retry attempts")

			clientManager.DeleteWhatsmeowClient(userID)
			clientManager.DeleteMyClient(userID)
			clientManager.DeleteHTTPClient(userID)

			sqlStmt := `UPDATE users SET qrcode='', connected=0 WHERE id=$1`
			_, dbErr := s.db.Exec(sqlStmt, userID)
			if dbErr != nil {
				log.Error().Err(dbErr).Msg("Failed to update user status after connection error")
			}

			postmap := make(map[string]interface{})
			postmap["event"] = "ConnectFailure"
			postmap["error"] = lastErr.Error()
			postmap["type"] = "ConnectFailure"
			postmap["attempts"] = maxConnectionRetries
			postmap["reason"] = "Failed to connect after retry attempts"
			sendEventWithWebHook(&mycli, postmap, "")

			return
		}
	}

	for {
		select {
		case <-killchannel[userID]:
			log.Info().Str("userid", userID).Msg("Received kill signal")
			client.Disconnect()
			clientManager.DeleteWhatsmeowClient(userID)
			clientManager.DeleteMyClient(userID)
			clientManager.DeleteHTTPClient(userID)
			sqlStmt := `UPDATE users SET qrcode='', connected=0 WHERE id=$1`
			_, err := s.db.Exec(sqlStmt, userID)
			if err != nil {
				log.Error().Err(err).Msg(sqlStmt)
			}
			delete(killchannel, userID)
			return
		default:
			time.Sleep(1000 * time.Millisecond)
		}
	}
}

func fileToBase64(filepath string) (string, string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", "", err
	}
	mimeType := http.DetectContentType(data)
	return base64.StdEncoding.EncodeToString(data), mimeType, nil
}

func (mycli *MyClient) myEventHandler(rawEvt interface{}) {
	txtid := mycli.userID
	postmap := make(map[string]interface{})
	postmap["event"] = rawEvt
	dowebhook := 0
	path := ""

	switch evt := rawEvt.(type) {
	case *events.AppStateSyncComplete:
		if len(mycli.WAClient.Store.PushName) > 0 && evt.Name == appstate.WAPatchCriticalBlock {
			// ADAPTAÇÃO 3: PresenceUnavailable (comportamento correto para manter sessão ativa)
			err := mycli.WAClient.SendPresence(context.Background(), types.PresenceUnavailable)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send available presence")
			} else {
				log.Info().Msg("Marked self as available")
			}
		}
	case *events.Connected, *events.PushNameSetting:
		postmap["type"] = "Connected"
		dowebhook = 1
		if len(mycli.WAClient.Store.PushName) == 0 {
			break
		}
		// ADAPTAÇÃO 3: PresenceUnavailable (comportamento correto para manter sessão ativa)
		err := mycli.WAClient.SendPresence(context.Background(), types.PresenceUnavailable)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to send available presence")
		} else {
			log.Info().Msg("Marked self as available")
		}
		sqlStmt := `UPDATE users SET connected=1 WHERE id=$1`
		_, err = mycli.db.Exec(sqlStmt, mycli.userID)
		if err != nil {
			log.Error().Err(err).Msg(sqlStmt)
			return
		}
	case *events.PairSuccess:
		log.Info().Str("userid", mycli.userID).Str("token", mycli.token).Str("ID", evt.ID.String()).Str("BusinessName", evt.BusinessName).Str("Platform", evt.Platform).Msg("QR Pair Success")
		jid := evt.ID
		sqlStmt := `UPDATE users SET jid=$1 WHERE id=$2`
		_, err := mycli.db.Exec(sqlStmt, jid, mycli.userID)
		if err != nil {
			log.Error().Err(err).Msg(sqlStmt)
			return
		}

		postmap["type"] = "PairSuccess"
		dowebhook = 1

		myuserinfo, found := userinfocache.Get(mycli.token)
		if !found {
			log.Warn().Msg("No user info cached on pairing?")
		} else {
			txtid = myuserinfo.(Values).Get("Id")
			token := myuserinfo.(Values).Get("Token")
			v := updateUserInfo(myuserinfo, "Jid", fmt.Sprintf("%s", jid))
			userinfocache.Set(token, v, cache.NoExpiration)
			log.Info().Str("jid", jid.String()).Str("userid", txtid).Str("token", token).Msg("User information set")
		}

		var daysToSyncHistory int
		query := "SELECT COALESCE(days_to_sync_history, 0) FROM users WHERE id=$1"
		query = mycli.db.Rebind(query)
		err = mycli.db.Get(&daysToSyncHistory, query, mycli.userID)
		if err != nil {
			log.Warn().Err(err).Str("userID", mycli.userID).Msg("Failed to get days_to_sync_history from database")
		} else if daysToSyncHistory > 0 {
			go func() {
				time.Sleep(2 * time.Second)

				log.Info().
					Str("userID", mycli.userID).
					Int("days", daysToSyncHistory).
					Msg("Triggering automatic history sync after QR code scan")

				count := daysToSyncHistory * 15
				if count > 500 {
					count = 500
				}
				if count < 50 {
					count = 50
				}

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				var chatJIDs []string

				contacts, err := mycli.WAClient.Store.Contacts.GetAllContacts(ctx)
				if err != nil {
					log.Error().Err(err).Str("userID", mycli.userID).Msg("Failed to get contacts for history sync")
				} else {
					for jid := range contacts {
						chatJIDs = append(chatJIDs, jid.String())
					}
				}

				groups, err := mycli.WAClient.GetJoinedGroups(ctx)
				if err != nil {
					log.Error().Err(err).Str("userID", mycli.userID).Msg("Failed to get groups for history sync")
				} else {
					for _, group := range groups {
						chatJIDs = append(chatJIDs, group.JID.String())
					}
				}

				for _, chatJIDStr := range chatJIDs {
					chatJID, err := types.ParseJID(chatJIDStr)
					if err != nil {
						log.Warn().Err(err).Str("chatJID", chatJIDStr).Msg("Failed to parse chat JID, skipping")
						continue
					}

					err = mycli.s.syncHistoryForChat(context.Background(), mycli.userID, chatJID, count)
					if err != nil {
						log.Warn().Err(err).Str("chatJID", chatJIDStr).Msg("Failed to sync history for chat")
					} else {
						log.Info().Str("chatJID", chatJIDStr).Int("count", count).Msg("History sync request sent for chat")
					}

					time.Sleep(100 * time.Millisecond)
				}

				log.Info().
					Str("userID", mycli.userID).
					Int("days", daysToSyncHistory).
					Int("chatsSynced", len(chatJIDs)).
					Msg("Automatic history sync completed after QR code scan")
			}()
		}
	case *events.StreamReplaced:
		log.Info().Msg("Received StreamReplaced event")
		return
	case *events.Message:

		var s3Config struct {
			Enabled       string `db:"s3_enabled"`
			MediaDelivery string `db:"media_delivery"`
		}

		lastMessageCache.Set(mycli.userID, &evt.Info, cache.DefaultExpiration)
		myuserinfo, found := userinfocache.Get(mycli.token)
		if !found {
			err := mycli.db.Get(&s3Config, "SELECT CASE WHEN s3_enabled = 1 THEN 'true' ELSE 'false' END AS s3_enabled, media_delivery FROM users WHERE id = $1", txtid)
			if err != nil {
				log.Error().Err(err).Msg("onMessage Failed to get S3 config from DB as it was not on cache")
				s3Config.Enabled = "false"
				s3Config.MediaDelivery = "base64"
			}
		} else {
			s3Config.Enabled = myuserinfo.(Values).Get("S3Enabled")
			s3Config.MediaDelivery = myuserinfo.(Values).Get("MediaDelivery")
		}

		if s3Config.Enabled == "true" && (s3Config.MediaDelivery == "s3" || s3Config.MediaDelivery == "both") {
			ensureS3ClientForUser(txtid)
		}

		postmap["type"] = "Message"
		dowebhook = 1
		metaParts := []string{fmt.Sprintf("pushname: %s", evt.Info.PushName), fmt.Sprintf("timestamp: %s", evt.Info.Timestamp)}
		if evt.Info.Type != "" {
			metaParts = append(metaParts, fmt.Sprintf("type: %s", evt.Info.Type))
		}
		if evt.Info.Category != "" {
			metaParts = append(metaParts, fmt.Sprintf("category: %s", evt.Info.Category))
		}
		if evt.IsViewOnce {
			metaParts = append(metaParts, "view once")
		}
		if evt.IsViewOnce {
			metaParts = append(metaParts, "ephemeral")
		}

		log.Info().Str("id", evt.Info.ID).Str("source", evt.Info.SourceString()).Str("parts", strings.Join(metaParts, ", ")).Msg("Message Received")

		if !*skipMedia {

			isIncoming := !evt.Info.IsFromMe
			chatJID := evt.Info.Sender.String()
			if evt.Info.IsGroup {
				chatJID = evt.Info.Chat.String()
			}

			s3cfg := mediaS3Config{
				Enabled:       s3Config.Enabled,
				MediaDelivery: s3Config.MediaDelivery,
			}

			if img := evt.Message.GetImageMessage(); img != nil {
				mycli.processMedia(img, img.GetMimetype(), ".jpg",
					downloadTimeoutImage, isIncoming, chatJID,
					evt.Info.ID, s3cfg, postmap, nil)
			}

			if audio := evt.Message.GetAudioMessage(); audio != nil {
				mycli.processMedia(audio, audio.GetMimetype(), ".ogg",
					downloadTimeoutAudio, isIncoming, chatJID,
					evt.Info.ID, s3cfg, postmap, nil)
			}

			if doc := evt.Message.GetDocumentMessage(); doc != nil {
				ext := ".bin"
				if doc.FileName != nil {
					ext = filepath.Ext(*doc.FileName)
				}
				mycli.processMedia(doc, doc.GetMimetype(), ext,
					downloadTimeoutDocument, isIncoming, chatJID,
					evt.Info.ID, s3cfg, postmap, nil)
			}

			if video := evt.Message.GetVideoMessage(); video != nil {
				mycli.processMedia(video, video.GetMimetype(), ".mp4",
					downloadTimeoutVideo, isIncoming, chatJID,
					evt.Info.ID, s3cfg, postmap, nil)
			}

			if sticker := evt.Message.GetStickerMessage(); sticker != nil {
				mycli.processMedia(sticker, sticker.GetMimetype(), ".webp",
					downloadTimeoutSticker, isIncoming, chatJID,
					evt.Info.ID, s3cfg, postmap, map[string]interface{}{
						"isSticker":       true,
						"stickerAnimated": sticker.GetIsAnimated(),
					})
			}
		}

		var historyLimit int
		userinfo, found := userinfocache.Get(mycli.token)
		if found {
			historyStr := userinfo.(Values).Get("History")
			historyLimit, _ = strconv.Atoi(historyStr)
		} else {
			log.Warn().Str("userID", mycli.userID).Msg("User info not found in cache, skipping history")
			historyLimit = 0
		}

		if historyLimit > 0 {
			messageType := "text"
			textContent := ""
			mediaLink := ""
			caption := ""
			replyToMessageID := ""

			if protocolMsg := evt.Message.GetProtocolMessage(); protocolMsg != nil && protocolMsg.GetType() == 0 {
				messageType = "delete"
				if protocolMsg.GetKey() != nil {
					textContent = protocolMsg.GetKey().GetID()
				}
				log.Info().Str("deletedMessageID", textContent).Str("messageID", evt.Info.ID).Msg("Delete message detected")
			} else if reaction := evt.Message.GetReactionMessage(); reaction != nil {
				messageType = "reaction"
				replyToMessageID = reaction.GetKey().GetID()
				textContent = reaction.GetText()
			} else if img := evt.Message.GetImageMessage(); img != nil {
				messageType = "image"
				caption = img.GetCaption()
			} else if video := evt.Message.GetVideoMessage(); video != nil {
				messageType = "video"
				caption = video.GetCaption()
			} else if audio := evt.Message.GetAudioMessage(); audio != nil {
				messageType = "audio"
			} else if doc := evt.Message.GetDocumentMessage(); doc != nil {
				messageType = "document"
				caption = doc.GetCaption()
			} else if sticker := evt.Message.GetStickerMessage(); sticker != nil {
				messageType = "sticker"
			} else if contact := evt.Message.GetContactMessage(); contact != nil {
				messageType = "contact"
				textContent = contact.GetDisplayName()
			} else if location := evt.Message.GetLocationMessage(); location != nil {
				messageType = "location"
				textContent = location.GetName()
			}

			if messageType != "reaction" && messageType != "delete" {
				if conv := evt.Message.GetConversation(); conv != "" {
					textContent = conv
				} else if ext := evt.Message.GetExtendedTextMessage(); ext != nil {
					textContent = ext.GetText()
					if contextInfo := ext.GetContextInfo(); contextInfo != nil && contextInfo.GetStanzaID() != "" {
						replyToMessageID = contextInfo.GetStanzaID()
					}
				} else {
					textContent = caption
				}

				if textContent == "" {
					switch messageType {
					case "image":
						textContent = ":image:"
					case "video":
						textContent = ":video:"
					case "audio":
						textContent = ":audio:"
					case "document":
						textContent = ":document:"
					case "sticker":
						textContent = ":sticker:"
					case "contact":
						if textContent == "" {
							textContent = ":contact:"
						}
					case "location":
						if textContent == "" {
							textContent = ":location:"
						}
					}
				}
			}

			if messageType == "text" && replyToMessageID == "" {
				if conv := evt.Message.GetConversation(); conv != "" {
					_ = conv
				}
			}

			if s3Data, ok := postmap["s3"].(map[string]interface{}); ok {
				if url, ok := s3Data["url"].(string); ok {
					mediaLink = url
				}
			}

			if textContent != "" || mediaLink != "" || (messageType != "text" && messageType != "reaction") || messageType == "delete" {
				evtJSON, err := json.Marshal(evt)
				if err != nil {
					log.Error().Err(err).Msg("Failed to marshal event to JSON")
					evtJSON = []byte("{}")
				}

				err = mycli.s.saveMessageToHistory(
					mycli.userID,
					evt.Info.Chat.String(),
					evt.Info.Sender.String(),
					evt.Info.ID,
					messageType,
					textContent,
					mediaLink,
					replyToMessageID,
					string(evtJSON),
				)
				if err != nil {
					log.Error().Err(err).Msg("Failed to save message to history")
				} else {
					err = mycli.s.trimMessageHistory(mycli.userID, evt.Info.Chat.String(), historyLimit)
					if err != nil {
						log.Error().Err(err).Msg("Failed to trim message history")
					}
				}
			} else {
				log.Debug().Str("messageType", messageType).Str("messageID", evt.Info.ID).Msg("Skipping empty message from history")
			}
		}

	case *events.Receipt:
		postmap["type"] = "ReadReceipt"
		dowebhook = 1
		if evt.Type == types.ReceiptTypeRead || evt.Type == types.ReceiptTypeReadSelf {
			log.Info().Strs("id", evt.MessageIDs).Str("source", evt.SourceString()).Str("timestamp", fmt.Sprintf("%v", evt.Timestamp)).Msg("Message was read")
			if evt.Type == types.ReceiptTypeRead {
				postmap["state"] = "Read"
			} else {
				postmap["state"] = "ReadSelf"
			}
		} else if evt.Type == types.ReceiptTypeDelivered {
			postmap["state"] = "Delivered"
			log.Info().Str("id", evt.MessageIDs[0]).Str("source", evt.SourceString()).Str("timestamp", fmt.Sprintf("%v", evt.Timestamp)).Msg("Message delivered")
		} else {
			return
		}
	case *events.Presence:
		postmap["type"] = "Presence"
		dowebhook = 1
		if evt.Unavailable {
			postmap["state"] = "offline"
			if evt.LastSeen.IsZero() {
				log.Info().Str("from", evt.From.String()).Msg("User is now offline")
			} else {
				log.Info().Str("from", evt.From.String()).Str("lastSeen", fmt.Sprintf("%v", evt.LastSeen)).Msg("User is now offline")
			}
		} else {
			postmap["state"] = "online"
			log.Info().Str("from", evt.From.String()).Msg("User is now online")
		}
	case *events.HistorySync:
		postmap["type"] = "HistorySync"
		dowebhook = 1

		if evt.Data != nil && evt.Data.Conversations != nil {
			go func() {

				accountOwnerJID := ""
				if mycli.WAClient.Store != nil && mycli.WAClient.Store.ID != nil {
					accountOwnerJID = mycli.WAClient.Store.ID.ToNonAD().String()
				}

				savedCount := 0
				for _, conv := range evt.Data.Conversations {
					if conv == nil || conv.ID == nil || conv.Messages == nil {
						continue
					}

					chatJID, err := types.ParseJID(*conv.ID)
					if err != nil {
						log.Warn().Err(err).Str("convID", *conv.ID).Msg("Failed to parse conversation JID in HistorySync")
						continue
					}

					for _, msg := range conv.Messages {
						if msg == nil || msg.Message == nil {
							continue
						}

						messageKey := msg.Message.GetKey()
						if messageKey == nil {
							continue
						}

						messageID := messageKey.GetID()
						if messageID == "" {
							continue
						}

						isFromMe := messageKey.GetFromMe()
						var senderJID string

						if isFromMe {
							senderJID = accountOwnerJID
							if senderJID == "" {
								senderJID = "me"
								log.Warn().Str("messageID", messageID).Msg("accountOwnerJID is not available for a message from me, using 'me' as senderJID")
							}
						} else {
							participantJID := messageKey.GetParticipant()
							if chatJID.Server == types.GroupServer || chatJID.Server == types.BroadcastServer {
								senderJID = participantJID
							} else {
								senderJID = chatJID.String()
							}
						}

						if senderJID == "" {
							log.Warn().Str("messageID", messageID).Msg("Cannot determine sender JID, skipping message")
							continue
						}

						message := msg.Message.GetMessage()
						if message == nil {
							continue
						}

						messageType := "unknown"
						textContent := ""
						mediaLink := ""
						quotedMessageID := ""

						if message.GetConversation() != "" {
							messageType = "text"
							textContent = message.GetConversation()
						} else if ext := message.GetExtendedTextMessage(); ext != nil {
							messageType = "text"
							textContent = ext.GetText()
							if contextInfo := ext.GetContextInfo(); contextInfo != nil {
								quotedMessageID = contextInfo.GetStanzaID()
							}
						} else if img := message.GetImageMessage(); img != nil {
							messageType = "image"
							textContent = img.GetCaption()
						} else if vid := message.GetVideoMessage(); vid != nil {
							messageType = "video"
							textContent = vid.GetCaption()
						} else if audio := message.GetAudioMessage(); audio != nil {
							messageType = "audio"
						} else if doc := message.GetDocumentMessage(); doc != nil {
							messageType = "document"
							textContent = doc.GetCaption()
						} else if sticker := message.GetStickerMessage(); sticker != nil {
							messageType = "sticker"
						} else if location := message.GetLocationMessage(); location != nil {
							messageType = "location"
							textContent = location.GetName()
						} else if contact := message.GetContactMessage(); contact != nil {
							messageType = "contact"
							textContent = contact.GetDisplayName()
						} else if buttons := message.GetButtonsResponseMessage(); buttons != nil {
							messageType = "buttons_response"
							textContent = buttons.GetSelectedButtonID()
						} else if list := message.GetListResponseMessage(); list != nil {
							messageType = "list_response"
							textContent = list.GetSingleSelectReply().GetSelectedRowID()
						} else if reaction := message.GetReactionMessage(); reaction != nil {
							messageType = "reaction"
							textContent = reaction.GetText()
							if key := reaction.GetKey(); key != nil {
								quotedMessageID = key.GetID()
							}
						}

						if textContent == "" && messageType != "text" && messageType != "reaction" && messageType != "delete" {
							switch messageType {
							case "image":
								textContent = ":image:"
							case "video":
								textContent = ":video:"
							case "audio":
								textContent = ":audio:"
							case "document":
								textContent = ":document:"
							case "sticker":
								textContent = ":sticker:"
							case "contact":
								textContent = ":contact:"
							case "location":
								textContent = ":location:"
							}
						}

						msgTimestamp := time.Now()
						if timestamp := msg.Message.GetMessageTimestamp(); timestamp > 0 {
							msgTimestamp = time.Unix(int64(timestamp), 0)
						}

						var senderJIDForInfo types.JID
						if isFromMe {
							if accountOwnerJID != "" {
								var pErr error
								senderJIDForInfo, pErr = types.ParseJID(accountOwnerJID)
								if pErr != nil {
									log.Warn().Err(pErr).Str("accountOwnerJID", accountOwnerJID).Msg("Failed to parse account owner JID in HistorySync")
								}
							}
						} else {
							if chatJID.Server == types.GroupServer || chatJID.Server == types.BroadcastServer {
								participant := messageKey.GetParticipant()
								if participant != "" {
									var pErr error
									senderJIDForInfo, pErr = types.ParseJID(participant)
									if pErr != nil {
										log.Warn().Err(pErr).Str("participantJID", participant).Msg("Failed to parse participant JID in HistorySync")
									}
								}
							} else {
								senderJIDForInfo = chatJID
							}
						}

						pushName := ""
						if !isFromMe && senderJIDForInfo.User != "" {
							if mycli.WAClient != nil && mycli.WAClient.Store != nil {
								if contact, err := mycli.WAClient.Store.Contacts.GetContact(context.Background(), senderJIDForInfo); err == nil {
									pushName = contact.PushName
								}
							}
						}

						messageInfo := types.MessageInfo{
							MessageSource: types.MessageSource{
								Chat:     chatJID,
								Sender:   senderJIDForInfo,
								IsFromMe: isFromMe,
								IsGroup:  chatJID.Server == types.GroupServer || chatJID.Server == types.BroadcastServer,
							},
							ID:        messageID,
							Timestamp: msgTimestamp,
							Type:      messageType,
							PushName:  pushName,
						}

						messageEvent := map[string]interface{}{
							"Info":                  messageInfo,
							"Message":               message,
							"IsEphemeral":           false,
							"IsViewOnce":            false,
							"IsViewOnceV2":          false,
							"IsViewOnceV2Extension": false,
							"IsDocumentWithCaption": false,
							"IsLottieSticker":       false,
							"IsBotInvoke":           false,
							"IsEdit":                false,
							"SourceWebMsg":          nil,
							"UnavailableRequestID":  "",
							"RetryCount":            0,
							"NewsletterMeta":        nil,
							"RawMessage":            msg.Message,
						}

						evtJSON, err := json.Marshal(messageEvent)
						if err != nil {
							log.Error().Err(err).Msg("Failed to marshal HistorySync message event to JSON")
							evtJSON = []byte("{}")
						}

						if textContent != "" || mediaLink != "" || (messageType != "text" && messageType != "reaction") {
							err = mycli.s.saveMessageToHistory(
								mycli.userID,
								chatJID.String(),
								senderJID,
								messageID,
								messageType,
								textContent,
								mediaLink,
								quotedMessageID,
								string(evtJSON),
							)
							if err != nil {
								log.Error().Err(err).
									Str("userID", mycli.userID).
									Str("chatJID", chatJID.String()).
									Str("messageID", messageID).
									Msg("Failed to save HistorySync message to history")
							} else {
								savedCount++
							}
						}
					}
				}

				if savedCount > 0 {
					log.Info().
						Str("userID", mycli.userID).
						Int("savedCount", savedCount).
						Msg("Saved HistorySync messages to message_history")
				}
			}()
		}

	case *events.AppState:
		log.Info().Str("index", fmt.Sprintf("%+v", evt.Index)).Str("actionValue", fmt.Sprintf("%+v", evt.SyncActionValue)).Msg("App state event received")
	case *events.LoggedOut:
		postmap["type"] = "LoggedOut"
		dowebhook = 1
		log.Info().Str("reason", evt.Reason.String()).Msg("Logged out")
		defer func() {
			select {
			case killchannel[mycli.userID] <- true:
			default:
			}
		}()
		sqlStmt := `UPDATE users SET connected=0 WHERE id=$1`
		_, err := mycli.db.Exec(sqlStmt, mycli.userID)
		if err != nil {
			log.Error().Err(err).Msg(sqlStmt)
			return
		}
	case *events.ChatPresence:
		postmap["type"] = "ChatPresence"
		dowebhook = 1
		log.Info().Str("state", fmt.Sprintf("%s", evt.State)).Str("media", fmt.Sprintf("%s", evt.Media)).Str("chat", evt.MessageSource.Chat.String()).Str("sender", evt.MessageSource.Sender.String()).Msg("Chat Presence received")
	case *events.CallOffer:
		postmap["type"] = "CallOffer"
		dowebhook = 1
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call offer")
	case *events.CallAccept:
		postmap["type"] = "CallAccept"
		dowebhook = 1
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call accept")
	case *events.CallTerminate:
		postmap["type"] = "CallTerminate"
		dowebhook = 1
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call terminate")
	case *events.CallOfferNotice:
		postmap["type"] = "CallOfferNotice"
		dowebhook = 1
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call offer notice")
	case *events.CallRelayLatency:
		postmap["type"] = "CallRelayLatency"
		dowebhook = 1
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call relay latency")
	case *events.Disconnected:
		postmap["type"] = "Disconnected"
		dowebhook = 1
		log.Info().Str("reason", fmt.Sprintf("%+v", evt)).Msg("Disconnected from Whatsapp")
	case *events.ConnectFailure:
		postmap["type"] = "ConnectFailure"
		dowebhook = 1
		log.Error().Str("reason", fmt.Sprintf("%+v", evt)).Msg("Failed to connect to Whatsapp")
	case *events.UndecryptableMessage:
		postmap["type"] = "UndecryptableMessage"
		dowebhook = 1
		log.Warn().Str("info", evt.Info.SourceString()).Msg("Undecryptable message received")
	case *events.MediaRetry:
		postmap["type"] = "MediaRetry"
		dowebhook = 1
		log.Info().Str("messageID", evt.MessageID).Msg("Media retry event")
	case *events.GroupInfo:
		postmap["type"] = "GroupInfo"
		dowebhook = 1
		log.Info().Str("jid", evt.JID.String()).Msg("Group info updated")
	case *events.JoinedGroup:
		postmap["type"] = "JoinedGroup"
		dowebhook = 1
		log.Info().Str("jid", evt.JID.String()).Msg("Joined group")
	case *events.Picture:
		postmap["type"] = "Picture"
		dowebhook = 1
		log.Info().Str("jid", evt.JID.String()).Msg("Picture updated")
	case *events.BlocklistChange:
		postmap["type"] = "BlocklistChange"
		dowebhook = 1
		log.Info().Str("jid", evt.JID.String()).Msg("Blocklist changed")
	case *events.Blocklist:
		postmap["type"] = "Blocklist"
		dowebhook = 1
		log.Info().Msg("Blocklist received")
	case *events.KeepAliveRestored:
		postmap["type"] = "KeepAliveRestored"
		dowebhook = 1
		log.Info().Msg("Keep alive restored")
	case *events.KeepAliveTimeout:
		postmap["type"] = "KeepAliveTimeout"
		dowebhook = 1
		log.Warn().Msg("Keep alive timeout")
	case *events.ClientOutdated:
		postmap["type"] = "ClientOutdated"
		dowebhook = 1
		log.Warn().Msg("Client outdated")
	case *events.TemporaryBan:
		postmap["type"] = "TemporaryBan"
		dowebhook = 1
		log.Info().Msg("Temporary ban")
	case *events.StreamError:
		postmap["type"] = "StreamError"
		dowebhook = 1
		log.Error().Str("code", evt.Code).Msg("Stream error")
	case *events.PairError:
		postmap["type"] = "PairError"
		dowebhook = 1
		log.Error().Msg("Pair error")
	case *events.PrivacySettings:
		postmap["type"] = "PrivacySettings"
		dowebhook = 1
		log.Info().Msg("Privacy settings updated")
	case *events.UserAbout:
		postmap["type"] = "UserAbout"
		dowebhook = 1
		log.Info().Str("jid", evt.JID.String()).Msg("User about updated")
	case *events.OfflineSyncCompleted:
		postmap["type"] = "OfflineSyncCompleted"
		dowebhook = 1
		log.Info().Msg("Offline sync completed")
	case *events.OfflineSyncPreview:
		postmap["type"] = "OfflineSyncPreview"
		dowebhook = 1
		log.Info().Msg("Offline sync preview")
	case *events.IdentityChange:
		postmap["type"] = "IdentityChange"
		dowebhook = 1
		log.Info().Str("jid", evt.JID.String()).Msg("Identity changed")
	case *events.NewsletterJoin:
		postmap["type"] = "NewsletterJoin"
		dowebhook = 1
		log.Info().Str("jid", evt.ID.String()).Msg("Newsletter joined")
	case *events.NewsletterLeave:
		postmap["type"] = "NewsletterLeave"
		dowebhook = 1
		log.Info().Str("jid", evt.ID.String()).Msg("Newsletter left")
	case *events.NewsletterMuteChange:
		postmap["type"] = "NewsletterMuteChange"
		dowebhook = 1
		log.Info().Str("jid", evt.ID.String()).Msg("Newsletter mute changed")
	case *events.NewsletterLiveUpdate:
		postmap["type"] = "NewsletterLiveUpdate"
		dowebhook = 1
		log.Info().Msg("Newsletter live update")
	case *events.FBMessage:
		postmap["type"] = "FBMessage"
		dowebhook = 1
		log.Info().Str("info", evt.Info.SourceString()).Msg("Facebook message received")
	default:
		log.Warn().Str("event", fmt.Sprintf("%+v", evt)).Msg("Unhandled event")
	}

	if dowebhook == 1 {
		sendEventWithWebHook(mycli, postmap, path)
	}
}
