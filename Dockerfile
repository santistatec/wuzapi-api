FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
ENV CGO_ENABLED=1
# go mod tidy regenera o go.sum a partir do go.mod (evita precisar do Go local pra fechar o go.sum)
RUN go mod tidy && go build -o wuzapi

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    netcat-openbsd \
    postgresql-client \
    openssl \
    curl \
    ffmpeg \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV TZ="America/Sao_Paulo"
WORKDIR /app

COPY --from=builder /app/wuzapi         /app/
COPY --from=builder /app/static         /app/static/
COPY --from=builder /app/wuzapi.service /app/wuzapi.service

RUN chmod +x /app/wuzapi && \
    chmod -R 755 /app && \
    chown -R root:root /app

ENTRYPOINT ["/app/wuzapi", "--logtype=console", "--color=true"]
