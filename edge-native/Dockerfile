# syntax=docker/dockerfile:1.7

# Тот же паттерн, что и в корневом Dockerfile (см. его комментарий): собираем
# внутри контейнера на той же базе (bookworm), что и рантайм, чтобы версия
# glibc гарантированно совпадала независимо от того, какая ОС у CI-раннера.
FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p netrunner-edge-native
COPY . .
RUN cargo build --release -p netrunner-edge-native

FROM debian:bookworm-slim
WORKDIR /app

# ca-certificates — не для TLS-терминации (её здесь нет намеренно, см.
# README.md), а на случай, если резолв VPN_NODE_ADDR/BACKEND_ADDR когда-нибудь
# пойдёт через DNS-over-HTTPS — оставлено той же дешёвой ценой, что и в
# корневом образе. curl — для HEALTHCHECK ниже.
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/netrunner-edge /app/netrunner-edge

# Только localhost по умолчанию — предполагается reverse-proxy (Caddy/nginx)
# перед этим процессом, который слушает 443 сам и проксирует сюда уже
# расшифрованный WS (см. README.md). Если разворачиваете без reverse-proxy
# (слушать 0.0.0.0 напрямую), переопределите --host в CMD/docker run.
EXPOSE 8082/tcp

# Отвечает decoy-страницей 200 OK на любой не-WS GET (см. main.rs::handle) —
# этого достаточно для базового healthcheck без отдельного /health-пути.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD curl -fsS http://127.0.0.1:8082/ || exit 1

CMD ["./netrunner-edge", "--host", "0.0.0.0", "--port", "8082"]
