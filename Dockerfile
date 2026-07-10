# syntax=docker/dockerfile:1.7

# Раньше этот Dockerfile просто копировал уже собранный на CI-раннере
# бинарник (target/release/netrunner-server) в debian:bookworm-slim — а
# раннер (ubuntu-24.04, glibc 2.39) собирал его с более новым glibc, чем
# несёт bookworm-slim (glibc 2.36). В рантайме это падало циклом рестартов:
# "GLIBC_2.38 not found". Компилируем внутри контейнера на той же базе
# (bookworm), что и рантайм — версии glibc гарантированно совпадают,
# независимо от того, какая ОС у раннера CI (см. тот же паттерн в
# netrunner-backend/Dockerfile).
FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p netrunner-server
COPY . .
RUN cargo build --release -p netrunner-server

FROM debian:bookworm-slim
WORKDIR /app

# Ставим системные сертификаты, чтобы прокси мог работать с сетью по HTTPS
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/netrunner-server /app/netrunner-proxy

EXPOSE 443/udp
EXPOSE 443/tcp

CMD ["./netrunner-proxy"]
