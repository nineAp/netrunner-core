# Минимальный чистый образ рантайма
FROM debian:bookworm-slim
WORKDIR /app

# Ставим системные сертификаты, чтобы прокси мог работать с сетью по HTTPS
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

# Просто копируем уже скомпилированный тобой локально бинарник из wsl-папки target
COPY target/release/netrunner-server /app/netrunner-proxy

EXPOSE 443/udp
EXPOSE 443/tcp

CMD ["./netrunner-proxy"]
