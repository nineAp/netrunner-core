# Netrunner Core

Мультиплексированный VPN-туннель на Rust, маскирующийся под обычный HTTPS (TLS 1.3 браузера
Chrome). Клиент (Linux/OpenWrt/Android через UniFFI) + серверный узел.

🇬🇧 [English version](README.en.md)

**Возможности**

- до 4 параллельных TCP-«ног» на сессию, бесшовный переезд потоков при обрыве ноги;
- сквозное управление потоком (кредитное окно), адаптивные буферы, BBR на ногах;
- аутентифицированный хендшейк (X25519 + статический ключ узла), forward secrecy,
  AEAD (AES-GCM / ChaCha20-Poly1305);
- маскировка: отпечаток Chrome 140 (JA3/JA4, постквантовый `key_share`), cover-flight сервера,
  нерегулярная набивка длин, сайт-приманка для сканеров и активных проб;
- свой профиль браузера из JSON: `netrunner-client profile record` снимает с настоящего браузера TLS-отпечаток,
  QUIC Initial и форму трафика, проверяет, что движок их воспроизводит, и пишет один файл;
- опционально: UDP-нога (QUIC/WebRTC-мимикрия), mesh из нескольких узлов с onion-маршрутами;
- L3-VPN без TCP-in-TCP: TUN + userspace-стек (`nrxp-smoltcp`), kill-switch, режим роутера.

> ⚠️ Проект не заменяет Tor и не обещает «неотличимости для DPI». Прочитайте
> [модель безопасности](docs/SECURITY_MODEL.md), особенно раздел 7 (известные ограничения).

## Быстрый старт: свой узел за 5 минут

Нужен Linux-VPS с открытыми `tcp/443` и `udp/443`, Rust ≥ 1.91 (или Docker).

```bash
git clone git@github.com:nineAp/netrunner-core.git && cd netrunner-core
cargo build --release -p netrunner-server

# 1. секреты узла
export PROXY_NRXP_SECRET=$(openssl rand -hex 32)        # получат клиенты
export PROXY_NRXP_PRIVATE_KEY=$(openssl rand -hex 32)   # остаётся на узле
export PROXY_NRXP_STRICT=true

# 2. запуск
sudo -E ./target/release/netrunner-server --port 443 --decoy-host www.debian.org --health-port 9091
```

В логе найдите `"nrxp_public_key":"…"` — это публичный ключ узла. Проверка:
`curl -s http://127.0.0.1:9091/` → `{"status":"ok",…}`.

**Клиент** (Linux/OpenWrt) — `client.toml` (`chmod 600`):

```toml
remote_address  = "IP_УЗЛА:443"
sni             = "www.debian.org"            # = --decoy-host
node_secret     = "<PROXY_NRXP_SECRET>"
node_public_key = "<nrxp_public_key из лога>"
killswitch_enabled = true
```

```bash
cargo build --release -p netrunner-client --features cli --bin netrunner-client
sudo ./target/release/netrunner-client --config client.toml
```

> ⚠️ Узел подключается к любому адресу, который просит клиент (включая `127.0.0.1` и частные
> сети). Перед выдачей ключей прочитайте [hardening-чеклист](docs/DEPLOYMENT.md#9-hardening-чеклист).

systemd, Docker, мониторинг, обновление и ротация ключей — в
**[руководстве по развёртыванию](docs/DEPLOYMENT.md)**.

## Документация

| Документ | О чём |
|---|---|
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | развёртывание узла и клиента: сборка, systemd/Docker, флаги, файрвол, мониторинг, ключи |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | полная спецификация NRXP: хендшейк, ключи, кадры, мультиплексирование, UDP, mesh, константы |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | модель угроз, гарантии, секреты, остаточные риски |
| [docs/PCAP_PROFILE.md](docs/PCAP_PROFILE.md) | браузерные профили: запись трафика из бинаря, JSON-формат, загрузка (`profile record`) |
| [docs/MESH.md](docs/MESH.md) | mesh и onion-маршрутизация: роли, защита, возможности, ограничения |
| [docs/en/](docs/en) | английские версии: DEPLOYMENT, PROTOCOL, SECURITY_MODEL, MESH, SECURITY, ARCH |
| [docs/SECURITY.md](docs/SECURITY.md) | популярное объяснение криптографии и сравнение с MTProto |
| [ARCH.md](ARCH.md) | краткий обзор архитектуры |
| [docs/MAINTENANCE.md](docs/MAINTENANCE.md) | эксплуатация, CI, известные грабли |
| [docs/PROTOCOL_ANALYSIS.md](docs/PROTOCOL_ANALYSIS.md) | количественный анализ и сравнение с VLESS/Trojan/Hysteria2 (исторический) |
| [docs/UDP_LEG_RESEARCH.md](docs/UDP_LEG_RESEARCH.md) | исследование UDP-ноги |

Карта кода: [`core/`](core) (протокол, крипто, мультиплексор) · [`server/`](server/README.MD) (узел) ·
[`client/`](client/README.MD) (VPN-клиент, FFI) · [`client/openwrt/`](client/openwrt/README.md) ·
[`masque-edge/`](masque-edge/README.md) · [`edge-native/`](edge-native/README.md) ·
[`client-edge/`](client-edge/README.MD) · [`tools/`](tools/README.MD).

## Разработка

```bash
cargo test -p netrunner-core --lib      # 244 теста
make debug-server                        # локальный узел на :8443 (см. Makefile)
make build-android | build-openwrt       # мобильные библиотеки / OpenWrt-клиент
```

Клиент зависит от форка [`nrxp-smoltcp`](https://github.com/nineAp/nrxp-smoltcp) (git-зависимость
по HTTPS, см. `client/Cargo.toml`). Серверу он не нужен.

## Лицензия

[AGPL-3.0](LICENSE).
