# Развёртывание netrunner-proxy

🇬🇧 [English version](en/DEPLOYMENT.md)

Пошаговое руководство: от пустого VPS до работающего узла и клиента. Быстрый старт —
в [README](../README.md); протокол — [PROTOCOL.md](PROTOCOL.md); угрозы и требования к
оператору — [SECURITY_MODEL.md](SECURITY_MODEL.md).

> Команды из §3–§4 проверены на этой кодовой базе (сборка `cargo build --release`, запуск
> сервера с ключами, health/metrics, зонды). Docker-сборка и systemd-юнит из §7 — по
> штатным файлам репозитория, но на чистом VPS не прогонялись; примеры файрвола (§9) —
> отправная точка, проверьте на своей системе.

## Содержание

1. [Режимы развёртывания](#1-режимы-развёртывания)
2. [Требования](#2-требования)
3. [Сборка](#3-сборка)
4. [Быстрый старт автономного узла](#4-быстрый-старт-автономного-узла)
5. [Справочник: флаги и переменные](#5-справочник-флаги-и-переменные)
6. [Маскировка (decoy)](#6-маскировка-decoy)
7. [Запуск как сервис](#7-запуск-как-сервис)
8. [Клиент](#8-клиент)
9. [Hardening-чеклист](#9-hardening-чеклист)
10. [Мониторинг](#10-мониторинг)
11. [Control-plane, mesh, MASQUE, edge](#11-control-plane-mesh-masque-edge)
12. [Обновление и ротация ключей](#12-обновление-и-ротация-ключей)
13. [Проверка и диагностика](#13-проверка-и-диагностика)

---

## 1. Режимы развёртывания

| Режим | Что нужно | Кто допущен |
|---|---|---|
| **Автономный** (рекомендуется для старта) | только узел + клиентский конфиг | любой, у кого есть `nrxp_secret` и публичный ключ узла |
| **С control-plane** (`--require-auth`) | HTTP-бэкенд с контрактом из [PROTOCOL.md §9](PROTOCOL.md#9-контрольная-плоскость-http-контракт) | пользователи с токеном, лимиты трафика |
| **Mesh** (`--mesh-enabled`) | control-plane + несколько узлов | как выше, маршрут через цепочку узлов |

Дальше — автономный режим; остальное — в §11.

## 2. Требования

* Linux x86_64/aarch64 с публичным IPv4, открытый **TCP и UDP на одном порту** (по умолчанию 443).
* Rust stable ≥ 1.91 (требование `nrxp-smoltcp` для клиента; проверено на 1.95) **или** Docker.
* Для сборки клиента: доступ по HTTPS к `gitea.netrunner-vpn.com` (зависимость `nrxp-smoltcp`,
  см. [`client/Cargo.toml`](../client/Cargo.toml)). **Серверу этот доступ не нужен.**
* Синхронизированные часы (NTP) на узле и клиентах: допуск ±2 минуты.
* Рекомендуется: ядро с BBR (`modprobe tcp_bbr`) — узел сам просит BBR на сокет ноги.

## 3. Сборка

```bash
git clone git@github.com:nineAp/netrunner-core.git netrunner-proxy && cd netrunner-proxy
cargo build --release -p netrunner-server        # → target/release/netrunner-server
```

Docker (собирает и `netrunner-server`, и `netrunner-masque-edge` внутри образа):

```bash
docker build -t netrunner-proxy .
```

Образ запускается как `./netrunner-proxy …` (так бэкенд исторически передаёт команду);
entrypoint `server/container-entrypoint.sh` поднимает MASQUE только при полной
MASQUE-конфигурации (§11).

## 4. Быстрый старт автономного узла

**1. Сгенерируйте секреты** (оба — 32 байта hex; храните как секреты):

```bash
export PROXY_NRXP_SECRET=$(openssl rand -hex 32)        # общий секрет входа: его получат клиенты
export PROXY_NRXP_PRIVATE_KEY=$(openssl rand -hex 32)   # приватный ключ узла: НИКОГДА не покидает узел
export PROXY_NRXP_STRICT=true                           # отвергать анонимную схему
```

**2. Запустите узел:**

```bash
sudo -E ./target/release/netrunner-server --host 0.0.0.0 --port 443 \
  --decoy-host www.debian.org --health-port 9091
```

**3. Возьмите публичный ключ из лога** — строка `NRXP identity loaded`:

```json
{"level":"INFO","fields":{"message":"NRXP identity loaded","nrxp_public_key":"5556…e00a","strict":true}}
```

**4. Выдайте клиенту** четыре значения: адрес `IP:443`, `sni` (= `--decoy-host`),
`node_secret` (= `PROXY_NRXP_SECRET`), `node_public_key` (из лога). Клиент — §8.

**5. Проверьте:**

```bash
curl -s http://127.0.0.1:9091/            # {"status":"ok","active_connections":0}
```

Если секреты не заданы, узел поднимется в анонимном режиме (v2) и громко предупредит:
аутентификации узла нет, зондом классифицируется без секретов
([SECURITY_MODEL §7.2](SECURITY_MODEL.md)). `PROXY_NRXP_SECRET` и
`PROXY_NRXP_PRIVATE_KEY` задаются **только вместе** — иначе паника на старте.

> ⚠ В автономном режиме без `--require-auth` доступ определяет **только** `nrxp_secret`.
> Выдавайте его только тем, кому доверяете, и сначала прочтите §9 (узел не фильтрует цели).

## 5. Справочник: флаги и переменные

Флаги `netrunner-server`:

| Флаг | По умолчанию | Смысл |
|---|---|---|
| `-p, --port` | `8080` | порт TCP **и** UDP (UDP-нога на том же порту) |
| `--host` | `0.0.0.0` | адрес привязки |
| `--decoy-host` | `www.debian.org` | сайт-приманка для «не наших» (режим `relay`) |
| `--decoy-mode` | `relay` | `relay` \| `self-hosted` (см. §6) |
| `--decoy-preset`, `--decoy-sni`, `--decoy-local-site` | — / — / `127.0.0.1:8443` | только `self-hosted` |
| `--require-auth` | выкл | требовать токен, валидировать у `--backend-url` |
| `--backend-url` | — | URL control-plane (обязателен с `--require-auth`/`--mesh-enabled`) |
| `--mesh-enabled`, `--mesh-max-hops`, `--mesh-quic-port` | выкл, `2`, `8443` | mesh (§11) |
| `--health-port` | выкл | `/health`, только `127.0.0.1` |
| `--metrics-port` | выкл | `/metrics` Prometheus, на **`0.0.0.0`** |

Переменные окружения:

| Переменная | Где | Смысл |
|---|---|---|
| `PROXY_NRXP_SECRET`, `PROXY_NRXP_PRIVATE_KEY` | узел | учётные данные узла (только парой) |
| `PROXY_NRXP_STRICT` | узел | `true` — отвергать анонимных клиентов |
| `PROXY_INTERNAL_SECRET` | узел | секрет узла к control-plane (`--require-auth`/mesh) |
| `PROXY_NODE_ID` | узел | UUID узла (mesh) |
| `NETRUNNER_DECOY_DOMAINS`, `NETRUNNER_DECOY_SITE_OUT` | узел | каталог доменов / путь витрины (`self-hosted`) |
| `NR_LEG_CC` | узел/клиент | алгоритм CC ноги (по умолчанию `bbr`, `off` — не трогать) |
| `MESH_QUIC_PORT`, `MASQUE_*` | узел | см. §11 |
| `RUST_LOG` | клиент | уровень логов |

Логи — JSON в stdout; на диск узел ничего не пишет.

## 6. Маскировка (decoy)

### 6.1 Режим `relay` (по умолчанию, рабочий)
Всё, что не прошло проверку `ClientHello`, прозрачно ретранслируется на реальный сайт
(по SNI из пробы, либо `--decoy-host`). Сканер видит настоящий сайт.

### 6.2 Как выбрать `--decoy-host`
Крупный стабильный HTTPS-сайт, **географически близкий к узлу**, отвечающий `200`
независимо от SNI/Host (по умолчанию `www.debian.org`). Тот же домен укажите клиентам как
`sni`. Должен резолвиться в публичный IP (loopback/private/ваш собственный IP отвергаются).
Каждый узел лучше иметь с разной приманкой.

### 6.3 Режим `self-hosted`
Узел сам «является сайтом»: `--decoy-mode self-hosted --decoy-preset hauler
--decoy-sni your.domain` + `NETRUNNER_DECOY_DOMAINS=your.domain`; витрина собирается при
старте в `NETRUNNER_DECOY_SITE_OUT` (по умолчанию `/var/www/netrunner-decoy/index.html`) и
должна отдаваться локальным TLS-терминатором (nginx/Caddy с сертификатом вашего домена)
на `--decoy-local-site`.

### 6.4 ⚠ Известная проблема `self-hosted`
Сборка витрины работает, но **пересылка fallback на локальный сайт сейчас не работает**
(SSRF-фильтр блокирует loopback; проверено запуском). Используйте `relay`. Подробности и
влияние на скрытность — [SECURITY_MODEL §7.6](SECURITY_MODEL.md).

## 7. Запуск как сервис

### systemd

```bash
sudo useradd -r -s /usr/sbin/nologin netrunner
sudo install -m 0755 target/release/netrunner-server /usr/local/bin/
sudo install -d -m 0750 -o root -g netrunner /etc/netrunner
sudo tee /etc/netrunner/node.env >/dev/null <<EOF
PROXY_NRXP_SECRET=$(openssl rand -hex 32)
PROXY_NRXP_PRIVATE_KEY=$(openssl rand -hex 32)
PROXY_NRXP_STRICT=true
EOF
sudo chmod 0640 /etc/netrunner/node.env && sudo chgrp netrunner /etc/netrunner/node.env

sudo tee /etc/systemd/system/netrunner-server.service >/dev/null <<'EOF'
[Unit]
Description=Netrunner node
After=network-online.target
Wants=network-online.target

[Service]
User=netrunner
EnvironmentFile=/etc/netrunner/node.env
ExecStart=/usr/local/bin/netrunner-server --host 0.0.0.0 --port 443 --decoy-host www.debian.org --health-port 9091
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitNOFILE=1048576
Restart=always
RestartSec=3
TimeoutStopSec=35

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now netrunner-server
journalctl -u netrunner-server | grep nrxp_public_key
```

(Штатные юниты репозитория — `server/netrunner-server.service`, запускаются от root из
`/root/netr-core`; пример выше строже.) `TimeoutStopSec=35`: сервер ловит SIGTERM и до
30 с ждёт отключения клиентов.

### Docker

```bash
docker run -d --name netrunner-proxy --restart always --network host \
  --ulimit nofile=1048576:1048576 \
  --log-driver json-file --log-opt max-size=50m --log-opt max-file=3 \
  --health-cmd="wget -q -O - http://127.0.0.1:9091/ | grep -q '\"status\":\"ok\"' || exit 1" \
  --health-interval=15s --health-start-period=20s \
  -e PROXY_NRXP_SECRET -e PROXY_NRXP_PRIVATE_KEY -e PROXY_NRXP_STRICT=true \
  netrunner-proxy ./netrunner-proxy --port 443 --decoy-host www.debian.org --health-port 9091
```

`--network host` нужен, чтобы UDP-нога и один порт TCP/UDP работали без NAT-прокси.
`--cap-add NET_ADMIN` нужен только если ядро запрещает `TCP_CONGESTION=bbr` обычному
процессу (иначе узел молча остаётся на умолчании ОС).

## 8. Клиент

### Linux / OpenWrt (headless)

```bash
cargo build --release -p netrunner-client --features cli --bin netrunner-client
```

`/etc/netrunner/client.toml` (права `0600`):

```toml
remote_address  = "203.0.113.10:443"      # только числовой IPv4:port
sni             = "www.debian.org"        # = --decoy-host узла
node_secret     = "<PROXY_NRXP_SECRET>"
node_public_key = "<nrxp_public_key из лога узла>"
auth_token      = ""                      # пусто для автономного узла
# browser_profile = "/etc/netrunner/chrome.json"   # свой профиль браузера, см. PCAP_PROFILE.md
killswitch_enabled = true
tunnel_mode     = "bypass_lan"            # all | bypass_lan
```

```bash
sudo setcap cap_net_admin,cap_net_raw,cap_dac_override=eip ./target/release/netrunner-client
./target/release/netrunner-client --config /etc/netrunner/client.toml
```

Все ключи также принимаются через `NETRUNNER_*` и флаги (`--help`). Пустая пара
`node_secret`/`node_public_key` включает анонимную схему — только для тестов.
Свой профиль браузера для маскировки (снять с настоящего браузера одной командой или написать JSON
руками): [PCAP_PROFILE.md](PCAP_PROFILE.md) — `netrunner-client profile record --out chrome.json`, затем
`browser_profile = "chrome.json"` либо `--browser-profile`.
OpenWrt (`router_mode`, procd, firewall-зона): [`client/openwrt/README.md`](../client/openwrt/README.md).
Мобильное приложение и Tauri-клиент используют тот же `client/` через UniFFI
(`make build-android`).

> Для локальной проверки без корневых прав клиент не запускается (нужен TUN). Тест полного
> пути в изолированных netns: `make test-router-wsl` (требует sudo).

## 9. Hardening-чеклист

Обязательно (обоснование — [SECURITY_MODEL §10](SECURITY_MODEL.md)):

- [ ] `PROXY_NRXP_STRICT=true`, секреты только в env/секрет-хранилище, не в командной строке.
- [ ] **Egress-фильтр процесса узла.** Узел подключается к любому `host:port` клиента,
  включая `127.0.0.1`, частные сети и `169.254.169.254`. Пример для nftables
  (пользователь `netrunner`; если control-plane в частной сети — добавьте исключение):
  ```bash
  sudo nft -f - <<'EOF'
  table inet nr_egress {
    chain out {
      type filter hook output priority 0; policy accept;
      meta skuid "netrunner" ip  daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } drop
      meta skuid "netrunner" ip6 daddr { ::1, fc00::/7, fe80::/10 } drop
    }
  }
  EOF
  ```
  Для Docker `--network host` правило по `skuid` не сработает (root в контейнере) — фильтруйте
  по cgroup (`socket cgroupv2`) или запускайте под отдельным не-root UID (`--user`).
- [ ] **Файрвол входа:** открыть `tcp/443` и `udp/443` (+ `udp/8443` для mesh) всем;
  `--metrics-port` — только IP сборщика метрик; `--health-port` слушает loopback.
  ```bash
  sudo ufw allow 443/tcp && sudo ufw allow 443/udp
  sudo ufw allow from <IP_PROMETHEUS> to any port 9093 proto tcp
  ```
- [ ] Лимиты: `LimitNOFILE`, при необходимости `nft … ct count over 200 drop` на SYN с одного IP
  (общего лимита соединений в узле нет).
- [ ] NTP включён. Узел не делит машину с ценными сервисами.
- [ ] `--backend-url` только `https://`.
- [ ] Права: `chmod 600` на файлы с секретами; клиентский `client.toml` — `0600`.

## 10. Мониторинг

`--metrics-port 9093` → `GET /metrics` (Prometheus). Ключевые серии:

| Метрика | Смысл |
|---|---|
| `netrunner_vpn_established_total` | успешные туннельные подключения |
| `netrunner_scanner_fallback_total` | «не наши» соединения (сканеры, пробы, чужие клиенты) |
| `netrunner_auth_failures_total` | валидный хендшейк, отказ авторизации |
| `netrunner_handshake_total{version}` | хендшейки по версии протокола (сколько клиентов осталось на v2) |
| `netrunner_connections_active`, `netrunner_legs_active`, `netrunner_legs_expected` | нагрузка и здоровье ног |
| `netrunner_nrxp_identity_configured`, `netrunner_nrxp_strict` | с чем реально поднят узел (должны быть `1`) |
| `netrunner_circuit_breaker_open` | control-plane недоступен |
| `netrunner_datagram_legs_established_total` | поднявшиеся UDP-ноги |
| `netrunner_mesh_*` | mesh (маршруты, капсулы, QUIC) |

```yaml
scrape_configs:
  - job_name: netrunner
    static_configs: [{ targets: ["NODE_IP:9093"] }]
```

`/health` → `200 {"status":"ok",…}` либо `503 {"status":"stalled"}` (процесс жив, но
периодический таск завис) — для docker/systemd healthcheck.

## 11. Control-plane, mesh, MASQUE, edge

* **`--require-auth`**: нужен бэкенд с эндпоинтами `/api/v1/internal/{validate,usage,usage/batch,node-health}`
  ([контракт](PROTOCOL.md#9-контрольная-плоскость-http-контракт)), `--backend-url https://…`,
  `PROXY_INTERNAL_SECRET` (свой у каждого узла, клиентам не выдаётся). Токен клиента — в
  `auth_token`.
* **Mesh** (`--mesh-enabled`): дополнительно `PROXY_NODE_ID`, NRXP-учётные данные,
  `/internal/mesh/{peers,validate}`, открыть `udp/8443` (или `--mesh-quic-port`) между узлами.
  `--mesh-max-hops` 1…8 — жёсткий верхний предел маршрута.
* **MASQUE** (HTTP/3-релей для iOS, **экспериментальный**, `udp/8444`):
  [`masque-edge/README.md`](../masque-edge/README.md), шаблон конфигурации
  `server/masque-edge.env.example`; нужен публично доверенный сертификат.
* **Edge-ретрансляторы** перед узлом: [`edge-native`](../edge-native/README.md) (VDS + Caddy,
  WSS), [`client-edge`](../client-edge/README.MD) (Cloudflare Worker).
* Ручной деплой одной машины: `make setup-server && make deploy-server` (читает `.env`,
  шаблон — `.env.example`).

## 12. Обновление и ротация ключей

**Обновление бинарника/образа:** собрать новое, `systemctl restart netrunner-server`
(SIGTERM → до 30 с на drain). Клиенты переподключат ноги за секунды. Протокол совместим в
обе стороны по версиям ([PROTOCOL §2](PROTOCOL.md#2-версии-протокола-и-совместимость)).

**Раскатка ключей на существующий парк:** сначала узлы без `STRICT` (принимают и v2, и v3+),
выдать клиентам ключи, смотреть `netrunner_handshake_total{version="2"}`; когда v2 ≈ 0 —
`PROXY_NRXP_STRICT=true`.

**Ротация:** новая пара `PROXY_NRXP_SECRET`/`PRIVATE_KEY` → перезапуск → новый
`nrxp_public_key` из лога → раздать клиентам. Старые клиенты **перестанут подключаться** —
это ожидаемо (иначе ротация ничего не отзывает); в логе узла будет
`Unauthorized ClientHello: Auth Tag mismatch`. При утечке `PROXY_NRXP_PRIVATE_KEY` менять
обязательно (возможна подмена узла); при утечке только `nrxp_secret` — см.
[SECURITY_MODEL §3 (A8)](SECURITY_MODEL.md).

## 13. Проверка и диагностика

```bash
curl -s http://127.0.0.1:9091/                      # health
curl -s http://127.0.0.1:9093/metrics | grep -E 'strict|identity|established|fallback'
curl -sk --resolve www.debian.org:443:NODE_IP https://www.debian.org/ -o /dev/null -w '%{http_code}\n'   # зонд: должен вернуться 200 от сайта-приманки
```

После зонда `netrunner_scanner_fallback_total` вырастет — так и должно быть.

| Симптом | Причина |
|---|---|
| паника на старте «задаются только вместе» | задан один из `PROXY_NRXP_SECRET`/`PRIVATE_KEY` |
| `Address already in use` | порт занят (TCP или UDP того же номера) |
| клиент не подключается, в логе узла `Auth Tag mismatch` | расходятся `node_secret`/`node_public_key` клиента с узлом; часы > ±2 мин; ротация |
| клиент подключается, сразу `auth_rejected` | узел с `--require-auth`, токен невалиден/просрочен; проверьте circuit breaker |
| зонд HTTP на порт висит 10 с | норма: ждём `ClientHello` до `TLS_HELLO_TIMEOUT`, затем fallback |
| `Stealth fallback: no safe target address` | decoy не резолвится в публичный IP (или `self-hosted`, §6.4) |
| нет UDP-ноги | UDP-порт закрыт/режется; клиент остаётся на TCP (это штатно) |
| сильный лаг при загрузке | ядро без BBR (`modprobe tcp_bbr`), либо `NR_LEG_CC=off` |

Больше — [MAINTENANCE.md](MAINTENANCE.md) (эксплуатация, CI, грабли).
