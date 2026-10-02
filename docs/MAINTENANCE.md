# MAINTENANCE.md — эксплуатация и поддержка netrunner-proxy

Практическое руководство: что где лежит, как собрать/запустить/тестировать,
как это связано с `netrunner-backend` и `nxrp-smoltcp`, известные грабли и
куда смотреть первым делом, если что-то сломалось. Протокол как таковой —
в [`ARCH.md`](../ARCH.md); архитектурная карта модулей — в [`README.MD`](../README.MD)
и во вложенных `README.MD` каждого блока. Этот файл — эксплуатационный слой
поверх них, а не замена.

---

## 1. Роль подпроектов (workspace)

Cargo-воркспейс (`Cargo.toml` в корне): `core`, `client`, `client-edge`,
`server`, `tools/bindgen`, `tools/log`, `tools/loadtest`.

| Крейт | Роль |
|---|---|
| **`core/`** | Платформо-независимое ядро протокола: крипто (X25519/HKDF/ChaCha20-Poly1305), NRXP (кадры/кодек/TLS-мост), TLS-маскировка (JA3/JA4), `net` (мультиплексор, движок туннеля, `ClientHandler`/`ServerHandler`), `edge` (тот же протокол без `tokio::net` — для wasm), `rawcast` (локальный сокет ⇄ кадр). Вся бизнес-логика живёт здесь, остальное — тонкие обвязки. |
| **`client/`** | VPN-клиент: TUN-интерфейс + userspace TCP/IP-стек на `smoltcp` + маршрутизация ОС. Собирается либо Linux-бинарём (`src/main.rs`, отладка), либо `.so`-библиотекой через UniFFI (`src/lib.rs`, `SessionManager`/`Session`) для мобильных/десктоп-приложений (`netrunner-app`). |
| **`server/`** | Серверная часть: TCP-листенер, принимает замаскированные TLS-соединения, отдаёт каждое `ServerHandler` ядра (хендшейк → авторизация → проксирование или stealth-fallback на decoy-хост), `/health` и `/metrics`. |
| **`client-edge/`** | То же ядро (модуль `core::edge`), скомпилированное в `wasm32-unknown-unknown` и запускаемое как Cloudflare Worker: релей `WebSocket ⇄ NRXP/TCP` перед обычной VPN-нодой (см. `client-edge/README.MD`). |
| **`tools/`** | `log` (`netrunner-logger` — общий логгер + реестр `ERR_*` кодов ошибок для всех крейтов), `bindgen` (генератор Kotlin/Swift-биндингов из `.udl` через `uniffi_bindgen`), `loadtest` (нагрузочный тест сервера реальным клиентским стеком, для сайзинга прод-нод). |
| **`gen/`** | Артефакт сборки (не редактировать руками) — `.so` для Android по ABI + сгенерированные UniFFI Kotlin-биндинги. В `.gitignore`, публикуется в Gitea Package Registry, откуда `netrunner-app` его забирает в своём CI. |

---

## 2. Сборка, запуск, тесты

### Требования
- Rust stable (edition 2024 в `client`/`server`, 2021 в остальных крейтах воркспейса — единый toolchain это не ломает).
- Linux: `CAP_NET_ADMIN`/`CAP_NET_RAW` (или root) для TUN-интерфейса.
- `cargo-ndk` + Android NDK — только для Android-сборки.
- `worker-build` (**версия строго `0.1.x`**, не `0.6.x`+ — см. предостережение ниже) — только для `client-edge`.

### Локально (см. `Makefile`, читает `.env`/`.env.example`)

```bash
make debug-client   # cargo build --bin netrunner-client, setcap, sudo-запуск с RUST_LOG=trace
make debug-server   # cargo build --bin netrunner-server, локальный запуск на :8443
                     # ВАЖНО: уже поднимается с --require-auth против DEV_BACKEND_URL —
                     # см. раздел 3, нужен PROXY_INTERNAL_SECRET валидной dev-ноды.
```

`make debug-server` **не** передаёт `--health-port`/`--metrics-port` — эти
эндпоинты в дев-режиме по умолчанию выключены (см. `server/src/main.rs`:
`Option<u16>`, `None` = выключено).

### Кросс-компиляция

```bash
make build-android   # cargo-ndk, 4 ABI (arm64-v8a, armeabi-v7a, x86_64, x86),
                      # -p netrunner-client -p netrunner-logger --lib (!), затем
                      # bindgen-tool generate --language kotlin → gen/
                      # ВАЖНО: именно `--lib`, не `--bin` — `cargo build --bin
                      # netrunner-client` не производит .so вообще (main.rs — само-
                      # достаточная точка входа, отдельная от lib.rs). Собирает и
                      # netrunner-logger отдельно: он не подтягивается транзитивно
                      # как cdylib только через зависимость netrunner-client.

make build-edge       # cd client-edge && worker-build --release (wasm32-unknown-unknown)
                      # .cargo/config.toml задаёт getrandom_backend="wasm_js" для этой цели.
```

Быстрая проверка компиляции edge-клиента без полной сборки воркера:
`cargo check -p netrunner-client-edge --target wasm32-unknown-unknown`.

Android-либы синхронизируются в `netrunner-app` через `rsync` из `ANDROID_BUILD_SRC`
(`gen/`) в `ANDROID_PROJECT_LIBS` (путь к `vpn-plugin/android/.../jniLibs` в
netrunner-app, оба — переменные `.env`) — это чисто локальный путь одной машины;
у CI своя дорога через Gitea Package Registry (см. раздел 5).

### Тесты

Юнит-тесты есть только внутри `core/` (крипто/кадры/кодек/TLS-профили/хендшейк/
интеграционные тесты `connection.rs`) — 46 тестов на момент написания:

```bash
cargo test -p netrunner-core
cargo test --workspace   # client/server почти не имеют #[test], но не повредит
```

**Тесты НЕ гоняются в CI** (`.gitea/workflows/build.yml` только собирает и
пушит Docker-образ + Android-либы, шага `cargo test` там нет) — это
технический долг, см. раздел 6.

Нагрузочное тестирование — отдельный бинарь, не `#[test]`:
```bash
cargo run --release -p netrunner-loadtest -- --concurrency 50 --duration-secs 30
```
Поднимает настоящий скомпилированный `netrunner-server` отдельным процессом
и гоняет через него реальный `ClientHandler::connect`, снимая RSS/CPU из
`/proc` — см. doc-комментарий в `tools/loadtest/src/main.rs`. Держите в уме:
один "пользователь" = `MAX_TUNNEL_LEGS` (сейчас 4) реальных TCP-соединений.

### Релизный цикл / деплой сервера

```bash
make setup-server     # apt install build-essential libssl-dev pkg-config rsync на VPS
make build-server      # собирает netrunner-server + netrunner-masque-edge
make deploy-server     # rsync обоих бинарников + двух systemd unit
make deploy-dev        # то же, но на DEV_IP / *.dev.service
make logs              # основной TCP-сервер
make logs-masque       # HTTP/3 relay на UDP/8444
make ssh               # быстрый ssh на прод-ноду
```

Основной сервер, его нативная UDP-нога и MASQUE используют отдельные сокеты:
`netrunner-server` занимает `0.0.0.0:443/tcp` и `0.0.0.0:443/udp`, а
`netrunner-masque-edge` — `0.0.0.0:8444/udp`. Ручной systemd-деплой всегда
кладёт оба бинарника и оба юнита, но MASQUE-юнит имеет
`ConditionPathExists=/etc/netrunner/masque-edge.env`: без конфигурации он
пропускается и не влияет на работающий NRXP. Шаблон —
`server/masque-edge.env.example`; файл на ноде должен иметь права `0600`.

Корневой Docker-образ устроен так же: содержит оба бинарника, а entrypoint
запускает MASQUE только при `MASQUE_ENABLED=true` или автоматически, когда
одновременно заданы remote-auth (либо тестовый `MASQUE_TOKEN`),
`MASQUE_CERT_FILE` и `MASQUE_KEY_FILE`.
Старый вызов бэкенда `IMAGE ./netrunner-proxy ...` поддерживается. Для
включения на Docker-ноде сертификат и ключ нужно смонтировать в контейнер, а
в firewall открыть `443/udp` для core datagram-нóги и `8444/udp` для MASQUE.
Новые iOS-профили используют relay URL с портом `8444`. После переноса старые
установленные профили нужно заменить профилем, повторно скачанным из админки.
Сертификат должен быть публично доверенным и совпадать с relay hostname
из iOS-профиля.

В production задаются `MASQUE_AUTH_URL` и per-node
`MASQUE_AUTH_SECRET`: edge валидирует персональный `iosr_*` bearer через
control-plane и репортит трафик на соседний `/usage`. `MASQUE_TOKEN` остаётся
только тестовым статическим режимом. Переиспользовать internal secret как
клиентский bearer нельзя: он даёт ноде доступ к control-plane и никогда не
должен оказываться у клиента.

Продовый путь деплоя нод — **не этот репозиторий**. Ноды разворачивает и
пересобирает `netrunner-backend` (`NodeService`, админка), а новый образ
приезжает на них сам: watchtower на каждой ноде опрашивает реестр раз в
5 минут (`--interval 300`, Step 7 в `templates/init_node.sh` бэкенда). Здесь
остаётся только `build.yml` — собрать и запушить образ.

`make deploy-server`/`deploy-dev` — ручной fallback для одной конкретной
машины из `.env`, для дев-стенда.

---

## 3. Конфигурация нод и авторизация клиента (важно для аудита)

### Реестр прокси-нод — в БД бэкенда, не здесь

Единственный источник правды о парке — таблица `vpn_nodes` в
`netrunner-backend`. Ноды рождаются и умирают там: через админку и через
автоматическое развёртывание личных (VIP) серверов.

Раньше в корне этого репозитория лежал `nodes.json` — рукописная копия
списка, по которой CI гонял деплой и генерил scrape-таргеты Prometheus.
Копия расходилась с БД не случайно, а неизбежно: ноду создаёт админка, а
файл про это не знает, и ни один VIP-сервер в него не попадал. Удалён
вместе с `deploy.yml` и `scripts/generate-prometheus-targets.mjs`.

Сейчас:
- **деплой** — `NodeService` в бэкенде, значения берутся из строки ноды
  (`port`, `sni_domain`, `require_auth`, `internal_secret`, ключи NRXP);
- **scrape-таргеты** — центральный Prometheus сам ходит в бэкенд по
  `http_sd_configs` (`/api/v1/observability/targets`), см.
  `netrunner-data/observability/prometheus.yml`.

Сама нода получает свои параметры (`--port`, `--decoy-host`, `--backend-url`)
CLI-аргументами при запуске контейнера — их формирует бэкенд из той же
строки БД, так что разъехаться им больше негде.

Клиентское приложение (`netrunner-app`) выбирает ноду и её `decoy_host`/SNI
не отсюда, а по своей собственной копии данных с `netrunner-backend`
(`spawn_session(remote_address, sni, ...)` в `client/src/lib.rs` принимает
оба параметра явно от вызывающего приложения — `netrunner-proxy` их не
резолвит и не хранит списка нод в рантайме).

### Авторизация клиента перед проксированием — как это устроено

Это НЕ TLS mTLS и НЕ отдельный HTTP-запрос от прокси к бэкенду до хендшейка —
токен едет внутри уже установленного зашифрованного NRXP-туннеля, первым
кадром после хендшейка:

1. **`client/src/lib.rs`** → `SessionManager::spawn_session(..., auth_token:
   Option<String>)` — токен (JWT, выданный `netrunner-backend` при логине)
   передаётся приложением (`netrunner-app`) при старте сессии; сам
   `netrunner-proxy` его не запрашивает и не хранит, только транспортирует.
2. **`core/src/net/connection/connection.rs`** (`ClientHandler::establish_leg`
   / `perform_handshake`, ~строка 357-360) — после TLS-хендшейка и
   выведения ключей сессии клиент шлёт **первый Heartbeat-кадр** с payload
   `"session_id:leg_id:auth_token"` (третий сегмент может быть пустым, если
   авторизация на этой ноде выключена).
3. **`core/src/net/connection/connection.rs`** (`ServerHandler::run`, ~строка
   1115-1204) — сервер парсит этот payload, и если инстанс поднят с
   `--require-auth`, зовёт `AuthValidator::validate(&auth_token)`.
4. **`core/src/net/auth.rs`** — трейт `AuthValidator` (`validate`,
   `report_usage`, `report_node_health`) — ядро знает только абстракцию,
   HTTP-детали ему не нужны (и недоступны на wasm-таргете `client-edge`).
5. **`server/src/backend_client.rs`** — единственная реализация
   `AuthValidator`, HTTP-клиент к `netrunner-backend`:
   - `POST {backend_url}/api/v1/internal/validate` с телом `{"token": ...}`
     и заголовком `X-Internal-Secret: $PROXY_INTERNAL_SECRET` — успех кеширует
     `UserQuota` на `VALIDATE_CACHE_TTL = 60s` (по токену, не по сессии — все
     ноги одной сессии бьют в общий кеш);
   - `POST .../internal/usage` — отчёт о переданных байтах, синхронно
     получает обратно `over_limit`;
   - `POST .../internal/node-health` — best-effort, полностью анонимная
     телеметрия ноды (без user_id/IP/хостов назначения), не через circuit
     breaker;
   - circuit breaker: 5 подряд неудач (только сетевые ошибки/таймаут/5xx —
     4xx на конкретный токен НЕ считается) размыкают цепь на 10 секунд,
     дальше отказ мгновенный без реального HTTP-вызова.
6. **`server/src/main.rs`** — `--require-auth` включает/выключает всё это
   на инстанс целиком; обязателен `--backend-url` и env-переменная
   `PROXY_INTERNAL_SECRET` (общий с `netrunner-backend`, хранится в БД
   бэкенда как `vpn_nodes.internal_secret`, свой на каждую ноду — см.
   `netrunner-backend/src/modules/proxy_internal` и `.env.example` здесь).

   Не путать с `PROXY_NRXP_SECRET` / `PROXY_NRXP_PRIVATE_KEY`: те отвечают за
   аутентифицированный туннельный хендшейк (`vpn_nodes.nrxp_*`, миграция 0052)
   и живут на другом уровне доступа. `internal_secret` пускает ноду в
   control-plane бэкенда и клиентам не отдаётся никогда; публичная половина
   NRXP-ключа, наоборот, раздаётся каждому клиенту вместе с адресом ноды.
   Приватная половина NRXP не покидает ноду и не показывается даже
   администратору в админке.
7. Отказ бэкенда клиент теперь **видит явно**: сервер шлёт `Close`-кадр на
   служебном `stream_id=0` с текстом `"auth_rejected: ..."` перед разрывом
   TCP (раньше клиент видел голый EOF, неотличимый от сетевого сбоя — фикс
   в `connection.rs`, см. коммит `162838a`).

**`--require-auth` теперь per-node**: флаг ставится по `vpn_nodes.require_auth`
(по умолчанию `true` у всех), переключается точечно из админки — например,
для ноды-точки входа под edge-воркер без собственного логина. Раньше
удалённый `deploy.yml` поднимал ноды с этим флагом безусловно и затирал
точечные исключения на каждом прогоне. Инстансы без флага пускают любой
токен, включая пустой — это осознанный dev-режим (`make debug-server`), но
для прод-ноды выключение должно быть сознательным решением, а не побочным
эффектом деплоя.

**Файлы, важные для аудита этого пути:**
- `core/src/net/auth.rs` — контракт трейта.
- `core/src/net/connection/connection.rs` — где токен извлекается из
  первого Heartbeat и где вызывается `validate` (строки ~357 и ~1115-1204).
- `server/src/backend_client.rs` — единственная реализация, HTTP + секрет +
  кеш + circuit breaker.
- `server/src/main.rs` — где решается, включена ли авторизация вообще.
- `client/src/lib.rs` (`spawn_session`) и `core/src/edge.rs`
  (`encode_auth_heartbeat`) — откуда токен попадает в кадр на клиенте
  (толстый клиент и edge-релей соответственно).

---

## 4. Связь с `nxrp-smoltcp`

`client/Cargo.toml` тянет `smoltcp` как **git-зависимость** (не path, не
crates.io) из приватного Gitea-зеркала:

```toml
smoltcp = { git = "https://gitea.netrunner-vpn.com/nineap/nxrp-smoltcp.git", branch = "main", ... }
```

Это форк `smoltcp` (репозиторий `nxrp-smoltcp` в `/home/k/netrunner/` — не
трогать напрямую из этого репозитория). Используется только в `client/` —
для userspace-разбора TCP/IP на TUN-интерфейсе (стейт-машина TCP + собственный
UDP NAT). `core/` и `client-edge/` от него не зависят: у `client-edge` нет
TUN/L3-перехвата, только релей уже собранного потока байт.

**Важно:** до коммита `a5181b0` зависимость шла по SSH с GitHub
(`ssh://git@github.com/nineAp/nxrp-smoltcp.git`) — с этим совпадает и
устаревший текст в `client/README.MD` ("зависит от приватного форка smoltcp
по SSH... из чистого Windows-shell cargo его не достанет"). Сейчас
зависимость идёт по HTTPS от Gitea, и эта проблема с Windows-shell больше не
актуальна — **`client/README.MD` не обновлён и вводит в заблуждение**, см.
раздел 6.

---

## 5. CI/CD (`.gitea/workflows/`)

Только Gitea Actions (`.gitea/workflows/`), GitHub Actions конфигов нет
(репозиторий зеркалится на GitHub, но CI там не гоняется).

- **`build.yml`** (push в `main`, теги `v*`, `workflow_dispatch`):
  - `build` — собирает `netrunner-server` и `netrunner-masque-edge`
    **внутри** одного Docker-образа (multi-stage,
    `cargo-chef`, единая база `rust:1-bookworm` → `debian:bookworm-slim` —
    решает рассинхрон glibc раннера vs рантайма, см. комментарий в
    `Dockerfile`), пушит образ в Container Registry самой Gitea.
  - `build-android-libs` — cargo-ndk на 4 ABI + uniffi Kotlin-биндинги,
    публикует их generic-пакетом в Gitea Package Registry
    (`scripts/publish-android-client-libs.mjs`) — оттуда их забирает
    `netrunner-app` в своём CI.
  - **Нет шага `cargo test`** — сборка проверяет только компилируемость, не
    поведение (см. раздел 6).
- **Деплоя нод здесь больше нет.** Была джоба `deploy.yml`: она гоняла
  matrix по `nodes.json` и пересоздавала контейнер своим `docker run`. Это
  был третий, самый разошедшийся экземпляр описания контейнера — он ставил
  общий `PROXY_INTERNAL_SECRET` вместо per-node, безусловный `--require-auth`,
  не ставил `--label autoheal=true`/`--health-*` и не знал про ключи NRXP,
  то есть после её прогона нода теряла аутентификацию хендшейка и
  автолечение зависаний. Удалена вместе с `nodes.json` и
  `scripts/generate-prometheus-targets.mjs`.

  Раскатка образа и без неё работала: watchtower на ноде опрашивает реестр
  раз в 5 минут. Точечная пересборка — из админки (кнопка «Обновить» и
  массовое обновление всех нод), там же берутся правильные per-node значения.
- Секреты `build.yml`: `GT_REGISTRY_TOKEN` (общий на несколько репозиториев,
  привязан к аккаунту Gitea, не к репозиторию — нужно дублировать в Settings
  каждого).

---

## 6. Известные грабли / технический долг

- **CI не гоняет тесты** — `build.yml` только компилирует и деплоит,
  `cargo test -p netrunner-core` (46 тестов) никогда не проверяется
  автоматически. Регрессия в крипто/кадрах/хендшейке может уехать в прод
  незамеченной, если разработчик не прогнал тесты руками.
- **`client/README.MD` устарел**: описывает зависимость от `nxrp-smoltcp`
  через SSH/GitHub, хотя с коммита `a5181b0` она идёт по HTTPS через Gitea
  (см. раздел 4). Утверждение "из чистого Windows-shell cargo его не
  достанет" больше не актуально.
- **`ARCH.md`, раздел 1 (типы кадров) неполный**: перечисляет только
  `0x00`–`0x03` (Connect/Data/Close/Heartbeat), но в коде
  (`core/src/nrxp/frame.rs`, `enum FrameType`) есть ещё `UdpConnect = 0x04`,
  `UdpData = 0x05` и диагностический тип отчёта (см. `core/src/nrxp/README.MD`)
  — тип для JSON-диагностики клиента. Документ не обновлён после добавления
  UDP-сессий и диагностических кадров.
- ~~**`nodes.json` не валидируется против реального состояния нод**~~ —
  **закрыто**: файла больше нет, источник правды один (`vpn_nodes`), и
  `--decoy-host` формируется из той же строки, из которой клиенты берут SNI.
- ~~**`PROXY_INTERNAL_SECRET` — общий master-секрет на все ноды в
  `deploy.yml`**~~ — **закрыто вместе с самой джобой**. Компрометация
  раннера Gitea больше не означает компрометацию авторизации всех нод
  разом: секрет per-нода живёт в `vpn_nodes.internal_secret` и уезжает на
  машину только провижинингом бэкенда.
- **`repomix-output.xml` и `hosts_cache.txt`** лежат в корне репозитория
  (не в `.gitignore` частично — `hosts_cache.txt` в `.gitignore` есть,
  `repomix-output.xml` тоже) — рабочие/кэш-артефакты, подтверждён, что не
  трекаются, но подтверждайте `git status` перед коммитом, если генерируете
  их локально.
- **rustc 1.94 ICE workaround** — `#![allow(dead_code)]` в `server/src/main.rs`
  и (проверить) `client/src/lib.rs` обходит известный ICE в
  `check_mod_deathness` (dead-code MIR pass); если апгрейд тулчейна снимет
  проблему в апстриме, можно убрать.

---

## 7. Если сломалось — куда смотреть в первую очередь

### Клиент не может подключиться к серверу вообще (TCP/сеть)
1. Строка ноды в админке / то, что реально передал `netrunner-app`:
   `ip_address`/`port` совпадают с тем, что слушает нода (`--host`/`--port`
   в `docker run` на ней)?
2. На ноде: `docker ps` — контейнер `netrunner-proxy` живой? `docker logs
   netrunner-proxy` / `make logs` (systemd-путь).
3. `--health-port` (биндится на 127.0.0.1, только локально на ноде):
   `curl 127.0.0.1:9091` (или заданный порт) — `200 {"status":"ok",...}`
   значит процесс жив и периодический таск не завис; `503 {"status":"stalled"}`
   — процесс жив, но внутренний луп подвис (см. `LAST_PERIODIC_TICK_UNIX_SECS`
   в `server/src/network.rs`) — это неявный "жив, но не работает", раньше
   маскировался обычным `200 ok`.
4. Файрвол/nftables на клиенте (маршрутизация TUN, см. `client/src/tun/README.MD`)
   и на самой ноде (открыт ли `proxy_port` наружу).

### Хендшейк не проходит (TLS/NRXP handshake fail)
1. `sni_domain` ноды и SNI клиента должны совпадать с тем, что нода реально
   ожидает. Оба берутся из одной строки БД, но разъехаться всё же можно:
   если ноду передеплоили руками по SSH мимо админки, `--decoy-host` на ней
   отстанет от `vpn_nodes.sni_domain`. Результат — валидный, но "чужой"
   ClientHello → сервер уходит в stealth-fallback
   (прозрачно проксирует на decoy, а не завершает Netrunner-хендшейк) —
   выглядит как обычный TLS-коннект к постороннему сайту, не как ошибка.
2. `core/src/tlseng/` — если DPI/провайдер начал блокировать конкретный
   JA3/JA4-отпечаток, проверьте `profile.rs` (актуальны ли профили браузеров)
   и содержимое/порядок расширений в `extension.rs`.
3. `ERR_NET_TLS_TAMPER` / `ERR_AUTH_FAILED` в логах (`tools/log/src/error.rs`,
   реестр `ERR_*`) — искать в `netrunner_diagnostics.jsonl` (серверная
   диагностика, `server/src/diagnostics.rs`) или в stdout JSON-логе
   (`docker logs`).
4. Проверьте системное время клиента/сервера — auth-tag в кадрах
   TOTP-подобный (шаг 60 сек, окно ±2 шага); рассинхрон времени больше
   ~5 минут рвёт все кадры как "replay"/tamper (см. `core/src/crypto/session.rs`,
   `ARCH.md` раздел 3).

### Хендшейк проходит, но клиента отшибает сразу после ("auth_rejected")
1. Это осознанный сигнал (см. раздел 3, пункт 7) — сервер поднят с
   `--require-auth`, и `AuthValidator::validate` отказал. Смотрите
   `e.internal_msg` в логе `warn!("❌ Backend rejected client token: ...")`
   (`connection.rs`).
2. Проверьте здоровье самого бэкенда: не разомкнут ли circuit breaker
   (`netrunner_circuit_breaker_open` в `/metrics`, лог "Circuit breaker
   разомкнут: бэкенд не отвечает N раз подряд") — если да, это НЕ отказ по
   токену, а `netrunner-backend` недоступен/тормозит 5+ запросов подряд.
3. `PROXY_INTERNAL_SECRET` на ноде должен совпадать с тем, что
   `netrunner-backend` ожидает для этой конкретной ноды
   (`vpn_nodes.internal_secret` в БД бэкенда) — рассинхрон после ротации
   секрета даёт стабильный 401/403 от бэкенда на КАЖДЫЙ токен, похоже на
   "все пользователи разом забанены".
4. Сам токен клиента: JWT просрочен/пользователь удалён/забанен —
   штатный кейс, см. коммит `4c7b74b`/`162838a` (сессия раньше вечно висела
   в "connected" с мёртвым туннелем в этом случае — если видите такое
   поведение на старой версии клиента, это тот самый уже пофикшенный баг).

### Клиенты перестали подключаться к одной ноде после ротации ключей NRXP

Симптом: соединения к конкретной ноде рвутся на хендшейке, в логе ноды
`Unauthorized ClientHello: Auth Tag mismatch` на каждой попытке, при этом сама
нода `online` и health-check зелёный.

1. Сверьте `nrxp_public_key=...`, который нода печатает при старте
   (`NRXP identity loaded`), с тем, что показывает админка для этой ноды.
   Разошлись — на ноду уехал не тот `.env`: пересоберите контейнер из админки
   (кнопка ротации ключей NRXP), она задеплоит ровно то, что лежит в БД.
2. Если значения совпали, проблема на стороне клиентов: они держат старый
   `nrxp_secret` и подключатся, как только приложение перезапросит список
   серверов. Это ожидаемое поведение ротации — старые учётные данные обязаны
   перестать работать, иначе ротация ничего не отзывает.
3. `PROXY_NRXP_SECRET` и `PROXY_NRXP_PRIVATE_KEY` задаются только парой: нода
   с одной из них падает на старте намеренно (`panic` в `main.rs`). Если нода
   вообще не поднимается после деплоя — смотрите сюда в первую очередь.
4. Если нода в строгом режиме (`PROXY_NRXP_STRICT=true`, переключатель в
   админке), она отвергает клиентов старой версии протокола вовсе. Включать его
   можно только после того, как бэкенд раздал ключи всем клиентам; выключение
   возвращает совместимость, но снова открывает downgrade — см. §7.1 в
   [PROTOCOL_ANALYSIS.md](PROTOCOL_ANALYSIS.md).

### Полностью новый пользователь долго не может пройти проверку / много 401
См. `MEMORY.md` пользователя: устойчивый всплеск 401 на бэкенде может быть
не багом авторизации прокси, а срабатыванием лимита числа устройств на
аккаунт при мультиустройственном логине (`backend_401_multidevice.md`) —
стоит исключить эту причину до того, как копать в `BackendClient`.

### Android/мобильная сборка не собирается или не находит биндинги
1. `ANDROID_NDK_HOME`/путь к NDK не экспортирован раннером/окружением
   (см. комментарий в `build.yml`, `step "Resolve NDK path"`) — проверьте,
   что путь реально существует, не полагайтесь на переменную от
   `android-actions/setup-android`.
2. Использована ли именно `--lib` (`-p netrunner-client -p netrunner-logger
   --lib`), не `--bin` — иначе `.so` не появится вообще, при этом сборка
   формально "успешна" (собирает бинарь, который никому не нужен на мобиле).
3. `netrunner-app` (`VpnPlugin.kt`) не находит
   `uniffi.netrunner_client.Session/SessionManager` — проверьте, что
   `gen/` реально опубликован в Gitea Package Registry и что
   `fetch-client-libs.mjs` в `netrunner-app` его успешно скачал (см.
   `scripts/publish-android-client-libs.mjs` здесь).

### `client-edge` (Cloudflare Worker) не собирается
1. Версия `worker-build` — должна быть `0.1.x`, не `0.6.x`+ (несовместимая
   схема бандлера/конфликт с зафиксированной версией `wasm-bindgen 0.2.105`,
   см. комментарий в `Makefile::build-edge`). `cargo install --list | grep
   worker-build` перед тем, как разбираться дальше.
2. `.cargo/config.toml` должен содержать `--cfg getrandom_backend="wasm_js"`
   для `wasm32-unknown-unknown` — без него сборка падает на `getrandom` 0.3+.
