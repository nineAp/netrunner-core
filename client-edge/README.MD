# netrunner-client-edge

NRXP-клиент ядра [`netrunner-core`](../core), скомпилированный в `wasm32-unknown-unknown`
и запускаемый как Cloudflare Worker. Роль: удалённый сервер подключается к этому
воркеру по WebSocket, воркер сам ходит к вашей VPN-ноде тем же замаскированным
под TLS протоколом (NRXP), что и обычный клиент, а нода — дальше к `BACKEND_ADDR`.

```
удалённый сервер ──WS──▶ Cloudflare Worker (этот крейт) ──NRXP/TCP──▶ netrunner-server ──▶ BACKEND_ADDR
```

Точка входа — [`src/lib.rs`](src/lib.rs), функция `fetch` с `#[event(fetch)]`
(Workers не запускают `main()` — раннер сам вызывает экспортированный
обработчик; это wasm-аналог `main.rs`, который есть у Linux/desktop сборки
клиента). Вся протокольная логика (хендшейк, шифрование, кадры) не
продублирована — переиспользуется из [`core::edge`](../core/src/edge.rs),
платформо-независимого модуля ядра без `tokio::net` (недоступен на
`wasm32-unknown-unknown`).

## Сборка

Требуется таргет `wasm32-unknown-unknown` и `worker-build` (обёртка над
`wasm-pack`, ставит и вызывает Cloudflare):

```bash
rustup target add wasm32-unknown-unknown
cargo install worker-build
cd client-edge
worker-build --release          # или просто `npx wrangler deploy`, см. [build] в wrangler.toml
```

Быстрая проверка компиляции без полной сборки под воркер:

```bash
cargo check -p netrunner-client-edge --target wasm32-unknown-unknown
```

## Локальный запуск и деплой

```bash
npx wrangler dev       # локальный раннер (нужен настоящий VPN_NODE_ADDR — Sockets API не эмулируется офлайн)
npx wrangler secret put AUTH_TOKEN   # если нода поднята с --require-auth
npx wrangler deploy
```

## Конфигурация (`wrangler.toml`)

| Переменная      | Тип    | Назначение                                                        |
|-----------------|--------|--------------------------------------------------------------------|
| `VPN_NODE_ADDR` | var    | `host:port` вашей ноды (`netrunner-server`), например `1.2.3.4:443` |
| `BACKEND_ADDR`  | var    | `host:port`, который нода откроет по `Connect`-кадру (ваш бэкенд)   |
| `DECOY_SNI`     | var    | Домен-декой для поддельного `ClientHello` (по умолчанию `www.debian.org`) |
| `AUTH_TOKEN`    | secret | Bearer-токен, только если нода поднята с `--require-auth`          |

## Ограничения по сравнению с полным клиентом

- **Один логический поток на WebSocket-соединение**, не полноценный
  мультиплексор с несколькими TCP-ногами и failover ([`Muxer`](../core/src/net/connection/muxer.rs))
  — для роли "точка входа перед нодой" этого достаточно; если нужен
  дальнейший multi-leg failover, он всё равно происходит на следующем
  сегменте (нода ⇄ бэкенд) вне зоны ответственности воркера.
- **Нет TUN/L3-перехвата** — воркер ничего не знает про IP-пакеты конечного
  пользователя, он лишь ретранслирует то, что удалённый сервер уже прислал
  как логичные байты одного TCP-подобного потока по WebSocket.
- Один воркер = одна пара (VPN-нода, бэкенд); для нескольких бэкендов нужно
  либо несколько воркеров, либо расширить протокол апгрейда (например,
  передавать целевой адрес заголовком запроса вместо статического `BACKEND_ADDR`
  из `wrangler.toml`) — сознательно не сделано в этой версии, чтобы не
  превращать edge-релей в открытый прокси без отдельного контроля доступа.
