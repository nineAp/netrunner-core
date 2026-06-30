# Крейт `server` — серверная часть прокси

Тонкая обвязка вокруг ядра ([`core`](../core)): принимает замаскированные
TLS-соединения, проверяет, что это валидный Netrunner-клиент, и проксирует трафик
во внешнюю сеть. Вся бизнес-логика — в ядре; здесь точка входа, листенер и
серверная диагностика.

> Детали — в rustdoc: `cargo doc --open -p netrunner-server`.

## Файлы

| Файл               | Роль                                                            |
|--------------------|-----------------------------------------------------------------|
| `src/main.rs`      | CLI (`--host`/`--port`), логгер, tokio-рантайм, запуск.         |
| `src/network.rs`   | TCP-листенер; на каждое соединение спавнит `ServerHandler`.     |
| `src/diagnostics.rs`| Логгер диагностики ядра → `netrunner_diagnostics.jsonl`.       |

## Жизненный цикл соединения (в ядре)

```text
accept TCP → core::ServerHandler::run:
  1. ClientHello → ServerHello   (невалидный/чужой → stealth-fallback на ubuntu.com:443)
  2. проверка auth-payload       (неверный → отказ)
  3. прицепить ногу к Muxer сессии и крутить TunnelEngine → проксировать к целям
```

Один общий `SessionManager` мультиплексирует несколько ног одной сессии на один
`Muxer`. Фоновая задача периодически делает health-check и печатает топологию.

## Запуск и деплой

Локально: `make debug-server` (биндится на `0.0.0.0:4443`). Релиз/деплой:
`make build-server` → `make deploy-server` (systemd-сервис на VPS, см.
`server/netrunner-server.service` и `Makefile`).
