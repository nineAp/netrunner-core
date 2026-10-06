# Крейт `client` — VPN-клиент и FFI-фасад

Клиентская сторона: перехватывает трафик приложений на уровне L3, прогоняет его
через userspace TCP/IP-стек и заворачивает в туннель ядра ([`core`](../core)).
Собирается двумя способами:

- **библиотека (`.so`)** для мобильных приложений через **UniFFI** — точка входа
  `src/lib.rs` (`SessionManager`/`Session`/`VpnTrafficStats`);
- **бинарь для Linux** — `src/main.rs` (отладка/локальный запуск).

> Детали — в rustdoc: `cargo doc --open -p netrunner-client`.

## Структура

| Путь            | Блок                                                              |
|-----------------|------------------------------------------------------------------|
| `src/lib.rs`    | FFI-фасад (uniffi): запуск/остановка сессии, статистика.         |
| `src/main.rs`   | Linux-бинарь: поднимает TUN и движок.                            |
| [`src/net/`](src/net)   | userspace TCP/IP-стек на smoltcp + мост в туннель.       |
| [`src/tun/`](src/tun)   | TUN-устройство, счётчики, системная маршрутизация.       |

## Как это работает (с высоты)

```text
приложение ─→ TUN ─→ net::Engine (smoltcp + перехват) ─RawCastFrame→
            core::ClientHandler (ноги туннеля, маскировка, шифр) ─→ сервер
```

`EngineBuilder::build` поднимает DNS, маршрутизацию и **устанавливает туннель**
(`core::ClientHandler::connect`), затем `Engine::run` крутит главный poll-цикл.

## Strong privacy mode

UniFFI-приложение может включить режим перед запуском сессии через
`SessionManager.set_strong_privacy(true)`. По умолчанию он выключен; настройка
действует на сессии, которые запускаются после вызова. Режим добавляет
перемешивание потоков и cover-трафик на relay-узлах, поэтому увеличивает
задержку. Headless/Linux-клиент принимает тот же параметр через
`--strong-privacy`, `NETRUNNER_STRONG_PRIVACY=1` или `strong_privacy = true` в
TOML-конфиге.

## Сборка

`client` зависит от приватного форка smoltcp (`nrxp-smoltcp`) как git-зависимости
по HTTPS из Gitea (`https://gitea.netrunner-vpn.com/nineap/nrxp-smoltcp.git`, см.
`client/Cargo.toml`) — доступ нужен именно к этому Gitea-инстансу, отдельного
SSH/GitHub-доступа больше не требуется.
Android-сборка `.so` + Kotlin-биндингов — через `make build-android` (см.
[`tools`](../tools)).
