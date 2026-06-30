# Блок `client/net` — userspace TCP/IP-стек и мост в туннель

«Локальная» половина клиента: то, что превращает перехваченные IP-пакеты
приложений в логические соединения и кормит ими ядро ([`netrunner_core`](../../../core)).
Построено поверх форка `smoltcp` (userspace-стек) + `tokio`.

> Детали — в rustdoc крейта `netrunner-client`, модуль `net`.

## Файлы

| Файл                    | Роль                                                       |
|-------------------------|------------------------------------------------------------|
| `engine.rs`             | Главный poll-цикл стека + сборка (`EngineBuilder`).        |
| `connection_manager.rs` | Перехват L3-пакетов, реестр сокетов, диспетчеризация.      |
| `connection.rs`         | Виртуальные TCP/UDP-соединения + ICMP-ответчик.            |
| `session_tracker.rs`    | NAT-таблица сокетов, idle/LRU-уборка.                     |
| `socket_factory.rs`     | Создание smoltcp-сокетов под профиль трафика.             |
| `dns.rs`                | Локальный DNS: фейковые IP (CGNAT) + блок-лист.           |

## Поток данных

```text
TUN ─пакеты→ engine ─push_rx→ smoltcp ─→ connection_manager
     ─перехват SYN/датаграмм→ TcpConnection/UdpConnection ─RawCastFrame→ туннель
туннель ─RawCastFrame→ engine ─route_download→ smoltcp ─→ TUN ─→ приложение
```

## Ключевые механики

- **Перехват** (`connection_manager`): на TCP-`SYN` и первую UDP-датаграмму
  заводится smoltcp-сокет и виртуальное соединение; служебный трафик (DNS:53,
  NetBIOS) пропускается.
- **Фейковый DNS** (`dns`): каждому имени выдаётся стабильный IP из 100.64.0.0/10,
  по нему потом восстанавливается хост при установке туннельного соединения.
- **Профили трафика** (`socket_factory`): bulk/interactive/dns → разные размеры
  буферов; TCP с BBR, без Nagle.
- **Анти-bufferbloat / анти-HOL**: download раздаётся **пер-сокетно**
  (`pending_download` в `engine`), upload — с `tx_congested`-паузой
  (`connection`); один застрявший сокет не морозит остальных.
- **Уборка** (`session_tracker`): idle-выметание + LRU-эвикт при лимите сокетов,
  с защитой системных/слушающих.

## Связи

Кормит ядро через канал `RawCastFrame` ([`rawcast`](../../../core/src/rawcast));
сам туннель поднимает `ClientHandler::connect` из ядра. Ввод/вывод и маршруты — в
соседнем блоке [`tun`](../tun).
