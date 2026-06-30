# Блок `nrxp` — протокол Netrunner eXchange Protocol

Прикладной протокол, который ездит **внутри** замаскированного TLS-канала. Снаружи
трафик выглядит как обычные TLS-записи `ApplicationData` (`0x17`), а внутри каждой
записи — один зашифрованный кадр NRXP с мультиплексированием потоков.

Блок отвечает только за «упаковку/распаковку» и ничего не знает о сети — он
превращает `(stream_id, тип, payload)` в байты и обратно.

> Детали — в rustdoc, модуль `nrxp`.

## Файлы

| Файл         | Что внутри                                                        |
|--------------|------------------------------------------------------------------|
| `frame.rs`   | Структура кадра, (де)сериализация, паддинг.                      |
| `codec.rs`   | Шифрующий слой: `TxCodec`/`RxCodec` (кадр ⇄ зашифрованный TLS).   |
| `bridge.rs`  | TLS-обёртка `TlsBridge`: хендшейк и `ApplicationData`.            |
| `errors.rs`  | `TlsError` + стратегия реакции `ErrorAction` (Wait/Redirect/Drop).|

## Формат кадра (25-байтовый заголовок)

```text
┌──────────┬───────────┬──────┬─────────────┬─────────────┬─────────┬─────────┐
│ Auth Tag │ Stream ID │ Type │ Payload Len │ Padding Len │ Payload │ Padding │
│ 16 байт  │ 4 байта   │ 1 б. │ 2 байта     │ 2 байта     │ N байт  │ 0..255  │
└──────────┴───────────┴──────┴─────────────┴─────────────┴─────────┴─────────┘
  └────────────────── FRAME_HEADER_SIZE = 25 ──────────────────┘
```

- **Auth Tag** — TOTP-подобный HMAC-тег (см. [`crypto`](../crypto)), анти-replay.
- **Stream ID** — id логического потока (нечётные у клиента, чётные у сервера).
- **Type** — `Connect`/`Data`/`Close`/`Heartbeat`/`UdpConnect`/`UdpData`.
- **Padding** — случайные байты против анализа длин; только у управляющих кадров
  (`Data`/`UdpData` не паддятся ради throughput).

## Конвейер

```text
 TX:  Frame::new → into_bytes(tag) → AEAD encrypt in-place → TlsBridge::pack_app_data
 RX:  TlsBridge::unpack_app_data → AEAD decrypt in-place (staging) → Frame::parse
```

**Инвариант:** одна TLS-запись `ApplicationData` = ровно один кадр NRXP. На нём
держится потоковая расшифровка в `codec.rs` (буфер `staging`).

## Связи

- Шифрование — [`crypto`](../crypto) (`AeadPacker`, `SessionAuth`).
- TLS-маскировка и хендшейк — [`tlseng`](../tlseng).
- Кадры передаёт/принимает движок туннеля [`net`](../net).
