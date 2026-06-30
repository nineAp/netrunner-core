# Производительность: zero-copy / batching / lock-free — разбор и план

> TL;DR. Кодовая база **уже** zero-copy и lock-free на горячем пути. Массовых
> `to_vec()` в обработке пакетов нет. Реально лишних копий было две, обе вне
> muxer. Одну (UDP) убрал сразу; вторая (TUN-ридер) требует смены типа канала и
> сборки/бенча — ниже готовый дифф. `recvmmsg/sendmmsg` к TCP-туннелю
> **неприменимы** (это байт-поток, а не датаграммы) — объяснение в §2.

Сборку из-под агента запустить нельзя (апстрим-фильтр харнесса блокирует cargo),
поэтому в код внесено только то, что верифицируется чтением; остальное — диффами.

---

## Схема потока данных (как есть)

```
APP ─(TUN)→ [tun_reader] ─Vec<u8>→ engine ─push_rx→ smoltcp ─recv_slice→
   ConnectionTask ─Bytes→ muxer.send_data_safe ─Bytes→ data_tx(mpsc) ─→
   TunnelEngine.writer ─TxCodec.encode(in-place AEAD)→ TCP leg ──┐
                                                                  ▼
SERVER ── RxCodec.decode(in-place AEAD) ── StreamHandler ── bridge ── INTERNET
```

Owность данных уже передаётся как `Bytes` от smoltcp до сокета: `MuxMessage`
держит `Bytes`, кодек шифрует **in-place** в `BytesMut` и в конце делает
`freeze()` (zero-copy), парсер отдаёт payload через `split_to().freeze()`.
muxer **ничего не сериализует** — он только перемещает `Bytes` между каналами;
«пробка» там была не в копированиях, а в каскадном закрытии стримов (исправлено в
[anti-domino-fix.md](anti-domino-fix.md)) и в жёстком write-timeout.

---

## §1. Zero-copy (Data Flow)

### Что уже сделано (доказательства)
- `MuxMessage { data: Bytes }` — указатель, не массив.
- `nrxp/codec.rs`: `encode_frame` шифрует in-place, `freeze()` в конце; `decode_inbound`
  декрипт in-place в `staging` (`split_off`/`unsplit`, без доп. аллокаций).
- `nrxp/frame.rs`: `Frame::parse` → `bytes.split_to(p_len).freeze()` (передача
  владения), паддинг просто пропускается `advance()` — без аллокаций.
- `connection/bridge.rs` (TCP): `buf.split().freeze()` — ownership transfer.
- Заголовок кадра собирается на стеке и пишется одним `copy_from_slice` (25 байт).

### Что исправлено сейчас
- **UDP bridge (`core/src/net/connection/bridge.rs`)**: был
  `vec![0u8;N]` + `Bytes::copy_from_slice(&buf[..n])` — **полная копия каждой
  датаграммы**. Заменено на `socket.recv_buf(&mut BytesMut)` + `split().freeze()`.
  Теперь датаграмма уходит в muxer без memcpy. Эффект: −1 копия и −1 memset на
  каждый UDP-пакет (DNS/QUIC/игры/VoIP — самый частотный мелкий трафик).

### Что НЕ трогаю и почему
- `connection.rs:208` (`peek_slice`→`copy_from_slice`) и `:395/:471` — это граница
  **smoltcp**: его кольцевой буфер нельзя забрать во владение, копия из ring → наш
  буфер неизбежна. Замена на `recv_slice` в `BytesMut` уберёт лишь второй memset,
  но потребует `unsafe set_len`; выигрыш на уровне шума. Оставлено.
- Копии в `crypto/`, `tlseng/handshake.rs`, `nrxp/bridge.rs` — это рукопожатие
  (один раз на коннект, холодный путь). Не горячо.

### Готовый дифф: TUN-ридер (убрать `to_vec()` на каждый пакет)
`client/src/net/engine.rs:407` — `let pkt = buf[..n].to_vec();` копирует **каждый**
пакет от приложения. Канал сейчас `mpsc::channel::<Vec<u8>>`. smoltcp `RxToken`
требует `&mut [u8]`, поэтому переходить надо на **`BytesMut`** (не `Bytes`):

1. `tun_to_engine`: `mpsc::channel::<Vec<u8>>` → `mpsc::channel::<BytesMut>`
   (поля `tun_rx`/`tun_tx`/типы в `EngineMetrics`-хелперах — обновить).
2. `spawn_tun_reader`:
   ```rust
   let mut buf = BytesMut::with_capacity(TUN_READ_BUF_SIZE * 8);
   loop {
       if buf.capacity() - buf.len() < TUN_READ_BUF_SIZE { buf.reserve(TUN_READ_BUF_SIZE * 8); }
       match reader.read_buf(&mut buf).await {          // читает в spare capacity, без memset
           Ok(n) if n > 0 => {
               let pkt = buf.split();          // BytesMut, ownership transfer, no copy
               if to_engine.send(pkt).await.is_err() { break; }
           }
           ...
       }
   }
   ```
   (т.е. `let pkt = buf.split();` — отдаём `BytesMut`, copy нет.)
3. `device.push_rx(pkt: BytesMut)` и внутреннее хранилище `VecDeque<Vec<u8>>` →
   `VecDeque<BytesMut>`; в `RxToken::consume` отдавать `&mut pkt[..]`.
4. `try_create_socket_from_packet(&pkt[..], ...)` — добавить `[..]` (Bytes/Mut→&[u8]).

Это −1 copy и −1 memset на каждый upload-пакет. Блокирует только то, что меняет
сигнатуры в 3 файлах → нужен `cargo build -p netrunner-client` + прогон трафика.

---

## §2. Syscall batching (recvmmsg/sendmmsg) — честная оценка

- **TCP-ноги туннеля — это байт-поток.** `recvmmsg/sendmmsg` работают только с
  датаграммными сокетами (одно сообщение = одна датаграмма). К `OwnedReadHalf`/
  `OwnedWriteHalf` они неприменимы в принципе. Там батчинг уже сделан «на уровне
  фрейминга»: один `read_buf` забирает всё, что есть в сокете, за **один** syscall,
  а затем декодируется *несколько* NRXP-кадров из буфера. Это и есть правильный
  батч для потока.
- **UDP/TUN** — теоретически `recvmmsg` применим, НО: (а) это Linux-only, проект
  собирается в т.ч. под Windows/Android; (б) `tokio` не предоставляет `recvmmsg`,
  пришлось бы тащить `AsyncFd` + `libc`/`nix` с ручным управлением готовностью fd —
  это много `unsafe`, потеря переносимости и заметный риск регрессий ради выигрыша
  на пути, который уже не блокирует CPU. **Не оправдано.**

### Что реально даёт батчинг syscalls здесь — коалесинг записи (TCP) ✅ внесено
`engine.rs::handle_outbound` раньше слал `for pkt in packets { write_all(pkt) }` —
**N syscall'ов** на большое сообщение (по кадру 16 КБ). Теперь:
```rust
if packets.len() == 1 {
    outbound.write_all(&packets[0]).await        // fast path: zero-copy, без аллокаций
} else if !packets.is_empty() {
    let mut batch = BytesMut::with_capacity(total);
    for pkt in &packets { batch.extend_from_slice(pkt); }
    outbound.write_all(&batch).await             // N кадров → ОДИН write()
}
```
Прим.: честный аналог sendmmsg для TCP — это `writev` без копий, но в `tokio`
нет `write_all_vectored` (только `write_vectored` с ручной обработкой частичных
записей через `IoSlice::advance_slices` — слишком хрупко без бенча). Поэтому
выбран надёжный вариант: один `write_all` по склеенному буферу. Цена — одна
memcpy ciphertext при >1 кадре (одиночный кадр идёт zero-copy). Под высоким RTT
экономия на syscalls перекрывает эту копию.

### Адаптивный размер батча по RTT ✅ внесено
`muxer::adaptive_batch_chunk(base)` масштабирует размер interleave-чанка writer'а:
`factor = clamp(1 + rtt_ms/250, 1, 4)`, `chunk = base * factor` (base =
`TUNNEL_INTERLEAVE_CHUNK`, 16 КБ). При RTT ≤250 мс — 16 КБ (минимум задержки,
честное чередование стримов); при высоком RTT — до 64 КБ за проход, и эти 4 кадра
коалесятся в один `write()` (см. #3). Считается на каждый чанк → подхватывает
текущий RTT. Применено в `engine.rs` writer.

---

## §3. Конкуренция (locks / actors / backpressure)

### Аудит блокировок (факт)
- `core`: единственный hot-path лок — `RwLock<Arc<Vec<MuxLeg>>>` (кэш ног в muxer).
  Читатели друг друга **не блокируют**, чтение = взять read-guard + бамп Arc. Всё
  остальное — `DashMap` (`legs`, `streams`, `stream_bindings`, `pending_pings`,
  `pending_connects`) — уже lock-free-шардировано.
- `Mutex<VecDeque>` в `diagnostics.rs` — холодный путь (снапшоты раз в событие). ОК.
- **Модель акторов уже внедрена**: каждая нога — две задачи (reader/writer),
  общение через `tokio::mpsc`. Стримы — отдельные задачи-мосты. Это и есть акторы.

### Backpressure (уже есть, не «зависания»)
- Данные: `data_tx.send().await` (bounded) — backpressure до TCP-сокета ядра.
- Контрол: критичные (`Close`/`Heartbeat`) — `send().await`; некритичные —
  `try_send`, при переполнении **дропаются** с `ControlChannelFull` (сигнал вверх),
  а не блокируют. Это ровно запрошенное «дропать/сигналить, не стоять».
- Upload в smoltcp-мостах: `try_send` + флаг `tx_congested` → пауза чтения из
  браузера (TCP backpressure), без stalls.

### Lock-free кэш ног через `arc-swap` ✅ внесено
Кэш ног переведён с `RwLock<Arc<Vec<MuxLeg>>>` на `arc_swap::ArcSwap<Vec<MuxLeg>>`:
```toml
# core/Cargo.toml
arc-swap = "1"
```
```rust
// muxer.rs
active_legs_cache: Arc<ArcSwap<Vec<MuxLeg>>>,
// read:  self.active_legs_cache.load_full()       // вместо .read().unwrap().clone()
// write: self.active_legs_cache.store(Arc::new(new_cache))
```
Чтение горячего пути (`select_leg`, snapshot, topology) теперь без read-guard —
атомарный bump Arc. **Внимание:** добавлена зависимость `arc-swap` → при первой
сборке `cargo` её скачает (реестр crates.io доступен — tokio тянется оттуда же).

---

## Итог: что сделано vs что в плане

| # | Изменение | Статус |
|---|-----------|--------|
| 1 | UDP bridge: `recv_buf`+`split().freeze()` (−copy/датаграмму) | ✅ внесено |
| 2 | TUN-ридер: канал `Vec<u8>`→`BytesMut` | ❌ неприменимо** |
| 3 | TCP writer: коалесинг кадров в один `write_all` (sendmmsg-аналог) | ✅ внесено |
| 4 | Адаптивный размер батча по `GLOBAL_MIN_RTT` (`adaptive_batch_chunk`) | ✅ внесено |
| 5 | `arc-swap` для кэша ног (lock-free read) | ✅ внесено |
| – | recvmmsg/sendmmsg на TCP | ❌ неприменимо (§2) |

> ** **Корректировка к §1.** При попытке применить #2 выяснилось, что потребитель
> пакетов — `smoltcp::phy::ChannelDevice` из **внешнего форка smoltcp** (git-зависимость),
> а его `push_rx(Vec<u8>)`/`pop_tx()->Vec<u8>` менять нельзя. Перевод канала на
> `BytesMut` упёрся бы в копию `BytesMut→Vec<u8>` на границе устройства — это
> сводит на нет весь смысл. Поэтому #2 переходит в разряд неприменимых (как и
> recvmmsg): без форка `ChannelDevice` под `BytesMut` чистого zero-copy не выйдет.
> `to_vec()` в `spawn_tun_reader` остаётся вынужденным.

Проверка после применения диффов:
```
cargo build -p netrunner-core -p netrunner-client
cargo test  -p netrunner-core
```
