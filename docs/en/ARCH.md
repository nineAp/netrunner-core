# ARCH.md: Netrunner protocol and architecture

🇷🇺 [Русская версия](../../ARCH.md)

## Overview

Netrunner is a comprehensive system for bypassing network restrictions that uses a custom
encapsulation protocol to hide the fact that a proxy is being used. The traffic looks like ordinary
HTTPS (a TLS handshake), inside which encrypted frames carrying multiplexed data streams are sent.

The project consists of a client-side virtual network stack, an asynchronous multiplexing core, and a
server part.

For the full byte-level specification see [PROTOCOL.md](PROTOCOL.md); for the threat model see
[SECURITY_MODEL.md](SECURITY_MODEL.md).

---

## 1. Protocol layers

### TRANSPORT LAYER (TLS wrapper)

- Uses `TlsBridge` to imitate a legitimate TLS handshake.
- The server and client exchange ECDH public keys in the ClientHello/ServerHello messages.
- After the handshake, symmetric session keys are initialized for AEAD encryption (AEAD: AES-128-GCM
  by default, ChaCha20-Poly1305 for old versions and on the client's request).
- All subsequent data is sent disguised as standard `TLS Application Data` records.

### MULTIPLEXING LAYER (Frame)

Each frame inside `AppData` has a fixed header and the following structure:

- **Auth Tag (16 bytes):** an HMAC over time; in the data phase the receiver does not verify it
  (integrity and ordering are provided by the AEAD and the nonce counter), see
  [SECURITY_MODEL.md](SECURITY_MODEL.md) §7.4.
- **Stream ID (4 bytes):** the stream identifier. Allows many independent TCP/UDP connections in one
  tunnel.
- **Frame Type (1 byte):**
  - `0x00` (Connect)
  - `0x01` (Data)
  - `0x02` (Close)
  - `0x03` (Heartbeat)
  - `0x04` (UdpConnect) — open a UDP "session" to the destination
  - `0x05` (UdpData) — a datagram of a UDP session
  - `0x06` (Diag) — a client diagnostic report (a JSON snapshot, over the control channel only)
  - `0x07` (Credit) — stream credit for end-to-end flow control (payload — `u32` BE, the absolute limit
    of the stream's Data bytes)
  - `0x08` (Cover), `0x09`/`0x0a` (SecureConnect/SecureUdpConnect), `0x0b`/`0x0c`
    (MeshOnionConnect/MeshOnionUdpConnect) — see [PROTOCOL.md](PROTOCOL.md) §5.1
- **Payload Len (2 bytes):** the payload length.
- **Padding Len (2 bytes):** the length of random junk traffic.
- **Payload (variable length):** the intercepted packet's data itself.
- **Padding:** random bytes; the padding decision is made at the TLS-record level (irregular
  quantization boundaries, separate for each connection), see PROTOCOL.md §5.3.

---

## 2. How the protocol works

1. **ClientHello:** the client generates keys and sends a disguised request.
2. **ServerHello:** the server answers, completing the key exchange.
3. **Key update:** session key initialization (the AEAD cipher chosen in `ServerHello`).
4. **Data packing:** the whole `Frame` is encrypted (including the header, payload and padding).
5. **Transport:** the encrypted buffer is sent in an `ApplicationData` record over TCP.

---

## 3. Security and replay protection (time-based auth tag)

> A clarification from the code: the time window is checked **only on `ClientHello`** (the tag in
> `session_id`, keyed by the node secret). In the data phase, replay/reordering is cut off by the AEAD
> with a nonce counter. In detail — [PROTOCOL.md](PROTOCOL.md) §4 and
> [SECURITY_MODEL.md](SECURITY_MODEL.md).

Entry into the tunnel is protected by a dynamic tag similar to TOTP (Time-Based One-Time Password): it
resists simple replay and probing without a secret by DPI.

- **Tag generation (in `ClientHello` only):** `HMAC-SHA256` under the node secret (`nrxp_secret`); the
  message includes the current time step (`UNIX_EPOCH` in seconds, divided by 60), the salt and the
  client's ephemeral key — the tag is bound to a specific connection.
- **Validation (drift tolerance):** the server tries a window of **±2 steps** (±2 minutes,
  5 candidates, always all of them, in constant time).
- **Filtering:** if the tag does not match, the server does not drop the connection but relays it to a
  decoy site (stealth fallback). A replay of a recorded `ClientHello` within the window passes the tag
  (there is no store of used tags) but gives the attacker no keys.
- **Data phase:** integrity, ordering and replay protection are provided by the AEAD with a nonce
  counter; the receiver does not verify the 16-byte `auth_tag` field in the frame header.
- **Length randomization:** the padding is decided at the TLS-record level along irregular boundaries,
  separate for each connection.

---

## 4. Virtual network stack and interception (client side)

The client part implements transparent traffic capture at the network layer (L3), working not as an
ordinary SOCKS proxy but as a full VPN client.

- **TUN interface & routing (nftables):** outgoing traffic is wrapped into a virtual interface (for
  example `netr0`) by OS rules.
- **Userspace network stack (`smoltcp`):** `smoltcp` is used to parse the intercepted L3 traffic.
  - **TCP:** it takes over the state machine of TCP connections, assembling IP packets into continuous
    data streams.
  - **UDP session tracking:** for UDP traffic a custom session manager (a NAT table) is implemented,
    binding a `(Source IP, Source Port)` pair to an internal handler with an activity-timeout mechanism.
- **Event loop:** the main loop constantly polls the TUN interface, feeds raw packets into `smoltcp` and
  extracts the L4 payload to send into the tunnel.

---

## 5. The asynchronous core and stream management (Tokio)

Joining the synchronous network stack (`smoltcp`) with the asynchronous tunnel requires strict
orchestration through `tokio`.

- **MPSC channels:** a unique `Stream ID` is created for each intercepted connection. Data from
  `smoltcp` is passed to asynchronous workers through message queues.
- **Multiplexer (Muxer):** packs many data streams from the channels into a single TLS connection.
  Forms frames (`Frame`), encrypts them and sends them to the server.
- **Demultiplexer (Demuxer):** receives data from the server, decrypts it (AEAD) and routes replies back
  into the right channel by `Stream ID`, so that `smoltcp` forms a valid IP packet for the TUN
  interface.
- **Close/Data ordering:** a stream's `Close` travels over the leg's priority control channel, but the
  leg's writer does not let it overtake not-yet-written `Data` of the same stream (otherwise the
  receiver removes the stream and loses the tail of the reply), and the bridge keeps the stream's
  binding to the leg until `Close` has gone out — it must travel by the same leg as the data. On the
  receiving side `Close` is `Muxer::finish_stream`: the consumer reads everything already received and
  sees EOF (the client engine delivers it to the local socket only after the backlog drains).
- **End-to-end flow control (`net::credit`):** a leg is one TCP connection for many streams and cannot
  slow down a single slow stream, so the receiver tells the sender the window with `Credit` frames
  (an absolute limit, idempotent). The client engine issues credit as the application ACTUALLY consumes
  data (bytes go into the smoltcp buffer); the window starts at 1 MB and grows with the consumption
  rate (≥ 2×bytes per RTT, like `tcp_rcv_space_adjust`) within 16 MB per stream and a total budget of
  64 MB. The `Muxer::credit_gate` gate sits in `send_to_network` and blocks only that stream's sender. A
  peer that sends no credits (an old client/server) is not limited.
- **Queue depth:** stream and leg channels hold 16 messages each (≤ 64 KB each). The "in-flight" depth
  is held by the leg's socket buffer (`buftune`, ≈ 2×BDP) and the credit window, not by the channel: a
  deep channel only let the application run ahead of the network and added +100 ms of latency to
  neighbouring streams. Legs ask the kernel for BBR (`TCP_CONGESTION`; `NR_LEG_CC=off` disables it).

---

## 6. The DPI camouflage engine (TLS fingerprinting)

The `tlseng` module is used to bypass modern deep packet inspection (DPI) systems.

- **Browser imitation:** the module ensures that the structure of the session's first packet
  (ClientHello) exactly repeats the fingerprint of the current Chrome (the Chrome 140 profile, with a
  post-quantum `key_share`).
- **ClientHello structure:** the lists of supported cipher suites, the order of extensions (ALPN, SNI,
  Supported Groups, Key Share) and their contents are replaced. This makes DPI systems classify the
  tunnel as ordinary HTTPS web browsing.

---

## 7. Cross-platform integration (FFI & Android)

The Rust core is fully separated from the platform-dependent interface to ensure portability.

- **Native libraries:** the code compiles to dynamic libraries (`.so`) for various architectures
  (arm64-v8a, armeabi-v7a, x86_64) via `cargo-ndk`.
- **Binding generation:** the `bindgen-tool` (based on UniFFI) automatically generates JNI wrappers and
  Kotlin code. This lets an Android application manage the tunnel state by safely calling native Rust
  functions without having to hand-write boilerplate.
