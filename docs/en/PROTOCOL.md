# NRXP — protocol specification

🇷🇺 [Русская версия](../PROTOCOL.md)

A complete description of the Netrunner protocol (NRXP, *Netrunner eXchange Protocol*): what is
transmitted on the wire and in what order, how keys are derived, how frames, multiplexing, the UDP
leg, mesh routing and the control plane are built.

> **The source of truth is the code.** This document was written from the `main` sources
> (`PROTOCOL_VERSION = 6`) and checked against them: every statement about a format carries a
> reference to a file/function, and the handshake behavior was additionally verified by running the
> server and the tests (`cargo test -p netrunner-core`, 244 tests, all green). Where a number
> **could not be confirmed** by a live browser capture it is marked `[?]` — such values must not be
> passed off as "byte-for-byte like a browser".

> **On publication.** The project used to deliberately not publish constants, offsets and labels
> (see [SECURITY.md](SECURITY.md), the section "Why there are no numbers here"): DPI signatures are
> built from exactly these. This file is a byte-level specification, and it **does not follow** that
> policy. Confidentiality does not suffer from publication (it rests on keys), but
> "indistinguishability" (section 11) partly relies on there being nothing to look for. Whether to
> keep this file in a public repository is the owner's decision.

## Contents

1. [Overview and layers](#1-overview-and-layers)
2. [Protocol versions and compatibility](#2-protocol-versions-and-compatibility)
3. [TCP leg: connection establishment](#3-tcp-leg-connection-establishment)
4. [Cryptography](#4-cryptography)
5. [Record and frame](#5-record-and-frame)
6. [Multiplexing and sessions](#6-multiplexing-and-sessions)
7. [UDP leg](#7-udp-leg)
8. [Mesh routing between nodes](#8-mesh-routing-between-nodes)
9. [Control plane (HTTP contract)](#9-control-plane-http-contract)
10. [Edge relays and MASQUE](#10-edge-relays-and-masque)
11. [What an observer sees](#11-what-an-observer-sees)
12. [Constants table](#12-constants-table)
13. [How it is verified](#13-how-it-is-verified)

Conventions: all multi-byte fields are **big-endian**; `‖` is concatenation; `[К]` ("code") —
derived from the code; `[И]` ("measured") — measured by running it; `[?]` — not checked against a
live capture; hex values without a prefix are bytes.

---

## 1. Overview and layers

NRXP is the application protocol of a multiplexed tunnel. From the outside the connection looks like
a Chrome browser's TLS 1.3 session to an ordinary site; inside are encrypted frames carrying
streams.

```text
┌───────────────────────────── client ─────────────────────────────┐   ┌────────── node ──────────┐
│ application ─ TUN ─ userspace TCP/IP (smoltcp)                     │   │                          │
│        │                                                           │   │                          │
│   Connect/Data/Close/Credit ... (NRXP frames, §5)                  │   │  frames → TCP/UDP to dest│
│        │                                                           │   │                          │
│   multiplexer: up to 4 "legs" per session (§6)                     │   │                          │
│        │                                                           │   │                          │
│   ApplicationData record (AEAD, padding) (§5)                      │   │                          │
│        │                                                           │   │                          │
│   fake TLS: ClientHello/ServerHello/CCS (§3)  ──────TCP──────▶     │   │  stealth-fallback → decoy│
│   UDP leg: QUIC / RTP / raw (§7)              ──────UDP──────▶     │   │                          │
└────────────────────────────────────────────────────────────────────┘   └──────────────────────────┘
```

Transports:

| Transport | What it is | Described in |
|---|---|---|
| **TCP leg** | primary; `MAX_TUNNEL_LEGS = 4` parallel TCP connections per session | §3–§6 |
| **UDP leg** | optional; one per session; QUIC/WebRTC mimicry or bare UDP | §7 |
| **Mesh (QUIC)** | node ⇄ node, real QUIC, with the same NRXP on top | §8 |
| **WSS / MASQUE** | external relays in front of a node | §10 |

Crates: `core/src/crypto` (keys, AEAD), `core/src/tlseng` (TLS imitation), `core/src/nrxp` (frames,
codec), `core/src/net` (multiplexer, engines, mesh), `core/src/quiceng`/`webrtceng`/`rawdgram.rs`
(UDP leg).

---

## 2. Protocol versions and compatibility

The version is the first byte of `session_id` in `ClientHello` (`session_id[0]`). It is the version
of **NRXP behavior**, not a TLS version. The client states it, and the server reads it before
deriving keys and decides which scheme to follow. [К] `core/src/lib.rs`

| Version | What it introduces | `ClientHello` tag | `ikm` | Data AEAD |
|:-:|---|---|---|---|
| **2** | anonymous scheme, one DH. No node credentials | HMAC over time, key = 32 zero bytes | `DH(e_c, e_s)` | ChaCha20-Poly1305, AAD = nonce |
| **3** | authenticated handshake: node secret + static key (second DH) | HMAC under `nrxp_secret` | `DH_eph ‖ DH_static ‖ "nrxp-v3-static-dh"` | ChaCha20-Poly1305, AAD = nonce |
| **4** | AES-GCM via `ring` | same + v4 label | `… ‖ "nrxp-v4-ring-aead" ‖ suite` | AES-GCM (per the chosen suite) or ChaCha, **empty AAD** |
| **5** | the client's cipher preference is confirmed by the tag | same + v5 label + preference byte | `… ‖ "nrxp-v5-cipher-preference" ‖ suite` | as v4, but the suite must match the preference |
| **6** | the client's mesh-route policy is confirmed by the tag | same + v6 label + 3 bytes | as v5 | as v5 |

What is actually stated:

* A client **without** node credentials → v2 (`PROTOCOL_VERSION_ANONYMOUS`).
* A client with credentials, `ring-aead` build (mobile app, headless client, server) → **v5**
  (`min(PROTOCOL_VERSION, 5)`); **v6** — only if a non-default mesh-route policy is set
  (`set_mesh_route_preference`).
* A build without `ring-aead` (wasm `client-edge`) → v3, always ChaCha. [К]
* The server accepts any version; a node in **strict mode** (`PROXY_NRXP_STRICT=true`) rejects v2
  (see [SECURITY_MODEL.md](SECURITY_MODEL.md) §5). A node with no credentials at all accepts only
  v2 and rejects ≥ v4. [К]

Other thresholds by client version (`>=`, so upgrading nodes and clients is independent):

| Constant | Value | Effect |
|---|:-:|---|
| `MIN_VERSION_FOR_CCS` | 1 | `ChangeCipherSpec` exchange |
| `MIN_VERSION_FOR_COVER` | 2 | the server sends a cover flight after `ServerHello` |
| `MIN_VERSION_FOR_STATIC_DH` | 3 | second DH + keyed tag |
| `MIN_VERSION_FOR_RING_AEAD` | 4 | AES-GCM allowed, empty AAD |
| `MIN_VERSION_FOR_CIPHER_PREFERENCE` | 5 | `session_id[1]` = cipher preference |
| `MIN_VERSION_FOR_MESH_ROUTE_PREFERENCE` | 6 | `session_id[2..4]` = route policy |

**Evolution rule.** An unknown frame-type byte after successful decryption **tears the leg down**
(desynchronization), so new frame types may only be sent to peers that declared a sufficient
version. [К] `nrxp/frame.rs`

---

## 3. TCP leg: connection establishment

### 3.1 Sequence

```text
Client                                                        Server (node)
  │── TLS record: ClientHello (≈1.7 KB, like Chrome 140) ──────▶│  tag check (HMAC, §4.2)
  │── TLS record: ChangeCipherSpec (14 03 03 00 01 01) ────────▶│  bad tag ⇒ stealth-fallback (§3.8)
  │                                                             │  key derivation (§4.3)
  │                                                             │  pause 5…40 ms (random)
  │◀── TLS record: ServerHello (127 B) ─────────────────────────│
  │◀── TLS record: ChangeCipherSpec ────────────────────────────│
  │◀── 4 ApplicationData records: cover flight (§3.6) ──────────│  only for clients v≥2
  │   key derivation (§4.3)                                     │
  │── ApplicationData: Heartbeat(stream 0) "sid:leg:token" ────▶│  token validation (§3.7)
  │◀══════════ multiplexed frames, AEAD (§5, §6) ═══════════════│
```

The client does not wait for the cover flight as a separate event: the records left in the buffer
are parsed normally as `Cover` frames and discarded. [К] `perform_handshake_on_connection`

Timeouts: waiting for `ClientHello` on the server — `TLS_HELLO_TIMEOUT` = **10 s**; waiting for the
auth frame — `SECURE_HANDSHAKE_TIMEOUT` = **20 s**. [К] `net/constants.rs`

### 3.2 TLS record

Every message on the wire is a TLS record: `type(1) ‖ version(2) ‖ length(2) ‖ payload`.
[К] `tlseng/tls_record.rs`

| Record | `type` | `version` | Where |
|---|:-:|---|---|
| Handshake (`ClientHello`) | `16` | the client profile: Chrome 140 → `03 01` (TLS 1.0, as in Chrome), Firefox/Safari → `03 03` | client |
| Handshake (`ServerHello`) | `16` | `03 03` | server |
| ChangeCipherSpec | `14` | `03 03`, body `01` | both sides |
| ApplicationData | `17` | `03 03` | all data |

Parsing accepts types `14/15/16/17`. An `ApplicationData` record shorter than 17 bytes is rejected
(minimum — an AEAD tag + 1 byte). A type/version error during parsing is marked
`ErrorAction::Redirect` — "looks like not our traffic".

### 3.3 `ClientHello`

[К] `tlseng/handshake.rs::ClientHello`, [И] sizes measured by running it.

```text
TLS record header (5)            16 | 03 01 | len
Handshake header (4)             01 | len24
legacy_version (2)               03 03
random (32)                      the client's local SALT (for HKDF, §4.3)
session_id_len (1)               20  (= 32)
session_id (32)                  see 3.3.1
cipher_suites_len (2) + list     16 values: GREASE, then the Chrome 140 set
compression (2)                  01 00
extensions_len (2) + extensions  see 3.3.2
```

Wire size [И]: **1730 B** for SNI `www.debian.org` (record payload 1725), **1720 B** for a 4-character
SNI; **+1 B per SNI character**. There is no RFC 7685 padding: the Chrome 140 profile sets
`target_padding_len = 0`, because a ClientHello with the PQ share weighs ~1.7 KB and physically
cannot fall into the forbidden 256–511 range.

#### 3.3.1 `session_id` — where the protocol is hidden

32 bytes, layout [К] (`make_client_hello`):

| Offset | Length | Field | Value |
|:-:|:-:|---|---|
| 0 | 1 | **protocol version** | 2 / 3 / 4 / 5 / 6 (see §2) |
| 1 | 1 | cipher preference | `0` auto, `1` AES-128-GCM, `2` AES-256-GCM, `3` ChaCha20-Poly1305 (for v≥5; otherwise a random byte) |
| 2 | 1 | mesh-route mode | for v6: `0` default, `1` direct, `2` two-hop, `3` up to X hops (otherwise a random byte) |
| 3 | 1 | hop count | for v6: `0` / `1` / `2` / `3..=8` (otherwise a random byte) |
| 4–15 | 12 | random bytes | `OsRng` |
| 16–31 | 16 | **authentication tag** | HMAC-SHA256 truncated to 16 B (§4.2) |

The value of `session_id` does not enter JA3/JA4 (only its length goes into the fingerprint), so the
version and preferences do not affect the fingerprint. `ServerHello` **echoes** the client's
`session_id` (as TLS 1.3 requires).

#### 3.3.2 Extensions (the `CHROME_140` profile)

The only profile in the rotation pool `BrowserProfile::ALL`: the others (`CHROME_131`, `EDGE_130`,
`FIREFOX_130`, `SAFARI_17`) are kept as structure samples and are **deliberately excluded** — they
have no post-quantum group, i.e. their `ClientHello` matches no live browser. The profile is chosen
once per session by a hash of the session's `session_id`. [К] `tlseng/profile.rs`

**Cipher suites:** `GREASE`, `1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035`
(16 values, GREASE first).

**Extension order** (`ExtensionOrder::CHROME_140`; **the middle is shuffled for every connection**,
the outer GREASE slots stay in place — as in Chromium since v110):

```text
GREASE(empty)  ALPS(0x44cd)  compress_certificate(brotli)  psk_key_exchange_modes
supported_versions  status_request  server_name  renegotiation_info  SCT
extended_master_secret  ALPN  session_ticket  key_share  supported_groups
encrypted_client_hello (GREASE)  ec_point_formats  signature_algorithms  GREASE(1 byte 0x00)
```

| Extension | Content |
|---|---|
| `server_name` | SNI = the client's `decoy_sni`, in plaintext (as a browser does) |
| `supported_groups` | GREASE, `X25519MLKEM768` (`0x11ec`), `x25519`, `secp256r1`, `secp384r1` |
| `key_share` | **`GREASE(1 B 00)`**, **`X25519MLKEM768`: 1216 B of ballast**, **`x25519`: 32 B — our real ephemeral key**. Total extension length 1263 B [К] |
| `signature_algorithms` | 11 values: `0904 0905 0906` (ML-DSA-44/65/87), `0403 0804 0401 0503 0805 0501 0806 0601` |
| `supported_versions` | GREASE, TLS 1.3, TLS 1.2 |
| `ALPN` | `h2`, `http/1.1` |
| `ALPS` | `h2` |
| `encrypted_client_hello` | GREASE-ECH: `outer`, HKDF-SHA256, AES-128-GCM, random `config_id`/`enc(32)`/`payload(144)` |
| GREASE | one draw per connection; the group value **must match** in `supported_groups` and `key_share` |

**ML-KEM ballast.** The real key exchange uses X25519; the 1216 bytes are not random junk but a
*structurally valid* client share of `X25519MLKEM768`: 768 coefficients < q = 3329, packed by the
`ByteEncode₁₂` rules (FIPS 203), plus the seed ρ. Random bytes would not pass the "modulus check"
(probability ≈ 10⁻⁷⁶) and would themselves be a detector. There is no real ML-KEM here; no
encapsulation can be performed against this key. [К] `tlseng/mlkem.rs`

**The server finds the key structurally**, not by substring: it parses `key_share` as
`list_len(2) ‖ { group(2) ‖ key_len(2) ‖ key }*` and takes the entry with `group == 0x001d` of
length 32 (earlier, a substring search for `00 1d 00 20` could fire by chance inside the ballast —
once per ~3.6 million handshakes). [К] `SessionKeys::extract_peer_public`

> `[?]` The GREASE-ECH payload length (144) was calibrated from a single capture. **Extraction from
> Chrome 148 ([PCAP_PROFILE.md](PCAP_PROFILE.md)) showed that in the browser it is random:
> 144/176/208/240 B** — the constant 144 in the builder is a distinguishing sign (needs fixing). The Firefox/Safari profile sizes have not
> been checked against a live capture.

### 3.4 `ServerHello`

[К] `ServerHello::from_client_hello`, [И] **127 B** on the wire (record payload 122):

```text
16 | 03 03 | 00 7a                         Handshake record
02 | len24                                 ServerHello
03 03                                      legacy_version
random (32)                                the server's local SALT
session_id_len (1)=20 + session_id (32)    echo of the client's
cipher_suite (2)                           the chosen suite (§4.4): 1301 / 1302 / 1303
compression (1)                            00
extensions: supported_versions(002b)=0304,  key_share(0033)= group 001d + the server's X25519 pubkey
```

The server profile `ServerProfile::MODERN`: suites `[1301, 1302, 1303]`, server order. Before
sending there is a random pause of **5…40 ms** (an instant, perfectly deterministic reply would by
itself distinguish the stack from a real server).

### 3.5 ChangeCipherSpec

Both sides send `14 03 03 00 01 01` right after their hello (TLS 1.3 middlebox compatibility,
RFC 8446 App. D.4) — browsers do this. Only for peers with version ≥ 1.

### 3.6 The server's cover flight

A real TLS 1.3 server right after `ServerHello` sends `EncryptedExtensions`, `Certificate`,
`CertificateVerify`, `Finished` — all under encryption, i.e. as records with content-type `17`.
Without an analogue our server would fall silent after the 127-byte hello, and the first
`ApplicationData` would be sent by the client (a boolean sign). So the server (for clients v≥2) sends
**four records of `Cover` frames** of exact length. [К] `tlseng/decoy.rs::CoverFlight`

The record length (the header `length` field) is computed from a typical Let's Encrypt ECDSA P-256
chain (`from_chain(&[1250, 1100], 72, 32)`): `4+2+7+17`, `4+1+3+Σ(3+DER+2)+17`, `4+2+2+72+17`,
`4+32+17`. Total records **`41 (30, raised to the minimum), 2385, 97, 53`** bytes; the server's first
flight on the wire — **127 + 6 + 46 + 2390 + 102 + 58 = 2729 B**. The lengths are identical on all
of a node's legs (determinism is a property of a real server).

> `[?]` The lengths were not taken from a specific node's live decoy site. The next step is to
> measure a real decoy site's response and reproduce exactly that.

### 3.7 The auth frame

The client's first encrypted record is a `Heartbeat` frame (type `03`) on `stream_id = 0` with the
payload (UTF-8):

```text
<session_id> : <leg_id> : <auth_token>
```

* `session_id` — 32 hex characters (`{:016x}{:016x}` of two random u64), one for the client's whole
  session (shared by all legs);
* `leg_id` — a number `0..MAX_TUNNEL_LEGS-1`;
* `auth_token` — a Bearer token (the user's JWT) or an empty string; for mesh peers — a `mesh…:`
  claim (see §8.1). Parsing is `splitn(3, ':')`, the token may contain `:`.

If the server is started with `--require-auth`, it validates the token with the control plane (§9);
otherwise the token is ignored entirely. A refusal is a `Close` frame on `stream_id = 0` with the
text `auth_rejected: <reason>` and a TCP close; on this text the client marks the session
**fatal** and stops reconnecting with a dead token. [К] `handler.rs`

### 3.8 Failures and stealth fallback

| Situation on the server | Reaction |
|---|---|
| `ClientHello` did not parse / not TLS | stealth fallback to the decoy |
| `ClientHello` parsed, **tag did not match** (foreign/scanner/stale secret/clock skew > ±2 min) | stealth fallback |
| bad cipher/route preference byte, no common cipher | stealth fallback |
| `ClientHello` did not arrive within 10 s (including plain HTTP on the port) | stealth fallback (with a 10 s delay) |
| valid handshake, the auth frame is wrong / did not arrive within 20 s | disconnect, `netrunner_auth_failures_total` |
| valid handshake, the token was rejected by the control plane | `Close auth_rejected:` + disconnect |

**Fallback** (`handle_stealth_fallback`): the already-read bytes are forwarded first, then the
connection is spliced both ways with the decoy; the bridge closes after
`FALLBACK_BRIDGE_IDLE_TIMEOUT` = 60 s of inactivity, at most `MAX_FALLBACK_BRIDGES` = 512 at once
(extras are closed). Where to:

* **`relay`** mode (default): to the SNI from the received `ClientHello` if it is a plausible
  hostname (not an IP literal, `[A-Za-z0-9.-]`, ≤ 253), otherwise to `--decoy-host`; port **443**.
  The address is resolved and checked: loopback, private, link-local (`169.254.169.254`!),
  multicast, unspecified, broadcast, documentation and the **node's own addresses** are rejected
  (the last is protection against a "node connects to itself" loop);
* **`self-hosted`** mode: the requested SNI is ignored, always one own site.
  ⚠ In the current code forwarding to the local site **does not work** (the `--decoy-local-site`
  target goes through the same SSRF filter that forbids loopback, and is passed as a hostname) —
  see [DEPLOYMENT.md](DEPLOYMENT.md) §6.4.

The tag is verified **before any asymmetric cryptography**: nothing heavier than HMAC on
unauthenticated input, otherwise a scanner's probe would be a DoS amplifier.

---

## 4. Cryptography

### 4.1 Primitives

There is no custom arithmetic; everything is a standard implementation:

| Purpose | Primitive | Implementation |
|---|---|---|
| Key exchange | X25519 | `x25519-dalek` |
| Node authentication | a second X25519 with the node's static key | `x25519-dalek` |
| KDF | HKDF-SHA256 (RFC 5869) | `hkdf` |
| `ClientHello` tags | HMAC-SHA256, truncated to 16 B | `hmac`, comparison — `subtle::ConstantTimeEq` |
| Data AEAD | AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 | AES-GCM — `ring`; ChaCha — `chacha20poly1305` (RustCrypto) |
| mesh capsules | HPKE Base: X25519 / HKDF-SHA256 / ChaCha20-Poly1305 (RFC 9180) | `hpke` |
| QUIC Initial | AES-128-GCM + AES-ECB header protection (RFC 9001 §5) | `aes-gcm`, `aes` |
| Secret wiping | `zeroize` (`Zeroizing`, `ZeroizeOnDrop`) | `zeroize` |

### 4.2 The `ClientHello` tag

`tag = HMAC-SHA256(key, msg)[0..16]`, placed in `session_id[16..32]`.
Time window: `step = ⌊unix_secs / 60⌋`. [К] `crypto/session.rs::SessionAuth`

| Version | `key` | `msg` |
|:-:|---|---|
| 2 (anonymous) | `auth_key` = 32 zero bytes | `step` (u64 BE) |
| 3 | `nrxp_secret` (32 B) | `"nrxp-handshake-v3"` ‖ `step` ‖ `random(32)` ‖ `client_eph_pub(32)` |
| 4 | `nrxp_secret` | `"nrxp-handshake-v4-ring-aead"` ‖ `step` ‖ `random` ‖ `client_eph_pub` |
| 5 | `nrxp_secret` | `"nrxp-handshake-v5-cipher-pref"` ‖ `[cipher_pref]` ‖ `step` ‖ `random` ‖ `client_eph_pub` |
| 6 | `nrxp_secret` | `"nrxp-handshake-v6-routing-policy"` ‖ `[cipher_pref, route_mode, route_hops]` ‖ `step` ‖ `random` ‖ `client_eph_pub` |

Properties:

* **Binding to the connection.** The salt and the client's ephemeral key go under the HMAC: an
  intercepted tag cannot be pasted into another `ClientHello`.
* **Binding of version and preferences.** The label depends on the version, and the cipher and route
  preferences go into the HMAC — tampering with these bytes on the path breaks the tag.
  (The exception is a downgrade to v2: see §4.2.1.)
* **Window.** The server tries `step-2 … step+2` (`AUTH_WINDOW_SIZE = 2`, `AUTH_TIME_STEP = 60 s`) —
  **5 candidates, ±2 minutes**, always **all five**, with no early exit; comparison via `subtle`,
  result accumulation via `Choice`. No branching on the secret.
* **Replay.** There is no store of used tags. A verbatim replay of an intercepted `ClientHello` passes
  the tag check as long as the time step is within the window (≈ 2–3 minutes after interception).
  The attacker will not derive the keys (they have no ephemeral private key, and the server mixes in
  a fresh salt), and will have no auth frame, so they get no tunnel — but the node **will respond like
  a node** (`ServerHello` + cover flight, not like the decoy), i.e. a replay works as an active probe.
  See [SECURITY_MODEL.md](SECURITY_MODEL.md) §4, §6.

#### 4.2.1 The anonymous scheme and downgrade

The v2 tag contains no secret: anyone who knows the formula computes it. It exists only for
compatibility during rollout. While a node is **not** in strict mode, an active middleman can rewrite
`session_id[0]` to 2 and steer the connection to the unauthenticated scheme;
`PROXY_NRXP_STRICT=true` closes this (then `verify_handshake_tag` returns `false` for v2).

### 4.3 Key derivation

[К] `SessionKeys::generate_keys`

```text
salt = initiator_random(32) ‖ responder_random(32)           64 bytes; initiator = client
ikm  = DH(e_local, e_peer)                                    v2
ikm  = DH(e_local, e_peer) ‖ DH_static ‖ domain [‖ suite_be16]   v≥3, where:
         v3: domain = "nrxp-v3-static-dh"            (no suite)
         v4: domain = "nrxp-v4-ring-aead"            ‖ suite
         v5, v6: domain = "nrxp-v5-cipher-preference" ‖ suite
       DH_static:  client = DH(e_client_priv, S_node_pub)
                   server = DH(S_node_priv,  e_client_pub)        (the same value)
PRK  = HKDF-Extract(salt, ikm)
client_aead = HKDF-Expand(PRK, "client_aead", 32)
client_iv   = HKDF-Expand(PRK, "client_iv",   12)
server_aead = HKDF-Expand(PRK, "server_aead", 32)
server_iv   = HKDF-Expand(PRK, "server_iv",   12)
auth_key    = HKDF-Expand(PRK, "auth_key",    32)
```

`suite` is the identifier of the TLS suite chosen by the server in `ServerHello` (`1301/1302/1303`),
big-endian. Client: `tx = client_*`, `rx = server_*`; the server mirrors it.

* **Forward secrecy.** The ephemeral private key is consumed by `take()`/`burn()` right after
  derivation; `ikm`, keys and IVs live in `Zeroizing` and are wiped on `Drop`.
* **Node authentication** is the second DH: only the owner of `S_node_priv` can compute it. The static
  key is **not transmitted** over the wire (the client knows it in advance) and is not a stable
  identifier in a packet.
* `PRK` is additionally saved as `datagram_root` for the UDP leg (§7.2) — the UDP leg needs no
  second handshake.

### 4.4 Choosing the data AEAD

The server chooses the suite and puts it into `ServerHello`; the data AEAD is determined by it.
[К] `TlsBridge::wrap_server_hello`, `SessionKeys::set_tls_cipher_suite`; [И] verified by running it.

| Client version | Preference | Result |
|:-:|---|---|
| < 4 | — | always ChaCha20-Poly1305 (`AAD = nonce`, legacy) |
| 4 | — | the first of `[1301, 1302]` that the client offered (AES-GCM mandatory) |
| ≥ 5 | `auto` (0) | AES-GCM: in practice **`1301` AES-128-GCM** [И] |
| ≥ 5 | `1`/`2`/`3` | exactly the requested suite if both have it; otherwise refusal → fallback |

Mapping: `1301` → AES-128-GCM (the **first 16 bytes** of the 32-byte key are used), `1302` →
AES-256-GCM, `1303` → ChaCha20-Poly1305. [И] with `auto` a v5 client got `1301`; with
`ChaCha20Poly1305` — `1303`; with a mesh policy — v6.

A consequence for the documentation: **current clients encrypt data with AES-128-GCM by default**,
not ChaCha20-Poly1305 (ChaCha is for v<4, wasm-edge and by explicit request).

### 4.5 Nonce, AAD, counters, rekeying

[К] `crypto/chacha.rs`

* `nonce(12) = base_iv XOR (0⁴ ‖ counter_be64)` — XOR over bytes `[4..12]` of the IV. `counter` is a
  u64, **separate per direction**, starts at 0 and grows with each `ApplicationData` record. The
  nonce is **not transmitted**: both sides compute it in lockstep.
* Consequences: nonce reuse under one key is excluded by construction; **a skipped, duplicated or
  reordered record** within a TCP leg desynchronizes the counters → an AEAD error → the leg is reset
  (`ErrorAction::Drop`) and reconnects with new keys.
* `AAD`: v≥4 — **empty**; v<4 with ChaCha — the `nonce` itself.
* **Rekeying** (AES-GCM only): every `2²⁰` records in a direction the key and IV are updated by a
  symmetric ratchet, with no network exchange:
  `ratchet₀ = key`; `next = HKDF-Expand(ratchet, "nrxp-stream-ratchet-next", 32)`;
  `key = HKDF-Expand(next, "nrxp-stream-aead-key", 32)`;
  `iv = HKDF-Expand(next, "nrxp-stream-aead-iv", 12)`; counter → 0.
  ChaCha has no rekeying (a u64 counter is never exhausted).

### 4.6 The per-frame tag in the frame header

Every frame carries a 16-byte `auth_tag` field (§5.1). The sender fills it with
`HMAC-SHA256(auth_key, ⌊unix/60⌋)[0..16]`. **The receiver does not verify this field in the data
phase** (`RxCodec::decode_inbound` does not call `verify_tag`; the field lies *inside* the AEAD
plaintext). Integrity, ordering and replay protection in the data phase are provided by the AEAD and
the nonce counter (§4.5). The time window is checked only on `ClientHello` (§4.2). Early editions of
ARCH.md/SECURITY.md described the opposite; this has been corrected. For datagrams the field is
always zero.

---

## 5. Record and frame

### 5.1 The NRXP frame

A frame is the unit of multiplexing; it lives **inside** an encrypted record. [К] `nrxp/frame.rs`

```text
┌──────────┬───────────┬──────┬─────────────┬─────────────┬─────────┬─────────┐
│ auth_tag │ stream_id │ type │ payload_len │ padding_len │ payload │ padding │
│  16 B    │   4 B     │ 1 B  │    2 B      │    2 B      │  N B    │ 0..2¹⁶  │
└──────────┴───────────┴──────┴─────────────┴─────────────┴─────────┴─────────┘
 └────────────── FRAME_HEADER_SIZE = 25 ────────────────┘
```

Padding is random bytes at the frame's tail (inside the AEAD); the receiver skips `padding_len` bytes.
`payload_len` is a u16, but the usual payload ceiling is `MAX_FRAME_PAYLOAD = 16360` (§5.2).

| `type` | Name | Payload | Direction |
|:-:|---|---|---|
| `00` | **Connect** | UTF-8 `host:port` (a name or an IPv4 literal). Open a TCP stream | client → server |
| `01` | **Data** | TCP stream bytes, ≤ 16360 | both |
| `02` | **Close** | empty; on `stream_id=0` — the text `auth_rejected: …` | both |
| `03` | **Heartbeat** | `PING` / `PONG` / empty / the auth payload on `stream_id=0` (§3.7) | both |
| `04` | **UdpConnect** | UTF-8 `host:port`. Open a UDP "session" | client → server |
| `05` | **UdpData** | one UDP datagram | both |
| `06` | **Diag** | a JSON snapshot of client diagnostics; `stream_id=0` only; on the server goes to the diagnostics sink, on the client is discarded | client → server |
| `07` | **Credit** | `u32` BE — the **absolute** limit of the stream's Data bytes (§6.5) | receiver → sender |
| `08` | **Cover** | empty / random bytes; the receiver silently discards | both |
| `09` | **SecureConnect** | like Connect, strong-privacy mode | client → server |
| `0a` | **SecureUdpConnect** | like UdpConnect, strong privacy | client → server |
| `0b` | **MeshOnionConnect** | an HPKE capsule (§8.4) | node → node |
| `0c` | **MeshOnionUdpConnect** | the same for UDP | node → node |

Any other type byte ⇒ `Err("Unknown FrameType")` ⇒ the leg is reset.

**Stream identifiers.** u32; the client issues **odd** ones (1, 3, 5, …), the server — **even**
(2, 4, …), step +2. `stream_id = 0` is reserved for service frames (heartbeat, diag, reject).
[К] `muxer.rs::IdGenerator`

**Destination address.** The client's DNS is "fake": the application is given an address from
`100.64.0.0/10` (starting at `100.64.0.1`, LRU 2000, TTL 60 s); on `Connect` the client recovers the
name from it and sends **`host:port` with the name**. The **node** resolves the name (no DNS leak on
the client). If there is no name — `a.b.c.d:port`. [К] `client/src/net/dns.rs`

### 5.2 The `ApplicationData` record

[К] `nrxp/codec.rs`, `nrxp/frame.rs`

* **Invariant:** a frame never crosses a record boundary, but **one record carries one or several
  frames** (`TxCodec::encode_batch`, greedy packing).
* Record: `17 | 03 03 | len` + `AEAD(frames ‖ padding) ‖ tag(16)`.
* The record plaintext ceiling `MAX_RECORD_PLAINTEXT = 2¹⁴ + 1 = 16385` (RFC 8446 §5.2: 16384 + a
  content-type byte). With the 16 B tag the `length` field is at most **16401** — exactly what is
  seen in browsers. `MAX_FRAME_PAYLOAD = 16385 − 25 = 16360`.
* A frame that does not fit in a record (a large control payload, e.g. `Diag`) goes out as a separate
  record **without padding**.
* Chunk sizes: `TUNNEL_INTERLEAVE_CHUNK = 16360` (a multiple of the frame payload, so no 24 B "tail"
  frame is left), `BRIDGE_READ_CHUNK = 4 × 16360`.

### 5.3 Length padding (`PadShaper`)

A record's length travels in plaintext, so without alignment an observer reads the size of every
message. [К] `nrxp/codec.rs::PadShaper`

* For **each connection** (each `TxCodec`) a list of increasing boundaries is built: a floor
  `floor ∈ [96, 512]`; the next boundary = `current + gap`, where
  `gap = clamp(current × r, 24, cap)`, `r ∈ [0.07, 0.34]`, `cap ∈ [256, 640]`; `r` and `cap` are
  **separate for each gap**; the last boundary is 16401.
* A record is padded up to the nearest boundary above; records ≥ 16401 are left alone.
* Padding goes to the tail of the record's last frame (`padding_len`), under the AEAD.
* Why not additive noise: quantization **hides** the size (a set of lengths → one target); with noise
  the expected target `length + E[noise]` is recoverable by averaging. The regularity of the
  boundaries is defeated by there being no step at all.
* Remainder: an observer who collects many records of one connection recovers the *set* of its
  boundaries, but not a step and not the parameters of other connections. `[?]` A full imitation of a
  specific decoy's length distribution requires a live capture.
* `Cover` frames bypass the shaper: their length is set exactly (`encode_cover`).

### 5.4 Parsing on receipt

`RxCodec::decode_inbound` decrypts records one by one into the `staging` buffer, parses frames and
returns the first; the remainder lives until the next call (the reader loops the call until
`Ok(None)`). That is why batching on the send side needed neither a version bump nor receiver
changes. Any AEAD or parsing failure after successful decryption ⇒ `ErrorAction::Drop` (recreate the
leg from scratch). The read buffer is capped at `TUNNEL_MAX_BUFFER_SIZE = 1 MiB` (OOM protection).

---

## 6. Multiplexing and sessions

### 6.1 Session and legs

A session = the client's `session_id` (§3.7). A **leg** is one TCP connection carrying the records of
many streams. A session has up to `MAX_TUNNEL_LEGS = 4` legs; the server joins the legs of one
`session_id` into one `Muxer`. Legs start staggered by `LEG_STAGGER_DELAY (1 s) × id × U(0.6; 1.4)`
(an even step would be a metronome). Client legs keep `TCP_NODELAY`; on Linux/Android both sides set
`TCP_NOTSENT_LOWAT = 2 × 16360` and request `TCP_CONGESTION = bbr` from the kernel (`NR_LEG_CC=off`
disables it; without the module the OS default remains), and the socket buffer sizes adapt to
≈ 2×BDP (`buftune`: floor 256 KiB, ceiling 8 MiB).

### 6.2 Stream lifecycle (TCP)

```text
client                                  server
  Connect(sid=odd, "host:port") ──────▶  TCP connect to the destination (timeout 7 s)
  Data(sid) ────────────────────────▶    ... immediately, without waiting for a reply (0-RTT on an open session)
  ◀──────────────────────── Data(sid)    the destination's data
  ◀──────────────────────── Credit(sid)  issued by the RECEIVER (client) as it consumes (§6.5)
  Close(sid) ◀──▶ Close(sid)             closing by either side
```

* There is no `Connect` acknowledgement in direct mode; on a connection error the node sends `Close`.
  The server also sends `Close` on **any** bridge completion (target EOF, leg write timeout,
  `STREAM_PAUSE_BUDGET`, backlog eviction) — otherwise the client's virtual socket would be stuck in
  `CloseWait` forever. A UDP target is resolved with a 5 s timeout.
* **`Close`/`Data` ordering.** `Close` travels over the leg's priority control channel, but the leg's
  writer **does not let it overtake not-yet-written `Data` of the same stream**; the bridge keeps the
  stream's binding to the leg until `Close` has gone out (it must travel by the same leg). On
  receipt, `Close` = `Muxer::finish_stream`: the consumer reads everything received and sees EOF (the
  client engine delivers EOF to the local socket only after the backlog drains). For `stream_id = 0`
  — immediate removal.
* A stream's binding to a leg is **sticky**: `select_leg` stores `stream_id → leg_id` on the first
  frame; TCP stream order is preserved with no sequence numbers in NRXP.

### 6.3 Leg selection, fault tolerance

[К] `muxer.rs::pick_leg`

* A leg's score `score = max(rtt_ms, 1) × (1 + load_factor)`; `load_factor` accounts for the writer
  queue, bytes at the writer, Linux `notsent` and a recent retransmission.
* Candidates are all legs with `score ≤ 2 × best`; among them **round-robin** (a burst of new streams
  in a speedtest spreads across legs instead of sticking to one).
* **Anti-domino failover** (`send_to_network`): a dead leg is evicted, the frame is resent on a
  neighbour; the stream is not closed.
* **Graceful pause**: if all legs are down, a chunk is held and retried every 250 ms up to
  `STREAM_PAUSE_BUDGET = 30 s` instead of dropping streams.
* UDP frames over TCP legs: not a sticky binding but short **flowlets** — a burst within a pause stays
  on a leg while it is not overloaded.

### 6.4 Heartbeat and health check

* A leg's writer sends `Heartbeat` with a base of `HEALTH_CHECK_INTERVAL = 3 s`, **jitter ±30 %**, and
  a multiplier `1 + idle_streak` (maximum ×8) by the number of consecutive idle intervals (a perfectly
  even period is itself a sign).
* `PING` → `PONG` on the **same leg**, RTT measurement; a reply to someone else's PING is not counted
  (otherwise a garbage RTT would enter `GLOBAL_MIN_RTT`). An empty `Heartbeat` on the server → an
  empty `Heartbeat`.
* `Muxer::perform_health_check` does not send `PING` to a leg with a fresh `PONG`
  (`LEG_PONG_FRESHNESS = 45 s`); the reply timeout is `HEALTH_CHECK_TIMEOUT = 20 s`. On a fully idle
  leg a break is detected in ≈ 65 s, on a loaded one — by the very first write error.

### 6.5 End-to-end flow control (`Credit`)

[К] `net/credit.rs`, `Muxer::credit_gate`

A leg is one TCP connection for many streams and cannot slow down a single slow stream. So the
**receiver** tells the sender the window with `Credit` frames:

* Payload — `u32` BE, an **absolute** limit ("you may send up to N bytes of this stream's Data in
  total", modulo 2³², compared by signed difference). Idempotent: a duplicate or late frame does not
  move the limit back; a lost one is repaired by the next.
* A sender without a single grant is **not limited** — old peers work as before.
* Credit is issued by the client engine (the "server → client" direction) as the application
  **actually consumes** data, and by mesh relays (on their segment). The "client → server" direction
  is not credit-regulated (it is held by TCP backpressure and the stream's 16 MiB backlog on the
  server).
* Window: starts at `CREDIT_INITIAL_WINDOW = 1 MiB`, minimum 256 KiB, maximum 16 MiB per stream, a
  process-wide budget of 64 MiB (`window ≤ budget / receiver count`); grows with the consumption rate
  (`≈ 2 × bytes per RTT`, like `tcp_rcv_space_adjust`). A grant is sent when `window / 4` (at least
  64 KiB) of unannounced bytes accumulate.
* `credit_gate` blocks **only that stream's sender**; if there are no grants for
  `CREDIT_STALL_FALLBACK = 600 s`, sending proceeds unrestricted (protection from a broken peer, but
  not from a player's pause).
* There is no credit for UDP.

### 6.6 Queues and backlogs

| What | Value |
|---|---|
| stream and leg channel | 16 messages (≤ 64 KiB each); deep channels added +100 ms to neighbouring streams |
| stream backlog on the client | 4 MiB |
| stream backlog on the server | 16 MiB |
| backlog eviction | budget exceeded **and** no progress for `BACKLOG_STUCK_GRACE = 5 s` (checked every 500 ms) |
| waiting for the local socket to accept data | `BRIDGE_STREAM_WRITE_TIMEOUT = 30 s` |
| bridge / UDP session / connection idle | 30 s / 15 s / 120 s |
| a consumer that ignores EOF | `STREAM_EOF_LINGER = 30 s` after EOF |

### 6.7 Reconnection and network change

* Pause before reconnecting a leg `LEG_RECONNECT_DELAY = 2 s`, backoff with jitter
  (`RECONNECT_BACKOFF_BASE 2 s + U(0..1 s)`, exponential with a ceiling
  `MAX_RECONNECT_BACKOFF_MS = 10 s`); a "flapping" leg (died faster than `LEG_FLAP_WINDOW = 5 s`) goes
  into an exponential pause; after 10 consecutive failures the engine returns an error and the outer
  loop re-resolves DNS.
* The network watcher (once a second), on a change of the local IP (or an address gap > 3 s), removes
  all legs and brings them up again. A tunnel with no leg at all for `TUNNEL_DEAD_AFTER = 30 s` is
  considered dead (after a network change — a `NETWORK_CHANGE_DEAD_GRACE = 90 s` window).
* `auth_rejected` marks the session fatal: all legs stop reconnecting.
* A session with no legs is removed after `SESSION_CLEANUP_DELAY = 120 s`.

---

## 7. UDP leg

An optional parallel transport for `UdpData`. If it does not come up, UDP travels over the TCP legs
as `UdpData` — nothing else is required.

### 7.1 The ladder and establishment

```text
1. QUIC mimicry ─┐ equal priority, the choice is a fair coin (CSPRNG, not derived from the session secret)
   WebRTC mimicry┘
2. bare UDP (raw)
3. TCP leg (UdpData over TCP)
```

* **One attempt per session**, no aggressive retries (UDP blocking is usually permanent). The client
  tries one engine; if no decrypted datagram **at all** arrives within
  `DATAGRAM_LEG_HANDSHAKE_TIMEOUT = 3 s` — raw; if that is silent too — we stay on TCP. The
  establishing `PING` is resent at offsets 0 / 300 / 800 / 1500 ms.
* There is no second handshake: keys are derived from `datagram_root` (§7.2); the server finds the
  session by the 16-byte `leg_token` and brings the leg up on the first successfully decrypted
  datagram. One server UDP socket (**the same port number as TCP**) serves all sessions; the peer's
  address is read on every send (roaming behind NAT).
* Classifying an incoming datagram by its first byte: ranges QUIC short header / RTP (`128..191`,
  RFC 7983) / everything else (raw).
* A `UdpData` frame > `MAX_DATAGRAM_LEG_PAYLOAD = 1150` B goes over TCP (no fragmentation); the outer
  UDP payload targets ~1250 B.
* An early `UdpData` may overtake its `UdpConnect` (which travels over TCP): the server buffers up to
  256 streams × 16 KiB × 2 s.

### 7.2 UDP leg keys

[К] `crypto/datagram_keys.rs`

```text
root        = the main handshake's PRK (datagram_root) ‖ negotiated suite
leg_token   = HKDF-Expand(root, "dgram-leg-token", 16)          (no engine label!)
for engine E ∈ {quic, webrtc, raw}, attempt A (always 0 now), info(x) = x ‖ 00 ‖ E ‖ 00 ‖ A_be16:
chain_c2s₀  = HKDF-Expand(root, info("dgram-chain-c2s"), 32)
chain_s2c₀  = HKDF-Expand(root, info("dgram-chain-s2c"), 32)
hp_c2s, hp_s2c = HKDF-Expand(root, info("dgram-hp-c2s"/"dgram-hp-s2c"), 32)   (QUIC header protection)
```

The engine label is needed so that a mimicry attempt and the fallback raw do not share a key and do
not reuse a one-time Poly1305 key when counters coincide (bug #18). `leg_token` has no label: the
server looks the session up by it **before** decryption.

**The ratchet** (the symmetric half of a double ratchet, no DH): per epoch —
`key = HKDF-Expand(chain, "dgram-epoch-key", 32)`, `salt = HKDF-Expand(chain, "dgram-epoch-salt", 12)`;
a step — `chain' = HKDF-Expand(chain, "dgram-epoch-next", 32)`, the old value is wiped. The epoch
changes after `2²⁰` datagrams per direction. Compromising epoch N's keys does not open N−1; it does
**not** provide post-compromise security (the ratchet is deterministic).

### 7.3 The datagram codec

[К] `nrxp/datagram.rs`

* `nonce = salt XOR (0⁴ ‖ counter_be64)`; a full 64-bit counter at the sender, only the low `W` bits
  on the wire (16 for RTP mimicry, 32 for QUIC/raw); the receiver reconstructs the full counter with
  the QUIC algorithm (RFC 9000 App. A.3 / SRTP ROC).
* AAD is the packet's plaintext header (as in SRTP/QUIC). Frame: the same NRXP header (25 B,
  `auth_tag` zero), no padding; the AEAD is the same suite as on TCP.
* Anti-replay: a sliding window of **2048** datagrams (like WireGuard), checked only *after* a
  successful AEAD; the epoch advance is also committed only after it. The epoch is guessed by trying
  neighbours (`current` → `+1` → `−1`).

### 7.4 QUIC mimicry (`quiceng`)

* **The first packet** is a real QUIC v1 Initial (RFC 9000 §17.2.2): Initial keys are derived from the
  public RFC 9001 salt and the plaintext DCID, the cipher is AES-128-GCM, header protection is
  AES-ECB — any QUIC stack (and DPI) will decrypt it; inside is our `ClientHello` (the same
  `TlsBridge::wrap_client_hello`) with ALPN `h3`, `quic_transport_parameters`, and an empty
  `legacy_session_id`.
* **Subsequent packets** are QUIC 1-RTT short header (RFC 9000 §17.3.1): the first byte
  `0x40 | key_phase | (pn_len−1)`, an 8 B DCID (`QuicProfile::CHROME`, version 1; half of
  `leg_token`: client → `[0..8]`, server → `[8..16]`), a 1–4 B packet number, header protection by a
  ChaCha20 mask (RFC 9001 §5.4.4); the sample is taken at offset 4 from the start of the PN. 1-RTT
  keys are not public, so the HP algorithm is unobservable.
* One NRXP frame per packet (no coalescing of QUIC packets).
* `[?]` The QUIC profile was not taken from a live capture; `QuicMode::Real` (real QUIC for
  self-hosted) is an extension point and not implemented.

### 7.5 WebRTC mimicry (`webrtceng`)

RTP (RFC 3550): V=2, X=1 (a one-byte `0xBEDE` header extension, 1 word), PT = 96 (VP8, 90 kHz), `seq`
with a random start, `timestamp` from real time, `SSRC` from `leg_token` (client — bytes `[0..4]`,
server — `[4..8]`). AAD is the whole RTP header (as in SRTP, RFC 7714). There is no epoch number on
the wire — trial decryption; no trailer. `[?]` The profile was not taken from a live capture
(Meet/Zoom/Discord), ICE/STUN/DTLS are not imitated; there is no mimicry of the time structure
(bursts on key frames).

### 7.6 Raw UDP

```text
leg_token(16) ‖ epoch_id(1) ‖ wire_counter(4) ‖ ciphertext
```
AAD is the entire prefix. No mimicry (`RAW_DGRAM_OVERHEAD = 21 + 25 + 16`). It exists because bare UDP
sometimes passes where neither a QUIC- nor an RTP-like shape does.

### 7.7 Keepalive

When idle — `PING` at an interval of `U(15; 25 s)` (a fixed period would be a sign; the upper bound is
below a typical NAT timeout of ≈ 30 s and `LEG_PONG_FRESHNESS`). Liveness is marked by any real frame.

---

## 8. Mesh routing between nodes

Mesh is enabled on a node with the `--mesh-enabled` flag (requires `PROXY_NODE_ID`,
`PROXY_INTERNAL_SECRET`, `--backend-url`, and NRXP credentials). The **ingress** node accepts the
client and, per policy, carries the stream through a chain of nodes to the **egress** — the one whose
IP the destination sees. The peer catalog is supplied by the control plane (§9). A narrative
description with advantages and limits — [MESH.md](MESH.md).

### 8.1 Peer authentication inside the tunnel

A peer connects to another node as an ordinary NRXP client (with the **recipient's** `nrxp_secret` and
static key, taken from the catalog) and, in the auth frame (§3.7), sends a claim instead of a token:

| Prefix | Grammar of the `auth_token` field |
|---|---|
| `mesh:` | `mesh:<peer_id>:<peer_secret>` — direct egress, no route |
| `mesh2:` | `mesh2:<peer_id>:<peer_secret>:<remaining_hops>:<selection>:<visited,csv>` |
| `mesh3:` | `mesh3:<peer_id>:<peer_secret>:<remaining_hops>:<selection>:<egress_id>:<visited,csv>` |
| `mesh4:` | `mesh4:<peer_id>:<peer_secret>` — an onion session: the route travels in capsules (§8.4) |

`selection` ∈ `nearest`, `weighted-random`. Constraints: `node_id` — `[A-Za-z0-9-]`, ≤ 64;
`peer_secret` ≤ 128 with no control characters; the whole claim ≤ 1024 B; `remaining_hops ∈ [1, 8]`
(`MAX_MESH_HOPS = 8`); a loop-free route (case-insensitive comparison), length
`remaining_hops + |visited| − 1 ≤ 8`; the second-to-last element of `visited` must be the peer
itself, the last — the local node; `egress_id` cannot appear before the end of the path; with
`remaining_hops = 1` it is the last, otherwise it is not. The validity of the peer's secret is checked
with the control plane (`/mesh/validate`, cached).

The peer confirms route readiness with `Heartbeat` markers: `PONG` (legacy), `NRXP-MESH2-READY`,
`NRXP-MESH-ONION1-READY`; exhaustion of backup egresses — `NRXP-MESH-EGRESS-EXHAUSTED`.

### 8.2 Client route policy

The client states it in `session_id[2..4]` (v6, confirmed by the tag, §4.2):

| Mode | `[2]` | `[3]` | Effect |
|---|:-:|:-:|---|
| default (node policy) | 0 | 0 | the node's `--mesh-max-hops` |
| `direct` | 1 | 1 | 1 node, no mesh |
| `two-hop` | 2 | 2 | ingress + 1 egress |
| `x-hop-N`, N ∈ 3..8 | 3 | N | path length random in `[3, N]` |

The node's `--mesh-max-hops` is a **hard upper bound** (`effective_max_hops = min`).

### 8.3 Route selection

For each application stream the ingress chooses an egress and a path length once: candidates are
peers with a fresh (≤ 90 s) RTT measurement (`PEER_PROBE_MAX_AGE`), ranked by RTT and weighted random
(`WeightedRandom`); when fresh data is lacking — a fallback two-node route from the catalog. The chain
is pinned to the stream for its whole life. Peers that fail 3 probes in a row are excluded
(`PEER_PROBE_TIMEOUT = 8 s`). Sessions to peers are pooled (≤ 256, idle 300 s).

### 8.4 Onion capsules

[К] `net/mesh_onion.rs`

The ingress builds the route **from the end**: each node receives only its own instruction and an
opaque capsule for the next one. A capsule is HPKE Base (RFC 9180): `KEM = X25519-HKDF-SHA256`,
`KDF = HKDF-SHA256`, `AEAD = ChaCha20-Poly1305`; the recipient's key is its NRXP `static_public`;
`info = "netrunner-mesh-onion-v1" ‖ 00 ‖ node_id` (a capsule cannot be replayed to another name with
the same key); empty AAD.

```text
wire      = enc(32) ‖ ciphertext          ≤ MAX_ONION_CAPSULE_SIZE = 12 KiB
plaintext = version(1)=2 ‖ strong_privacy(1) ‖ is_udp(1) ‖ remaining_hops(1)
          ‖ expires_at_unix(u64) ‖ replay_nonce(16) ‖ kind(1) ‖ body
kind=1  Forward: node_id(u8+str) host(u16+str) port(u16) decoy_sni(u16+str)
                 nrxp_secret(u8+str) nrxp_static_public(u8+str) next_capsule(u16+bytes)
kind=2  Exit:    target(u16+str ≤ 2048) failovers_left(u8) has_fallback(u8)
                 [ fallback_peer…(as Forward) ‖ fallback_capsule ]
```

Version 1 (without backup egresses) is read for compatibility. Invariant: `Forward` is allowed with
`remaining_hops ∈ 2..8`, `Exit` — only with `1`; `has_fallback` ⇔ `failovers_left > 0` (≤ 7).

Egress fault tolerance: a chain of pre-chosen backup egresses (up to 7) is embedded in capsules; when
connecting to the destination fails, the egress node tries the next one; the end-to-end stream setup
deadline is **65 s**.

Capsule protection: a **lifetime** `ONION_CAPSULE_MAX_AGE_SECS = 120` (checked against
`expires_at_unix`); a **replay cache** by `replay_nonce` (up to 262,144 entries, swept every 1024
insertions; on overflow — refusal); a route with a loop and protocol violations are counted by the
`netrunner_mesh_onion_*_rejections_total` metrics.

### 8.5 Mesh QUIC

The node ⇄ node transport is real QUIC (`quinn`, ALPN `nrxp-mesh/1`), UDP port `--mesh-quic-port`
(**8443** by default). The TLS certificate is ephemeral and self-signed (`mesh.netrunner`), and the
client does **not verify** it: the peer's identity is established by the inner NRXP handshake
(§3–§4), without which a mesh session is not accepted. Before authentication, limits apply: ≤ 512
concurrent connections/handshakes, a datagram buffer of 256 KiB receive / 64 KiB send. The port
listens **for mesh peers only**: a non-mesh claim is rejected (`mesh_quic_non_mesh_rejected`). Clients
reach the ingress over ordinary NRXP (TCP/UDP), not over this port.

### 8.6 Strong privacy

A client mode (`--strong-privacy`, `SecureConnect`/`SecureUdpConnect`): the route goes only through
onion capsules (opening a stream directly is rejected); the ingress node **mixes** frames of different
streams in windows of `MIX_BATCH_WINDOW = 20 ms` (≤ 512 packets; order within a stream is preserved),
and while streams are active sends background `Cover` frames on `stream_id = 0`: interval
`U(0.9; 2.4 s)`, size `U(128; 384)` random bytes. The price is latency.

---

## 9. Control plane (HTTP contract)

The core knows only the `AuthValidator` trait; the implementation in `server/src/backend_client.rs`
(`reqwest`) talks to the control plane over HTTP. Any compatible backend can be written yourself. All
requests carry the header **`X-Internal-Secret: <the node's PROXY_INTERNAL_SECRET>`** (each node's
secret is its own; it is never given to clients).

| Method and path | Request body | Response | Notes |
|---|---|---|---|
| `POST /api/v1/internal/validate` | `{"token": "<Bearer>"}` | `{"user_id": str, "limit_bytes": u64\|null, "used_bytes": u64}` | success cached for 60 s per token; an empty token is rejected locally |
| `POST /api/v1/internal/usage` | `{"user_id", "delta_bytes"}` | `{"used_bytes", "limit_bytes", "over_limit"}` | a single report |
| `POST /api/v1/internal/usage/batch` | `{"batch_id", "entries": [{"user_id", "delta_bytes"}]}` (≤ 1000) | a list of `{"user_id", "used_bytes", "limit_bytes", "over_limit"}` | batched traffic report |
| `POST /api/v1/internal/node-health` | anonymous node telemetry (sessions, legs, streams, MB up/down, error counters, uptime) | any 2xx | best-effort, no user_id/IP/destinations |
| `GET /api/v1/internal/mesh/peers` | — | `[{"node_id","host","port","decoy_sni","nrxp_secret","nrxp_static_public"}]` | the mesh peer catalog |
| `POST /api/v1/internal/mesh/validate` | `{"peer_id","peer_secret"}` | 2xx = accepted | success is cached |

Circuit breaker: 5 consecutive network errors/5xx (a 4xx for a specific token does **not** count) open
the circuit for 10 s — afterwards an immediate refusal with no HTTP call
(`netrunner_circuit_breaker_open`). `over_limit = true` in a traffic report is a signal to drop the
user's streams.

---

## 10. Edge relays and MASQUE

* **`client-edge`** (a Cloudflare Worker, wasm) and **`edge-native`** (an ordinary service on a VDS) —
  the same client side of NRXP without `tokio::net` (`core::edge::EdgeHandshake`): one logical TCP
  channel to the node (no multiplexer, no multiple legs), the inbound side being a WebSocket over real
  TLS (WSS). The hosting provider sees the VDS → node connection.
* **`masque-edge`** — a separate HTTP/3 relay for iOS Network Relay: TCP `CONNECT` and UDP
  `CONNECT-UDP` (RFC 9298), UDP stays in QUIC DATAGRAM. **Not NRXP**; its own token
  (`MASQUE_AUTH_URL`/`MASQUE_TOKEN`), UDP/8444. Private/loopback/link-local destinations are rejected
  by default (`--allow-private-targets` — lab only). Experimental, not production-hardened (ACLs, rate
  limiting, UDP-amplification protection — still to come).

---

## 11. What an observer sees

A passive observer of the TCP leg sees: TCP:443; a `ClientHello` of ≈ 1.7 KB with a Chrome 140
fingerprint (JA3/JA4 rotate via extension shuffling, GREASE random per connection) and SNI =
`decoy_sni`; `ServerHello` 127 B + `CCS`; then the **first `ApplicationData` — from the server**
(4 records 41/2385/97/53 B); after that `ApplicationData` records with irregular quantized lengths
≤ 16401. A heartbeat with ±30 % jitter and a ×1…8 back-off when idle.

What in this picture **differs from a real TLS server** (an honest list of residual signs; more
detail and an assessment — [SECURITY_MODEL.md](SECURITY_MODEL.md) §6):

1. **There is no certificate.** The server presents no chain; the cover flight only reproduces
   *sizes*. Anyone who drives a real TLS handshake to completion will find the discrepancy.
2. **SNI ↔ IP.** The SNI is someone else's decoy site, which does not resolve to the node's IP (a
   detector that costs one DNS query). Cured only by your own domain on the node (`self-hosted` mode,
   which currently does not work — DEPLOYMENT.md §6.4).
3. **Active probing by a client owner.** The tag is verified under the `nrxp_secret` that every client
   of the node has. A censor who obtains a valid client config can compute the tag and classify the
   node with one probe.
4. **Record lengths** — residual statistics (§5.3); the cover flight is not calibrated against a live
   decoy `[?]`; GREASE-ECH sizes `[?]`.
5. QUIC/RTP UDP mimicry is calibrated against the specifications, not a live capture `[?]`; a deep
   inspection would run into there being no `Certificate`/`Finished` after the `ClientHello`.

---

## 12. Constants table

| Constant | Value | Where |
|---|---|---|
| `PROTOCOL_VERSION` | 6 (3 without `ring-aead`) | `lib.rs` |
| `FRAME_HEADER_SIZE` | 25 | `nrxp/frame.rs` |
| `MAX_RECORD_PLAINTEXT` / `MAX_FRAME_PAYLOAD` | 16385 / 16360 | `nrxp/frame.rs` |
| max record `length` field | 16401 | `nrxp/codec.rs` |
| `AUTH_TIME_STEP` / `AUTH_WINDOW_SIZE` | 60 s / 2 (±2 min, 5 candidates) | `net/constants.rs` |
| `MAX_TUNNEL_LEGS` | 4 | `net/constants.rs` |
| `TLS_HELLO_TIMEOUT` / `SECURE_HANDSHAKE_TIMEOUT` | 10 s / 20 s | `net/constants.rs` |
| `HEALTH_CHECK_INTERVAL` (heartbeat base) | 3 s (±30 %, ×1…8) | `net/constants.rs` |
| `LEG_PONG_FRESHNESS` / `HEALTH_CHECK_TIMEOUT` | 45 s / 20 s | `net/constants.rs` |
| `LEG_RECONNECT_DELAY` / `MAX_RECONNECT_BACKOFF_MS` | 2 s / 10 s | `net/constants.rs` |
| `TUNNEL_DEAD_AFTER` / `NETWORK_CHANGE_DEAD_GRACE` | 30 s / 90 s | `net/constants.rs` |
| `STREAM_PAUSE_BUDGET` | 30 s | `net/constants.rs` |
| `STREAM_BACKLOG_MAX_BYTES` / `SERVER_…` | 4 MiB / 16 MiB | `net/constants.rs` |
| `CREDIT_INITIAL_WINDOW` / `MIN` / `MAX` / `GLOBAL_BUDGET` | 1 MiB / 256 KiB / 16 MiB / 64 MiB | `net/credit.rs` |
| `CREDIT_STALL_FALLBACK` | 600 s | `net/constants.rs` |
| `DATAGRAM_LEG_HANDSHAKE_TIMEOUT` | 3 s | `net/constants.rs` |
| `MAX_DATAGRAM_LEG_PAYLOAD` | 1150 B | `net/constants.rs` |
| `DATAGRAM_KEEPALIVE_MIN` / `MAX` | 15 / 25 s | `net/constants.rs` |
| `REKEY_AFTER_DATAGRAMS` / `STREAM_REKEY_AFTER_RECORDS` | 2²⁰ / 2²⁰ (AES-GCM) | `nrxp/datagram.rs`, `crypto/chacha.rs` |
| datagram anti-replay window | 2048 | `nrxp/datagram.rs` |
| `FALLBACK_CONNECT_TIMEOUT` / `MAX_FALLBACK_BRIDGES` / idle | 5 s / 512 / 60 s | `net/connection/connection.rs` |
| `MAX_MESH_HOPS` | 8 | `net/auth.rs` |
| `MAX_ONION_CAPSULE_SIZE` / lifetime | 12 KiB / 120 s | `net/mesh_onion.rs`, `net/mesh.rs` |
| `DEFAULT_MESH_QUIC_PORT` | 8443 (UDP) | `net/constants.rs` |
| `DEFAULT_DECOY_HOST` | `www.debian.org` | `net/constants.rs` |
| `BUF_FLOOR` / `BUF_CAP` of a leg buffer | 256 KiB / 8 MiB | `net/connection/buftune.rs` |

---

## 13. How it is verified

```bash
cargo test -p netrunner-core --lib           # 244 tests, crypto/frames/handshake/engines/mesh
cargo test -p netrunner-core --features ring-aead --lib   # including the AES-GCM branches
```

Key tests (name → what it pins down): `legitimate_handshake_succeeds_over_real_tcp` (a real server on
localhost; the tail after `ServerHello` consists entirely of `Cover`),
`mitm_without_the_node_private_key_derives_different_keys`,
`tampered_auth_tag_in_session_id_is_rejected_by_server`,
`chrome_client_hello_matches_the_live_capture_shape`,
`record_lengths_share_no_recoverable_step_within_a_connection`,
`record_length_never_exceeds_real_tls13_maximum`, `server_close_neither_overtakes_data_nor_gets_lost`,
`sender_stops_at_the_credit_limit_and_resumes_on_grants`,
`client_falls_back_to_raw_when_the_mimicry_engine_gets_no_reply`.

Load and flow under loss/delay: `tools/loadtest`, `scripts/netns-stand/`.

What the tests do **not** prove: the constant-time property of tag verification (it lives in machine
code; ensured by construction through `subtle`, and must be measured with `dudect`/`cachegrind` on the
target architecture) and "indistinguishability" from a real browser (a live capture is needed).
