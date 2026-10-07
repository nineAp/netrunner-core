# Netrunner security model

🇷🇺 [Русская версия](../SECURITY_MODEL.md)

This document answers three questions: **what we protect**, **from whom**, and **with what**. It is
deliberately written as a threat model, not as marketing: for each adversary it states what
succeeds and what does not. Byte-level formats are in [PROTOCOL.md](PROTOCOL.md); a plain-language
explanation of "why the cryptography here is sound" (and a comparison with MTProto) is in
[SECURITY.md](SECURITY.md); deployment and hardening are in [DEPLOYMENT.md](DEPLOYMENT.md).

> All statements were checked against the `main` code and, where possible, by running it (a server
> with real keys, `curl` probes, `cargo test -p netrunner-core` — 244 tests). Mismatches between
> earlier documentation wording and the code are **called out** in section 7 — better to know them
> than to find them.

## Contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [Parties and trust boundaries](#2-parties-and-trust-boundaries)
3. [Adversaries](#3-adversaries)
4. [Protection mechanisms and what they provide](#4-protection-mechanisms-and-what-they-provide)
5. [Secrets and keys](#5-secrets-and-keys)
6. [Indistinguishability: what exists and what does not](#6-indistinguishability-what-exists-and-what-does-not)
7. [Known limitations and discrepancies with earlier descriptions](#7-known-limitations-and-discrepancies-with-earlier-descriptions)
8. [User data privacy](#8-user-data-privacy)
9. [Attack surface and resilience](#9-attack-surface-and-resilience)
10. [Node operator requirements](#10-node-operator-requirements)
11. [Reporting a vulnerability](#11-reporting-a-vulnerability)
12. [Possible improvements](#12-possible-improvements-for-developers)

---

## 1. Goals and non-goals

**Goals** (in order of importance):

1. **Confidentiality and integrity** of traffic between the client and the exit node in the face of
   a passive and an active on-path observer.
2. **Forward secrecy**: traffic recorded today cannot be decrypted tomorrow even with full access
   to the node (its long-term keys).
3. **Node authentication** by the client: an active man-in-the-middle cannot silently replace the node.
4. **Resistance to blocking**: a connection should look like ordinary HTTPS and offer no simple way
   to classify the node by probing.
5. **Do not degrade privacy at the operator**: the node writes neither destinations nor content to disk.

**Non-goals** (what the system does not promise):

* **Anonymity relative to the node operator.** The exit node sees the `host:port` of every
  connection, resolves names, and sees the plaintext of anything not protected by its own TLS.
  Trust in the operator is part of the model. (Mesh/strong privacy modes spread knowledge across
  several nodes but do not make you anonymous in the Tor sense.)
* **End-to-end encryption** to the destination: the channel is protected client ⇄ exit node.
* **Protection from a global observer** correlating a node's inbound and outbound traffic by timing
  and volume.
* **Protection of a compromised device** (malware, root on the phone/router).
* **Indistinguishability against a censor with unlimited resources and live captures.** The mimicry is
  calibrated but not proven (section 6).
* **Protection from network-level DoS** (L3/L4 floods) — that is the hosting provider's/firewall's job.

---

## 2. Parties and trust boundaries

```text
 device ──(1) NRXP channel──▶ INGRESS node ──(mesh, optional)──▶ EGRESS node ──▶ destination
     │                              │                                       │
     └─(2) HTTPS: login, node list, node keys─▶ control plane ◀─(3) /internal/*, X-Internal-Secret─┘
```

| Party | What we trust | What we do **not** trust |
|---|---|---|
| Client **device** | stores the token, `nrxp_secret` and the node's public key | — (out of model, §1) |
| **Channel (1)** | nothing: assumed fully controlled by the adversary | — |
| **Exit node operator** | sees destinations and plaintext | must be chosen deliberately |
| **Control plane (2)(3)** | gives the client the address, SNI, `nrxp_secret` and the node's **public** static key over HTTPS; this is the **root of trust** for node authentication | must not know the node's private key |
| **Node hosting provider** | — | sees netflow, can take a disk/RAM image: the node's private key and `PROXY_INTERNAL_SECRET` are "in the palm of their hand" |
| **Destination** (site) | — | sees the exit node's IP |

The client's root of trust is the **delivery channel of the node's public key**. If it is
compromised (the node list is replaced), the client authenticates a foreign node.

---

## 3. Adversaries

| # | Adversary | Capabilities | Outcome |
|---|---|---|---|
| **A1** | **Passive DPI/ISP** | reads all packets, computes JA3/JA4, lengths, timings, profiles by SNI/IP | sees TLS 1.3 "Chrome → decoy site"; content unavailable. Residual signs — section 6 |
| **A2** | **Active prober without secrets** | opens its own connections to the node, sends arbitrary `ClientHello`s, garbage, plain HTTP | gets the response of a **real** decoy site (relay) — indistinguishable from an ordinary server. **But**: in non-strict mode the node answers "like a node" to **any** v2 `ClientHello` (the tag needs no secret) — see §7.2 |
| **A3** | **Prober with a valid client config / a recorded foreign ClientHello** | knows the node's `nrxp_secret` (every client of the node has it) or replays an intercepted `ClientHello` within the ≈ 2–3 min window | **successfully classifies the node** with one probe: gets `ServerHello` + cover flight instead of the decoy. Gets no tunnel (no keys, no token). Not closed (§6, §7.3) |
| **A4** | **Active on-path MITM** (node substitution, scheme downgrade) | sits between client and node, rewrites bytes | a client with credentials will **not** connect: without the node's static private key the second DH cannot be computed, keys diverge, the first record does not decrypt. Downgrading the client is impossible (the client picks the scheme itself, §7.2). A client **without** credentials (v2) is not protected from MITM |
| **A5** | **Authenticated but malicious user** | has a token/config, tries to use the node for harm | the node **does not filter destinations**: loopback/private/metadata (`169.254.169.254`) are reachable via `Connect`. Only closed by the host firewall (§7.1) |
| **A6** | **Foreign client / scanner that does not know the protocol** | knocks on the port | decoy site; pools and limits (`MAX_FALLBACK_BRIDGES = 512`); SSRF filter on the decoy |
| **A7** | **Compromise of the node's private key** | reads `PROXY_NRXP_PRIVATE_KEY` | can impersonate the node (active MITM) for **future** client connections. Cannot passively decrypt past or future recorded sessions: without the ephemeral keys the first DH cannot be computed (FS). Rotation — section 5 |
| **A8** | **Leak of `nrxp_secret`** | knows the node's shared secret | can probe (A3) and pass the entry barrier; **cannot** decrypt others' sessions and **cannot** MITM (needs the private key) |
| **A9** | **Control-plane compromise** | controls the node list and token validation | can hand clients foreign nodes/keys (root of trust, §2) and see per-`user_id` traffic accounting; **cannot** decrypt sessions with honest nodes |
| **A10** | **Exit node host / server seizure** | disk/RAM dump, VM snapshot | obtains the node's long-term secrets (rotate) and the current keys of live sessions; past sessions — no (FS) |
| **A11** | **Traffic correlation** (global observer) | matches ingress and egress traffic | not protected; partly hindered by mesh/strong privacy (section 4.9) |

---

## 4. Protection mechanisms and what they provide

### 4.1 Confidentiality and integrity

Data is encrypted with an AEAD (by default for current clients — **AES-128-GCM**; AES-256-GCM or
ChaCha20-Poly1305 by explicit client preference, ChaCha for v<4 and wasm-edge). Encryption and
authentication are inseparable; a verification failure tears the leg down, not a "nearly correct"
result. Padding sits **under** the encryption and inside the authentication zone.
Details: PROTOCOL.md §4–§5.

### 4.2 Forward secrecy

`ikm` contains `DH(e_client, e_node)`; ephemeral private keys are destroyed right after derivation
(`take()`/`burn()`), and `ikm`, keys and IVs are `Zeroizing`. Long-term values (`nrxp_secret`,
the node's static key) alone do not open past sessions: **`nrxp_secret` is not part of `ikm`
at all** (only of the `ClientHello` tag), and the static DH is useless without the ephemeral one.

### 4.3 Node authentication

The second DH with the node's static key goes into `ikm` (v≥3). A middleman without the private key
gets **different keys** and is exposed by data failing to decrypt; the static key is **not
transmitted** over the wire (no stable identifier in the packet). The test
`mitm_without_the_node_private_key_derives_different_keys` gives the middleman even `nrxp_secret` —
and it still does not converge.

The client picks the scheme **itself**: with credentials it always computes the second DH, so a
middleman cannot make it fall back to the anonymous scheme (diverging keys yield a failure, not a
downgrade).

### 4.4 Entry: the `ClientHello` tag

HMAC-SHA256(`nrxp_secret`, label‖step‖salt‖client ephemeral key)[..16] (256 bits of secret at the
entry). Purposes: (a) filter out scanners without the secret without spending asymmetric crypto on
them; (b) bind the tag to a specific connection (an intercepted tag cannot be pasted into another
hello); (c) confirm the version and the cipher/route preferences (tampering with these bytes breaks
the tag). The window is ±2 steps of 60 s, checked in constant time over all 5 candidates.

**What the tag does not do:** the secret is shared by all of the node's clients and does not identify
a user; replays within the window are not tracked (§3 A3, §7.3).

### 4.5 Replay and ordering protection

* *Within a session (TCP leg)*: a per-direction nonce counter, not transmitted; a skip, duplicate or
  reordering breaks decryption immediately.
* *Datagrams*: a full 64-bit counter, only the low 16/32 bits on the wire with reconstruction, a
  sliding anti-replay window of 2048 (after a successful AEAD), a key ratchet.
* *New connection*: the tag window on `ClientHello` (see 4.4). Replaying a hello yields no keys but
  gives the adversary the node's response (A3).
* The per-frame `auth_tag` field in the data phase is **not verified** (§7.4) — protection is
  provided by AEAD + counter.

### 4.6 Constant time and memory hygiene

* Tag verification (`verify_tag`, `verify_handshake_tag`) always computes **all** window candidates,
  compares with `subtle::ConstantTimeEq`, accumulates the result via `Choice`, with no early exit and
  no secret-dependent branching. This is ensured by construction (`subtle` barriers); the tests check
  the *semantics* of the window but not timing — that requires `dudect`/`cachegrind` on the target
  architecture.
* Key material (`SessionKeys`, `NonceState`, ratchets, `Identity`, `ikm`) is wiped by `zeroize` on
  `Drop`. This protects against "a memory dump is taken now" (swap, core dump, VM snapshot); for a
  dump of a **live** process the keys of active sessions are in memory anyway.

### 4.7 Stealth fallback (protection from active probes)

Everything that fails the ClientHello check is transparently relayed to a decoy site (`relay` mode):
the already-read bytes first, then bidirectionally. The target is chosen by the SNI from the received
hello (if plausible) or `--decoy-host`. Protection of the relay itself:

* only public addresses (loopback, private, link-local, **metadata `169.254.169.254`**, multicast,
  unspecified, broadcast, documentation, ULA/link-local IPv6 are rejected);
* the **node's own addresses** are rejected (a "node → itself" loop used to eat memory in seconds —
  OOM on 2 GB);
* ≤ 512 concurrent bridges; closed after 60 s of inactivity; the port is always 443.

A side effect of `relay` mode (§7.5): the node relays **any** TLS probes to any public hosts on
port 443 — it is an "open" handshake relay.

### 4.8 Access control

* **Node managed by a control plane** (`--require-auth`): each client presents a Bearer token
  validated by an HTTP request (cache 60 s); limits and accounting via `usage`/`usage/batch`.
  A refusal is `Close auth_rejected:` + a fatal session on the client.
* **Standalone node** (no `--require-auth`): the token is ignored; access is determined only by
  possession of `nrxp_secret` and the node key (and, in non-strict mode, by nothing).
* **Mesh**: a peer confirms `peer_id`/`peer_secret` with the control plane; the route is bound to the
  authenticated path (the second-to-last node of `visited` must be the peer itself).

### 4.9 Mesh and strong privacy

* The route is built at the ingress and **wrapped in HPKE capsules** (X25519/HKDF-SHA256/
  ChaCha20-Poly1305, `info` bound to the recipient's `node_id`): each node knows only its predecessor
  and the next hop. A capsule lives 120 s, replay is rejected by the `replay_nonce` cache
  (≤ 262,144), size ≤ 12 KiB, loops and hop-budget violations are rejected.
* The transport between nodes is real QUIC; the peer's identity is established by the **inner** NRXP
  handshake, not by a TLS certificate (it is ephemeral and not verified).
* Strong privacy: onion route only, frame mixing in 20 ms windows, background `Cover` traffic.
  **Limitations:** the first node knows the client, the last one the destination; there is no
  protection against an adversary who sees both ends (A11). More — [MESH.md](MESH.md).

### 4.10 Other

* Resource limits before authentication: reading `ClientHello` ≤ 10 s; mesh QUIC ≤ 512 connections;
  a leg's read buffer ≤ 1 MiB; stream backlogs are bounded (4/16 MiB); stream credit prevents a fast
  sender from inflating a slow receiver's memory.
* The `/metrics` and `/health` endpoints are deliberately placed on **separate ports** (mixing them
  would give DPI readable HTTP).

---

## 5. Secrets and keys

| Secret | Who knows it | Purpose | A leak means | Storage / rotation |
|---|---|---|---|---|
| `PROXY_NRXP_PRIVATE_KEY` (32 B, hex) | **the node only** | static X25519 private key: node authentication | A7: node impersonation for clients; past sessions are not exposed | node env/secret store, not in logs; rotation = new pair + redistribution to clients |
| public static key | node, all of the node's clients | the client verifies the node | nothing (public) | printed by the node at startup (`nrxp_public_key`) — **compare** with what clients have |
| `PROXY_NRXP_SECRET` / `nrxp_secret` (32 B) | the node **and all its clients** | HMAC entry barrier | A8: probing; not MITM, not decryption | distributed to clients; rotation revokes access for **all** clients at once |
| `PROXY_NRXP_STRICT` | node flag | reject the anonymous scheme v2 | — | enable after keys are distributed |
| `PROXY_INTERNAL_SECRET` | the node **and the control plane** | node authorization to `/api/v1/internal/*` | access to token validation, reports, the mesh catalog | **separate for each node**; never given to clients; HTTPS only |
| user token (Bearer/JWT) | user, control plane | admits a client to a `--require-auth` node | access on the user's behalf | issued by the control plane; short TTL; revocation on the backend side |
| mesh `peer_secret` | control plane, peer node | admits a peer to an egress | A: ingress impersonation | from the catalog, not logged (`Debug` hides `nrxp_secret`) |
| `MASQUE_AUTH_SECRET` / `MASQUE_TOKEN` | node (+ control plane) / device | MASQUE relay authorization | — | per-node / per-device, revocable |

Rules:

* `PROXY_INTERNAL_SECRET` and `PROXY_NRXP_SECRET` are **different** secrets of different access
  levels; do not substitute one for the other.
* `PROXY_NRXP_SECRET` and `PROXY_NRXP_PRIVATE_KEY` are set **only together**: a node with half the
  configuration panics at startup on purpose.
* Pass secrets via environment variables, not command-line arguments (arguments are visible in `ps`).
  Client config files — `chmod 600`.
* Rotating `nrxp_secret`/keys: afterwards clients with the old values will not connect, and that is
  expected (otherwise rotation would revoke nothing). A strict-mode node logs
  `Unauthorized ClientHello: Auth Tag mismatch` for every such attempt.

---

## 6. Indistinguishability: what exists and what does not

A cipher does not make traffic indistinguishable: encrypted garbage looks like encrypted garbage.
Hence a separate layer. State by known detector:

| # | Detector | Type | Status |
|---|---|---|---|
| 0 | **SNI does not resolve to the node's IP** (`relay` mode: SNI = someone else's site) | boolean, 1 DNS query | ⚠ **open** (ops). Cured by your own domain on the node → `self-hosted` mode, which currently does not work (§7.6) |
| 1 | First `ApplicationData` from the client (real TLS 1.3 — from the server) | boolean | ✅ closed by the cover flight (4 records 41/2385/97/53 B) |
| 2 | Server's first flight is 133 B | threshold | ✅ closed (now 2729 B) |
| 3 | Chromium `ClientHello` inside the RFC 7685-forbidden range 256–511 | boolean | ✅ closed (Chrome 140 profile: ≈1.7 KB, no padding by construction) |
| 4 | Record-length invariant `len − 41 = 2ᵏ` | statistical | ✅ closed (irregular per-connection boundaries) |
| 5 | Maximum record 16425 (unreachable for a browser) | boolean | ✅ closed (16401) |
| 6 | Heartbeat period exactly 3 s; health-check probe exactly every 10 s | statistical | ✅ closed (jitter ±30 %, back-off ×1…8, probe dedup) |
| 7 | 4 connections from the start with an even step | weak | ✅ blurred (× U(0.6; 1.4)) |
| 8 | **A valid tag is computed without a secret** | active | ✅ closed on a **strict** node; ⚠ **open on a non-strict one** (the v2 tag is an HMAC under a zero key) |
| 9 | Record lengths congruent modulo a step | statistical | ✅ closed; the *set* of a connection's boundaries remains visible |
| 10 | **No real certificate / `Certificate` is just a record of the right size** | active (driving TLS to completion) | ⚠ **open**: the node will not present a chain |
| 11 | **A probe with `nrxp_secret`, or a replay of a foreign ClientHello** | active | ⚠ **open** (A3) |

What is **not** verified by a live capture `[?]`: the GREASE-ECH length (144), cover-flight sizes
relative to a real decoy site, Firefox/Safari fingerprints, the QUIC and RTP profiles, the ALPS
codepoint `0x44cd`. Any statement of the form "indistinguishable from Chrome" should be read as
"reproduced from the specification and one capture".

**Wording acceptable in public:** "masquerades as HTTPS; the browser fingerprint is reproduced; a
decoy site answers scanners". **Not acceptable:** "indistinguishable from HTTPS for DPI", "bypasses
any DPI", comparing stealth with REALITY (REALITY serves the real certificate of a real site, we do
not).

---

## 7. Known limitations and discrepancies with earlier descriptions

### 7.1 The node does not filter destinations (A5) — important for operators

The exit node performs `TcpStream::connect(target)` and a UDP "connect" to **any** `host:port` sent
by the client. There is no list of forbidden networks and no loopback/private check. Consequence:
any user of the node (and in standalone mode without `--require-auth` — **anyone who knows
`nrxp_secret`**) can reach the node's `127.0.0.1` (including `/health` and `/metrics`), the hosting
provider's private network and the **cloud metadata service** (`169.254.169.254`). An SSRF filter
exists only for the fallback bridge (§4.7) and for the MASQUE relay (`--allow-private-targets` is
off by default). Mitigations are in DEPLOYMENT.md §9: host firewall egress rules (DROP on RFC 1918,
link-local, loopback-from-container), a separate network zone for the node, and do not co-locate it
with anything you would mind losing.

### 7.2 Strict mode and scheme downgrade

Documentation used to say: "while a node is not in strict mode, an active middleman can rewrite the
version byte and steer the connection to the weak scheme". By the code this is **accurate for a
different scenario**:

* A client with credentials picks the scheme **itself** and always computes the second DH. If a
  middleman rewrites `session_id[0]` to 2 and recomputes the keyless tag, the server derives
  anonymous keys while the client derives authenticated ones: divergence → failure, not interception.
  **Downgrading a client with credentials is impossible.**
* The real harm of non-strict mode is different: the node accepts **anonymous clients** and answers
  "like a node" (`ServerHello` + cover flight) to **anyone** who computes a v2 tag — and it is
  computed without a secret. Hence a non-strict node (a) **can be classified by any probe without
  secrets** (detector 8), and (b) without `--require-auth` is an **open proxy for everyone**.

Practical rule: a node with credentials should run with `PROXY_NRXP_STRICT=true` as soon as clients
have received keys. Non-strict mode is only for the rollout period.

### 7.3 `ClientHello` replay and the entry barrier (A3)

The entry secret is shared among the node's clients, and there is no store of used tags. So the node
can be classified (a) by the owner of a client config, (b) by replaying a recorded `ClientHello`
within ≈ 2–3 minutes. This is not a cryptographic break but a boundary of the model "a barrier
against scanners, not against a censor with a client". Mitigations outside the code: rotating
`nrxp_secret`, per-user entry (see §12).

### 7.4 The per-frame "time-based" tag in the data phase

[ARCH.md](../../ARCH.md) §3 and [SECURITY.md](SECURITY.md) (the replay section) used to claim that
every unit carries a time-based HMAC that the receiver verifies, dropping records outside the
window. **In the code the receiver does not verify this field in the data phase**
(`RxCodec::decode_inbound` does not call `verify_tag`). This is not a hole: the field sits inside
the AEAD, and integrity, ordering and replay protection in the data phase are provided by the AEAD
and the nonce counter. But the time window applies **only to `ClientHello`**. The descriptions have
been corrected.

### 7.5 `relay` mode — an open relay of TLS probes

The fallback sends traffic to the host from the received SNI (public addresses, port 443). Anyone can
use the node as a "jump point" for TLS connections to an arbitrary public host: the node will see and
relay foreign bytes, and the destination's logs will show the node's IP. The limit is 512 bridges and
60 s of idleness. This is a deliberate trade-off of the REALITY-style mode (different SNIs get
different sites, as with a real proxy).

### 7.6 `self-hosted` mode: forwarding to the local site does not work

`--decoy-mode self-hosted` builds and publishes the storefront, but the fallback to
`--decoy-local-site` **does not work in the current build**: the target goes through the same SSRF
filter that forbids loopback, and is passed as a hostname with an extra `:port`. Verified by running
it: the probe got `Stealth fallback: no safe target address available, dropping connection`, and a
local listener on `127.0.0.1` saw no connection. Until this is fixed, the only working mode is
`relay`, and detector #0 stays open.

### 7.7 The default cipher is AES-128-GCM

The old descriptions ("ChaCha20-Poly1305") hold for v<4, wasm-edge and an explicit choice. Current
clients with `auto` get `1301` (AES-128-GCM). Both ciphers are standard AEADs with a 128-bit tag;
AES-GCM uses hardware acceleration.

### 7.8 Other

* **Time.** The `ClientHello` tag depends on the clock: a device off by more than ±2 minutes will not
  connect (a visible failure, not a silent degradation).
* **No certificate pinning in mesh QUIC** — deliberate: identity comes from the inner NRXP
  (by the code, if the inner handshake fails on the mesh port, the mesh session is not accepted and
  no fallback to the decoy is started there).
* **The datagram ratchet** gives backward protection (compromise of epoch N does not open N−1), but
  not post-compromise security.
* **`auth_key`** is derived but effectively unused in the data phase (§7.4).
* **Nodes without credentials** accept only v2 — there is no node authentication at all.
* **Old log lines** such as `Unauthorized ClientHello` are a normal part of a node's life on the
  internet; not a cause for alarm by themselves.

---

## 8. User data privacy

* The node **does not write a connection log to disk**: the JSON log goes to stdout, and client
  diagnostic frames are drained "into nothing" (`in-memory only`). Destination hosts are not logged
  (a `stream_id` is used for correlation); the SNI of probes is not logged either.
* What goes to the control plane: `user_id` ⇄ **byte volume** (accounting and limits), token
  validation, anonymous node telemetry (session/leg/stream/MB/error counters, uptime — **without**
  user_id, IP or destinations).
* DNS names are resolved by the **exit node** (no leak on the client side), but the node operator
  sees the requested names in `Connect`.
* Prometheus metrics contain no user_id, destinations or client addresses; they reveal volume and
  connection counts (`/metrics` listens on `0.0.0.0` — close it with a firewall).
* The hosting provider and the node's network see netflow (who connects to the node and how much),
  but not content.

---

## 9. Attack surface and resilience

| Surface | What it accepts unauthenticated | Protection |
|---|---|---|
| Tunnel TCP port | any bytes | parsing ≤ 10 s; HMAC×5 before crypto; fallback ≤ 512, 60 s; **no** global limit on concurrent TCP connections (bounded by `ulimit`) — firewall rules/`connlimit` needed |
| UDP port (same number) | any datagrams | lookup by `leg_token`; AEAD before any action; a failed probe has no side effects |
| mesh QUIC (`8443/udp`) | QUIC handshake | ≤ 512 connections, 256 KiB buffer; non-mesh rejected |
| `/health` | any HTTP | listens on `127.0.0.1` only |
| `/metrics` | any HTTP | listens on `0.0.0.0` → **close with a firewall to the collector's IP** |
| node's control-plane client | — (outbound) | circuit breaker 5/10 s; validation cache 60 s |

Failures: a control-plane outage does **not** tear down already established sessions (validation is
cached, traffic reports are retried in batches), but new clients in `--require-auth` mode will be
refused while the breaker is open.

---

## 10. Node operator requirements

Minimum for a node on a network where users are not trusted:

1. `PROXY_NRXP_SECRET` + `PROXY_NRXP_PRIVATE_KEY` are set; **`PROXY_NRXP_STRICT=true`**.
2. **Host egress firewall** blocks the node process from the machine's own loopback, RFC 1918,
   link-local (`169.254.0.0/16`, `fe80::/10`), ULA, cloud metadata.
3. `/metrics` is firewalled (or not enabled); `/health` on loopback only.
4. `--require-auth` (+ HTTPS `--backend-url`) if the control plane should identify users; otherwise
   knowingly accept that access is determined by `nrxp_secret`.
5. Secrets via environment variables/a secret store, not on the command line and not in logs.
6. Resource limits (`LimitNOFILE`, `connlimit`/SYN rate-limit rules).
7. Your own domain on the node — once `self-hosted` mode works (detector #0).
8. Clocks synchronized (NTP) on the node and on clients.
9. Updates: rebuild the image when dependencies update (`cargo audit`); `Cargo.lock` is pinned.

Full checklist and commands — [DEPLOYMENT.md](DEPLOYMENT.md) §9.

---

## 11. Reporting a vulnerability

Do not open a public issue with details. Use **GitHub → Security → Report a vulnerability**
(a private security advisory) of this repository. Include the version (`git rev-parse HEAD`),
reproduction steps and the affected component (`core/`, `server/`, `client/`, `masque-edge/`…).

---

## 12. Possible improvements (for developers)

In order of payoff:

1. Fix the `self-hosted` fallback (§7.6) and move to your own domain on the node → closes detector #0
   and removes the open TLS relay (§7.5).
2. A destination filter on the exit node by default (§7.1) with an opt-out.
3. A store of used `ClientHello` tags (Bloom/LRU over the window) → closes replays (A3); per-user/
   per-device entry instead of a shared `nrxp_secret`.
4. A real certificate in the response to a valid but unauthenticated prober (i.e. real TLS for
   non-clients) — detector #10.
5. Calibrating the cover flight and profiles against a live capture `[?]`.
6. Instrumented constant-time verification of tags (`dudect`) in CI.
