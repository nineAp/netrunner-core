# Mesh and onion routing

🇷🇺 [Русская версия](../MESH.md)

How several Netrunner nodes join into a network, how multi-hop routes with encrypted instructions
("onion") are built, what this protects against, what it enables, and where the mechanism has
**honest limits**. The byte formats of capsules and claims are in
[PROTOCOL.md §8](PROTOCOL.md#8-mesh-routing-between-nodes); deployment —
[DEPLOYMENT.md §11](DEPLOYMENT.md#11-control-plane-mesh-masque-edge); the general threat model —
[SECURITY_MODEL.md](SECURITY_MODEL.md).

> Described from the code in `core/src/net/{mesh,mesh_onion,mesh_quic,auth}.rs` and
> `core/src/net/connection/handler.rs`. Behavior was checked by reading the code and by tests
> (`cargo test -p netrunner-core --features mesh-quic --lib mesh`); no separate multi-node test bed
> was brought up while writing this document.

## Contents

1. [The idea in one paragraph](#1-the-idea-in-one-paragraph)
2. [Roles and what each node knows](#2-roles-and-what-each-node-knows)
3. [Route modes](#3-route-modes)
4. [How a route is built and lives](#4-how-a-route-is-built-and-lives)
5. [Onion capsules](#5-onion-capsules)
6. [Transport between nodes](#6-transport-between-nodes)
7. [Strong privacy](#7-strong-privacy)
8. [What it protects against](#8-what-it-protects-against)
9. [What it lets you do](#9-what-it-lets-you-do)
10. [Comparison](#10-comparison)
11. [Limitations — must read](#11-limitations--must-read)
12. [Enabling and operating](#12-enabling-and-operating)
13. [x-hop: route entropy under the TCP wrapper](#13-x-hop-route-entropy-under-the-tcp-wrapper)
14. [Decentralization: what exists and how to get there](#14-decentralization-what-exists-and-how-to-get-there)
15. [Exit randomization and traffic interception](#15-exit-randomization-and-traffic-interception)

---

## 1. The idea in one paragraph

The client still talks to **one** node (the ingress) over ordinary NRXP. But instead of exiting to
the internet from its own IP, the ingress carries each stream through a chain of other nodes of the
network and releases it to the internet from the IP of **another** node (the egress). The chain is
chosen per stream, and the "where next" instructions are packed into **HPKE capsules** addressed to
each node separately: an intermediate node decrypts only its own layer and knows neither the whole
path nor the final destination. The client side does not change — mesh is transparent to the client,
which may only state a desired path length.

```text
client ══NRXP══▶ INGRESS ══NRXP/QUIC══▶ RELAY ══NRXP/QUIC══▶ EGRESS ──TCP/UDP──▶ destination
                  knows: client,         knows: previous       knows: destination,
                  destination, whole     and next node         previous node
                  route                  (not client, not      (not the client)
                                         destination)
```

## 2. Roles and what each node knows

Any node of the network can be an ingress, a relay and an egress (`--mesh-enabled`).

| Node | Knows client IP | Knows destination (`host:port`) | Knows whole route | Sees stream plaintext |
|---|:-:|:-:|:-:|:-:|
| **Ingress** (accepted the client) | ✅ | ✅ (the client sends it in `Connect`) | ✅ (builds it itself) | ✅ |
| **Relay** (intermediate) | ❌ (sees the IP of the previous *node*) | ❌ | ❌ (only previous and next) | ✅ if the stream is not under its own TLS |
| **Egress** (exit) | ❌ (sees the previous *node*) | ✅ | ❌ | ✅ if the stream is not under its own TLS |
| **Destination** (site) | ❌ | — | ❌ | sees the **egress** IP |

The key point: **the egress and relays do not know who the client is**, a relay does not know where
the traffic goes, and the destination sees not the node the client connected to. But the **ingress
knows everything** — mesh does not remove trust in the first node (see §11).

## 3. Route modes

A node sets the upper bound `--mesh-max-hops` (1…8, default 2) — a **hard ceiling**. A client may
request a policy no higher than the ceiling (a field in `ClientHello`, confirmed by the tag,
[PROTOCOL.md §8.2](PROTOCOL.md#82-client-route-policy)); client config/flag:

| Client policy | Value | Result |
|---|---|---|
| (not set) | node policy | the node's policy |
| `direct` | 1 | no mesh: exit from the ingress itself. If the outbound connection fails, the ingress may reuse a backup egress chain (`build_direct_onion_fallback`) |
| `two-hop` | 2 | ingress → one egress (RTT-weighted rotation among healthy nodes) |
| `x-hop-N`, N∈3…8 | 3…8 | a **random** path length per stream in `[3, min(N, available nodes+1)]`, the egress is chosen in advance |
| strong privacy | see §7 | onion route only + mixing + background cover traffic |

If there are not enough healthy nodes for the requested length, the length is **reduced** (down to a
two-node route); a larger `N` is a maximum, not a minimum.

## 4. How a route is built and lives

**Node catalog.** Every 20 s a node asks the control plane for the peer list
(`GET /api/v1/internal/mesh/peers`: `node_id`, address, SNI, `nrxp_secret`, public key) and measures
the RTT to each (TCP probe, 8 s timeout; a result is "fresh" for 90 s; a node that fails to answer
3 times drops out of selection).

**For each application stream** (ingress, `build_onion_route`):

1. Candidates exclude the ingress; nodes with a fresh RTT take priority.
2. The path **length**: for a ceiling > 2 — random in `[3, max]`, otherwise 2.
3. **Relay nodes** and the **egress** are chosen by weighted random selection (weight decreases with
   RTT); the egress is additionally rotated through a "bag": each unique address is used once per
   cycle before the bag is reshuffled, and is never repeated back to back — exit IPs alternate.
4. A **chain of backup egresses** (up to 7) is built from the remaining nodes — also in capsules.
5. Capsules are sealed **from the end to the start**: first `Exit` for the last node, then `Forward`
   for each previous one (§5). A capsule's lifetime is 60 s (a node accepts ≤ 120 s).
6. The ingress opens a stream to the first node, connecting to it as a mesh peer
   (`mesh4:<id>:<secret>`), and sends the first capsule in a `MeshOnionConnect` frame.
7. Each node opens its step, forwards the next capsule and confirms readiness with the
   `NRXP-MESH-ONION1-READY` marker; the egress connects to the destination (up to 7 s per attempt)
   and confirms.

**The route lives** exactly as long as the stream: the path is **pinned to the stream** and is not
rebuilt on the fly (otherwise it would have to be silently shortened, exposing a node).

**Failure handling during setup** (before connecting to the destination):

* the first node did not answer/refused → other first nodes are tried (up to `min(peer count, 8)`
  attempts), with an overall setup deadline of **65 s**;
* the egress could not connect to the destination → the next **backup egress** from the embedded
  chain; chain exhausted → an explicit `NRXP-MESH-EGRESS-EXHAUSTED` signal (no silent start of a new
  route);
* duplicates and loops are rejected; metrics `netrunner_mesh_*`.

**Data-path protection:** between nodes, credit flow control runs **per segment** (`RelayCredit`):
a relay gives the previous hop a window and refills it as data moves on — a slow client does not
inflate a relay's memory but limits the egress's speed. There is no credit for UDP.

## 5. Onion capsules

A capsule is HPKE Base (RFC 9180; X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20-Poly1305), addressed
to the recipient node's static public key; `info` includes the recipient's `node_id` — an intercepted
capsule cannot be "replayed" to another node name. Inside is a route step:

* **Forward**: the next node's data (address, SNI, `nrxp_secret`, public key — needed to connect to
  it) + an **opaque** capsule for it. The current node cannot read it.
* **Exit**: the stream's destination and an optional backup egress with its capsule.

Capsule protection: a lifetime and a **replay cache** by `replay_nonce` (up to 262,144 entries per
node; overflow → refusal); size ≤ 12 KiB; a hop-budget consistency check (Forward only with ≥ 2
remaining, Exit with 1); the UDP/TCP flag must match the frame type. Any error → the stream is
closed, counter `netrunner_mesh_onion_capsule_rejections_total`.

> What does **not** happen: the stream data is **not** wrapped in layers of encryption per hop, as in
> Tor. Onion layers protect the *route instructions*. Data travels in each segment under its own NRXP
> session and is decrypted and re-encrypted at the nodes (§11).

## 6. Transport between nodes

* Node ⇄ node — **real QUIC** (`quinn`, ALPN `nrxp-mesh/1`, UDP `--mesh-quic-port`, default 8443)
  with a TCP fallback; on top of it, the same NRXP handshake with authentication by the recipient's
  static key ([PROTOCOL.md §3–§4](PROTOCOL.md)). The QUIC certificate is ephemeral and **not
  verified**: the peer's identity is established only by the inner NRXP handshake, without which a
  mesh session is not accepted.
* The client reaches the ingress over ordinary NRXP (TCP/UDP leg) — the mesh port is logically
  closed to clients: a non-mesh claim is rejected on it.
* Peer admission: `peer_secret` is verified with the control plane (cached), and the route is bound
  to the authenticated path (the second-to-last element of `visited` is the peer itself).
* Peer sessions are pooled (≤ 256, idle 300 s): the handshake is done once, but each stream stays on
  its own route. Datagrams (UDP) use QUIC DATAGRAM.
* Before authentication, limits apply: ≤ 512 connections on the mesh port, bounded buffers.

## 7. Strong privacy

Enabled by the client (`--strong-privacy` / `NETRUNNER_STRONG_PRIVACY=1` /
`set_strong_privacy(true)`); the client sends `SecureConnect`/`SecureUdpConnect`. What changes:

* a stream is accepted **only** over an onion route — no direct exit and no silent "simplification"
  of the route (if there is no route, the stream is rejected);
* on every node of the path, packets of different streams are **mixed in 20 ms windows** (up to 512
  packets per window): order within a stream is preserved, and streams interleave with each other;
* while a session has active streams, background `Cover` traffic runs on `stream_id = 0` on both
  sides of each segment (interval 0.9–2.4 s, 128–384 random bytes);
* the flag is carried in every capsule, so the mode is not "lost" at intermediate nodes.

The price is latency (up to the mixing window at every hop plus the path length) and idle traffic.

## 8. What it protects against

| Threat | How mesh helps | How much |
|---|---|---|
| **The destination/site sees your node** (blocks or bans the node IP) | the exit IP is one of **many** nodes, alternating between streams | strongly: blocking one IP does not take the network down |
| **A censor blocking the egress node on the destination side** | the backup-egress chain takes over when the connection to the destination fails | strongly |
| **A relay/egress operator or intruder wants to learn who the client is** | they do not see the client IP — only the neighbouring node | strongly for relay/egress |
| **A relay operator wants to know where traffic goes** | the destination is only in the `Exit` capsule for the egress | medium: see §11 on plaintext |
| **Single node compromise** | one node knows no more than its own step (except the ingress) | medium |
| **"Client ↔ destination" correlation at a single node** | the client and destination are split across different nodes (except the ingress) | medium |
| **Replay/substitution of an intercepted capsule** | lifetime, `replay_nonce`, `info` with `node_id`, HPKE authentication | strongly |
| **Route forgery/loops/exceeding the hop budget** | claim and capsule validation, binding to the authenticated path | strongly |
| **Substituting a node in the chain** | each link is an NRXP handshake with the recipient's static key | strongly |
| **Overload/failure of one node** | egress pool, RTT-weighted selection, backup chain | strongly |
| **Simple timing correlation of streams inside a node** (strong privacy) | 20 ms mixing + cover traffic | weak–medium |

## 9. What it lets you do

* **Rotate exit IPs.** Each stream may exit from a different node; the "bag" guarantees even
  alternation of addresses rather than sticking to one.
* **Choose geography and quality.** Exit closer to the destination, entry closer to the client; nodes
  with a better RTT are chosen more often.
* **Scale and survive failures.** The entry point is not tied to the exit point; losing an egress
  before connecting to the destination does not tear the stream down, thanks to the backup chain.
* **Split knowledge.** A relay operator knows neither client nor destination; an egress operator does
  not know the client (but knows the destination). Useful when nodes are at different hosting
  providers/jurisdictions.
* **Hide the entry from destinations.** Blocking/reputation-banning the exit IP does not affect the IP
  the client connects to.
* **Manage the latency/privacy trade-off** — a ceiling on the node, a policy on the client
  (`direct` / `two-hop` / `x-hop-N`), strong privacy for sensitive scenarios.
* **Use the same for UDP** (DNS, games, calls): route and failover also work for `UdpConnect`
  (UDP has no credit window).
* **Plug in your own control plane**: the peer catalog and validation are six HTTP endpoints
  ([PROTOCOL.md §9](PROTOCOL.md#9-control-plane-http-contract)).

## 10. Comparison

| | Single node | Mesh `two-hop` | Mesh `x-hop` / strong | Tor |
|---|---|---|---|---|
| Exit IP ≠ the IP the client connected to | ❌ | ✅ | ✅ | ✅ |
| Relay/egress do not know the client | — | ✅ | ✅ | ✅ |
| Ingress knows the client **and** destination | ✅ | ✅ | ✅ | ❌ (the guard knows the client, not the destination) |
| Per-hop layers of data encryption | — | ❌ | ❌ | ✅ |
| Network of nodes under one control | — | yes | yes | no (public relays) |
| Latency | minimal | +1 segment | +N segments (+20 ms window) | high |
| Purpose | speed, simplicity | exit rotation, resilience | knowledge splitting | anonymity |

Mesh is **trust distribution and exit resilience inside one operator's network**, not a replacement
for Tor.

## 11. Limitations — must read

1. **The ingress knows the client and the destination.** The destination reaches it in plaintext
   inside NRXP, and it builds the capsules itself. The entire gain is that the *other* nodes do not
   know this. The ingress operator, and an attacker who takes it over, see everything.
2. **Data is not wrapped in per-hop layers.** A relay and an egress see the stream plaintext if it is
   not protected by its own TLS (and TLS metadata — SNI, sizes — is always visible). A relay does not
   know the destination from the capsule but may guess it from SNI/IP addresses in the traffic.
3. **All nodes are usually under one operator.** If one owner controls both the ingress and the
   egress, there is essentially no knowledge splitting. A heterogeneous set of hosting
   providers/jurisdictions gives the effect.
4. **No protection from a global observer.** An observer who sees the ingress input and the egress
   output correlates by time/volume. Mixing (20 ms) and cover traffic (≈ 1 packet per 1–2 s) are a
   measure against simple statistics, not against serious correlation. Packet sizes are normalized
   only by record padding on each segment.
5. **The root of trust is the control plane.** It supplies the peer catalog, their keys, and
   validates `peer_secret`. A compromised catalog lets foreign nodes be slipped into a route. Without
   a control plane mesh **does not work** (there is no standalone mode — the catalog comes only from
   the HTTP contract).
6. **A capsule reveals the next peer's data to the next node** (`nrxp_secret` and the key are needed
   to connect). A leak from a relay reveals the neighbour's entry barrier, not its private key.
7. **Path length is limited** (≤ 8) and shrinks if there are few nodes; in a two-node network there
   is no "multi-hop" route.
8. **The path is pinned to the stream.** A long-lived stream does not change its route until it closes.
9. **End-to-end privacy does not inherit the camouflage.** The mesh QUIC port is not a browser
   imitation: to an observer between nodes it is QUIC with ALPN `nrxp-mesh/1` (not disguised as
   HTTP/3). Firewall the mesh port from everyone except node addresses where possible.
10. **Latency and load.** Each hop is a separate session and re-encryption; strong privacy adds a
    mixing window and idle traffic.
11. **`direct` mode** keeps a backup exit through mesh only when the connection to the destination
    fails; otherwise it is an ordinary single node.

## 12. Enabling and operating

**Node** (each in the network): NRXP credentials (`PROXY_NRXP_SECRET`/`PRIVATE_KEY`),
`PROXY_INTERNAL_SECRET`, `PROXY_NODE_ID`, a `--require-auth`-compatible backend:

```bash
./netrunner-server --port 443 --decoy-host www.debian.org \
  --mesh-enabled --mesh-max-hops 3 --mesh-quic-port 8443 \
  --backend-url https://control.example.com --health-port 9091
```

Open `udp/8443` (or your own port) **between nodes**. Mesh does not start on a node without NRXP
credentials (a panic by design).

**Client:** `--strong-privacy` (headless), or a route policy `direct`/`two-hop`/`x-hop-N` in the app;
without configuration the node's policy applies.

**Diagnostics** (`/metrics`):

| Metric | What it says |
|---|---|
| `netrunner_mesh_peers_available` | how many peers are in the catalog |
| `netrunner_mesh_peer_rtt_ms` | RTT to peers |
| `netrunner_mesh_selected_route_hops`, `…_route_setup_seconds` | actual lengths and setup time |
| `netrunner_mesh_onion_streams_total` / `…_setup_seconds` | onion streams |
| `netrunner_mesh_onion_{capsule,protocol,loop}_rejections_total` | rejected capsules (replay/expired/loop) |
| `netrunner_mesh_onion_{route,forward}_failures_total` | first-/subsequent-hop failures |
| `netrunner_mesh_egress_{failover_attempts,failover_exhausted,connect_failures}_total` | backup-egress activity |
| `netrunner_mesh_quic_{sessions_*,handshake_failures,fallback,admission_rejected}_total` | state of QUIC between nodes |
| `netrunner_mix_batch_{packets,flows}`, `netrunner_mix_packet_drops_total` | mixing (strong privacy) |

Common problems: no peers in the catalog → check `--backend-url`, `PROXY_INTERNAL_SECRET`, the
circuit breaker; `capsule_rejections` growing → clock skew (a capsule lives ≤ 120 s);
`egress_failover_exhausted` → the destination is unreachable from all egresses or there are too few
nodes; `quic_fallback` growing → `udp/8443` is closed between nodes (works over TCP, slower).

---

## 13. x-hop: route entropy under the TCP wrapper

From the outside the client sees **one** ordinary TLS-like TCP connection to the ingress (really up
to 4 legs, [PROTOCOL.md §6](PROTOCOL.md#6-multiplexing-and-sessions)). Everything that happens next
is hidden under this "wrapper", and `x-hop-N` mode makes that internal structure
**unpredictable**:

* **The path length is random** per stream: uniform in `[3, min(N, available nodes + 1)]`.
* **The path composition is random**: relay nodes and the egress are taken by weighted random
  selection (weight decreases with RTT), and the egress is additionally rotated through a "bag"
  without back-to-back repeats.
* **Different streams of one client take different routes** and exit from different IPs, even though
  the client side sees them as a multiplex in one connection.
* **Each segment is re-encrypted**: each link has its own keys, its own nonces and its own random
  length-padding grid ([PROTOCOL.md §5.3](PROTOCOL.md#53-length-padding-padshaper)). The encrypted
  stream at a node's input and output cannot be matched byte by byte — only time and volume remain.

**How much this gives — an upper-bound estimate.** For a network of 10 nodes (the ingress + 9 peers)
and `x-hop-5`: a path length of 3, 4 or 5 equally likely, then an ordered choice of 2, 3 or 4 peers
out of 9:

```text
length-3 paths: 9·8       =   72  (≈ 6.2 bits)
length-4 paths: 9·8·7     =  504  (≈ 9.0 bits)
length-5 paths: 9·8·7·6   = 3024  (≈ 11.6 bits)
total ≈ log2(3) + mean(6.2; 9.0; 11.6) ≈ 10.5 bits of route per stream
(for two-hop — only 9 options ≈ 3.2 bits)
```

This is the entropy of the **route choice**, not "randomness of the traffic": the ciphertext on each
segment is already indistinguishable from random bytes, but the *shape* of the flow (volumes,
timings) is preserved. The real numbers are lower: RTT weights make the choice non-uniform, and nodes
without a fresh probe are excluded from the catalog. Entropy grows with the number of nodes and the
ceiling `N`; the price is latency and load.

## 14. Decentralization: what exists and how to get there

**What is confirmed.** A network of nodes with no single entry point has worked on the
netrunner-vpn.com project: nodes build routes through each other themselves, any node can be an
ingress, a relay or an egress, and the exit is not tied to the entry. In this repository such a mode
is exercised by the mesh tests (`cargo test -p netrunner-core --features mesh-quic --lib mesh`,
25 tests) and described in §4–§6.

**What is centralized today (test mode).** Routing is decentralized, but nodes **get information
about each other from the control panel**: the peer catalog (address, SNI, `nrxp_secret`, public
key) — `GET /api/v1/internal/mesh/peers`, and peer admission —
`POST /api/v1/internal/mesh/validate` ([PROTOCOL.md §9](PROTOCOL.md#9-control-plane-http-contract)).
The implementation is the `AuthValidator` trait (`list_mesh_peers`, `validate_mesh_peer`); there is
no standalone implementation in the repository. So the panel is a single point of failure and the
**root of trust** (§11 item 5): a panel outage does not tear down live streams (the catalog is in the
node's memory and refreshes every 20 s), but new peers do not appear and admission is not refreshed.

**How it could be made decentralized (a proposal, not implemented).** The idea is to embed address
data in the protocol so nodes learn about each other themselves (peer exchange):

1. **Peer exchange inside an already authenticated mesh session.** Nodes already hold NRXP sessions
   with each other with mutual verification. Add a control frame/marker (behind a version flag, like
   `MIN_VERSION_FOR_*`, so old nodes do not drop a leg on an unknown type) carrying
   `MeshPeer { node_id, host, port, decoy_sni, nrxp_secret, nrxp_static_public }` records. A node
   receives such records from neighbours and extends its catalog.
2. **Bootstrap.** A static list of seed nodes in the config; after that the catalog grows by
   exchange (gossip), without contacting the panel.
3. **Trust in records instead of the panel.** A replacement is needed for "the panel confirms the
   peer":
   * signatures on records by the network operator's key (a federation) — a node accepts only records
     signed by a key it knows; or
   * an allowlist of nodes' public static keys (the key is already a node's identity in the
     handshake); or
   * vouching: a record is accepted if ≥ K known nodes signed it.
4. **Peer admission** (`peer_secret`): replace the HTTP validation with a check against an
   allowlist/a signed membership certificate; a network-wide shared secret is only a temporary measure.
5. **Protection against catalog poisoning:** limits on size/growth rate, record TTLs, a reachability
   and RTT probe before use (the probe already exists, §4), priority for records confirmed by
   several neighbours.

What would need to change in the code: a new catalog source instead of `BackendClient` (an
`AuthValidator` implementation without HTTP), a new frame type gated by version, record storage and
eviction, signatures. The transport, capsules, route selection, failover and credit flow control
stay as they are.

**Decentralization risks to be closed:** Sybil (an attacker brings up many "nodes" and becomes a
frequent relay/egress), poisoning the catalog with foreign addresses, leaking the network topology
to anyone who joined, and revoking a compromised node (without a panel a revocation mechanism is
needed — for example a signed list of revoked keys).

## 15. Exit randomization and traffic interception

Exit randomization makes **intercepting** a user's traffic harder, because there is no single place
through which all of it passes:

* a client's streams are **spread across different egresses** and different paths; an observer at one
  exit sees only a share of the streams and does not know which of them belong to the same client;
* the egress and relays do not know the client IP (§2), the exit IP alternates — one cannot match
  "this exit = this user" by IP;
* on each segment the traffic is re-encrypted, so a node's input and output cannot be linked
  byte-for-byte;
* the path is unpredictable in advance (~10 bits per stream for 10 nodes and `x-hop-5`, §13), and the
  path length is hidden from every node.

A rough estimate for an attacker controlling a share `f` of the exit nodes: they see about a share
`f` of the streams **without attribution to a user**. To link a stream to a client, both the entry
(ingress) and the exit are needed at once, i.e. on the order of `f_in · f_out`, or timing
correlation between the observed ends. "Purely theoretically quite hard" is the right wording: this
is a **complication**, not a guarantee.

What randomization does **not** close (see §11): the ingress knows the client and the destination; a
relay and an egress see plaintext if the stream is not under its own TLS; a global observer
correlates by time and volume; all nodes under one operator give little knowledge splitting; and
choosing from a small number of nodes gives little entropy. In practice the effect grows with the
number of **heterogeneous** nodes (different hosting providers and jurisdictions) and the ceiling
`N`, and for sensitive scenarios — with strong privacy (§7).
