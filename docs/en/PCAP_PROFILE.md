# Browser profiles: record, JSON, load

🇷🇺 [Русская версия](../PCAP_PROFILE.md)

The engine builds its `ClientHello` from a **browser profile** — a "recipe" for the fingerprint
(ciphers, groups, signatures, extension order…). A profile is data: a JSON file. You can **extract it
from a real browser with one command**, edit it by hand or write it from scratch, and the client picks
it up at startup. No rebuild.

One recording run gives **three things** in a single file:

| What | Where it is applied |
|---|---|
| TLS profile (`ClientHello` over TCP) | the client's TCP legs |
| `quic` — the QUIC Initial (`ClientHello`, transport parameters, packet layout) | the client's UDP leg |
| `shape` — the browser's TLS record lengths | record-length padding on the client and the node |

Separately, for the node, a `cover-flight` is recorded — the record lengths of your own domain's reply.

```text
 browser ──traffic──▶ netrunner-client profile record ──▶ profile.json ──▶ netrunner-client --browser-profile profile.json
                      (AF_PACKET, no tcpdump)       (pcap parsing, JA3/JA4,        (the engine builds ClientHello from JSON)
                                                     building, self-check)
```

## Quick start

```bash
# 0. once: permission for a raw socket (or run through sudo)
sudo setcap cap_net_raw+ep ./netrunner-client

# 1. TURN THE VPN OFF, start recording and browse 3–5 different sites
#    (do not disable QUIC: Chrome will use both TCP and UDP/443 on its own)
./netrunner-client profile record --out chrome.json
#    stops by itself: 12 connections of one fingerprint collected (and, if QUIC appeared, 4 of its
#    connections), or on the timer (120 s) or Ctrl+C

# 2. check (optional: record already validates)
./netrunner-client profile check chrome.json

# 3. run the client with this profile
./netrunner-client --config client.toml --browser-profile chrome.json
```

`browser_profile = "chrome.json"` can also go into `client.toml`, or use the `NETRUNNER_BROWSER_PROFILE`
variable. A file may hold one profile or an **array** of profiles — then each session takes one of them
by a hash of its `session_id` (the fingerprint is stable for the whole session). Without the flag the
built-in profile is used.

Ready profiles: [`profiles/chrome_148.json`](../../profiles/chrome_148.json) (extracted from a real
Chrome 148) and [`profiles/minimal_example.json`](../../profiles/minimal_example.json) (hand-written — a
template for your own).

### Commands

| Command | What it does |
|---|---|
| `profile record --out F` | records traffic, builds the profile, checks it with the engine, writes JSON. Flags: `--iface` (all by default), `--port` (443; repeatable), `--seconds` (120), `--stop-after` (0 — Ctrl+C/timer only; N — stop after N connections of one fingerprint), `--save-pcap F`, `--name`, `--sni`, `--client`, `--ja4`, `--all`, `--min-hellos`, `--quic-ja4`, `--no-quic`, `--flight-sni`, `--flight-out` |
| `profile build CAP… --out F` | the same from ready `.pcap`/`.pcapng` files (Wireshark, `tcpdump`, Windows/macOS). Several files are analysed as one — e.g. a run with QUIC and a run with `--disable-quic` |
| `profile merge A B… --out F` | merges profile files into one pool (duplicates by JA4 are dropped, names are made unique) |
| `profile check F` | validates the JSON (whether the profile fits our protocol, including the `quic` and `shape` blocks) and prints warnings |

Selection flags: `--sni` (substring), `--client` (IP), `--ja4`/`--quic-ja4` (a specific fingerprint
group). `--all` extracts **every** fingerprint in the capture (Chrome + Firefox…) and writes an array;
`--min-hellos` (default 2) drops lone stray clients such as `curl`.

Recording shows progress (TCP connections, `ClientHello`s, QUIC, fingerprints), and at the end a
summary: JA4, extension shuffling, the observed ECH lengths, the QUIC Initial layout, the self-check
result and notes on what the engine does not reproduce.

> To determine **extension shuffling** and the spread of ECH lengths several connections are needed:
> Chromium changes the order on each one. Record without the VPN: otherwise the capture would hold our
> own tunnel. To get the QUIC block you need sites with HTTP/3 (google.com, youtube.com, cloudflare.com).

### Self-check

A profile that passed `validate` is merely **applicable** to the protocol. So after building, `record`/
`build` do what the engine does: they assemble 24 `ClientHello`s (and QUIC Initials) from the profile,
parse them with the same parser as the capture, and compare with the browser: JA4, extension set, the
presence of shuffling, ECH lengths, datagram sizes, transport-parameter order. A mismatch is printed as
`✘` and the command exits with an error (the file is still written — you can inspect it).

### Privacy

The JSON profile **does not contain** site names or IP addresses from the capture (`meta` used to hold
the SNI — removed, pinned by a test). The raw capture (`--save-pcap`) does hold the IPs and SNI of
everything the browser opened: do not publish or forward it.

## What is recorded for the node

### Cover flight: your domain's reply

The node answers "foreign" `ClientHello`s with records whose lengths must match the real reply of the
node's site (`EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`). Record them **from
your own domain**:

```bash
# on the machine with the browser: open https://your.domain/ a few times in fresh tabs
./netrunner-client profile record --out chrome.json --flight-sni your.domain --flight-out flight.json
# on the node:
netrunner-server … --cover-flight /etc/netrunner/flight.json     # or as a list: --cover-flight 27,4342,537,69
```

Only full TLS 1.3 handshakes are used (resumed sessions and TLS 1.2 do not show the `Certificate`); the
most frequent set of lengths is taken, and a warning is printed if the sets differ (a load balancer).
Without the flag the typical Let's Encrypt chain is used. Variable: `NETRUNNER_COVER_FLIGHT`.

> A record shorter than 41 bytes is raised to 41: a cover record cannot be shorter than its frame
> header. Real servers often have a 23–30 byte `EncryptedExtensions`, so the first record stays
> slightly longer than the real one — the command warns about it.

### Traffic shape

The length of a TLS record is visible to an observer. The `shape` block holds the distribution of the
browser's record lengths (up to 256 quantiles per direction). The client uses `up`, the node uses
`down`: the padding quantisation boundaries are drawn from the observed lengths (still at most 640 B
of padding per record — channel efficiency does not change). The node can use the same JSON:

```bash
netrunner-server … --shape-profile /etc/netrunner/chrome.json     # NETRUNNER_SHAPE_PROFILE
```

At least 8 values per direction are needed; fewer — the shape is not applied for it (recording
warns). Only record lengths per direction are taken into account; the timing pattern and a specific
site are not reproduced.

## JSON format (schema 1)

Numbers — a number or the string `"0x1301"`; extensions — a number, `"0x…"` or a **name**. Unknown
fields are rejected (a typo will not pass silently).

| Field | Req. | Meaning |
|---|:-:|---|
| `schema` | — | format version, currently `1` |
| `name` | yes | name (1–64 chars) |
| `record_layer_version` | yes | version in the TLS record header carrying `ClientHello`: `0x0301` (Chrome), `0x0303`, `0x0304` |
| `cipher_suites` | yes | ciphers **without GREASE**; `0x1301` or `0x1302` is required (the node picks AES-GCM by default) |
| `groups` | yes | `supported_groups` without GREASE; **`0x001d` is required** (x25519), `0x11ec` adds the post-quantum ballast |
| `signatures` | yes | `signature_algorithms` |
| `delegated_signatures` | — | for `delegated_credential` |
| `versions` | yes | `supported_versions` without GREASE; **`0x0304` is required** |
| `alpn`, `alps_protocols` | — | ALPN / ALPS protocols |
| `alps_codepoint` | — | `0x44cd` (default) or `0x4469` |
| `extension_order` | yes | extension order; `grease_first` / `grease_last` — GREASE positions. `key_share`, `supported_groups`, `supported_versions` are required |
| `has_grease` | — | by default: whether the order has GREASE slots |
| `shuffle_extensions` | — | shuffle the "middle" of the order per connection (Chromium) |
| `target_padding_len` | — | `ClientHello` padding target (0 — none) |
| `ech_payload_lengths` | — | allowed GREASE-ECH payload lengths; a random one is taken per connection (empty = 144) |
| `compress_cert_algs`, `psk_modes`, `ec_point_formats` | — | content of the same-named extensions (defaults: brotli, `[1]`, `[0]`) |
| `raw_extensions` | — | bodies of extensions with no dedicated builder: `{"0x1234": "abcd01"}` — written out as is |
| `quic` | — | the QUIC block (below) |
| `shape` | — | `{"up": [...], "down": [...]}` — TLS record lengths, ascending |
| `meta` | — | any information (source, JA3/JA4, notes); not read by the engine |

Extension names: `server_name`, `status_request`, `supported_groups`, `ec_point_formats`,
`signature_algorithms`, `alpn`, `sct`, `padding`, `extended_master_secret`, `compress_certificate`,
`delegated_credential`, `session_ticket`, `supported_versions`, `psk_key_exchange_modes`, `key_share`,
`alps`, `ech`, `renegotiation_info`, `grease_first`, `grease_last`.

### The `quic` block

| Field | Meaning |
|---|---|
| `hello` | the QUIC `ClientHello` — the same format as the whole profile (a nested `quic` is forbidden). `extension_order` holds `"0x0039"` (`quic_transport_parameters`); the engine fills in the body itself |
| `scid_len` | length of the client's Source Connection ID (Chrome — 0) |
| `pn_len`, `first_pn` | length of the encoded packet number and the number of the first packet (Chrome — 1) |
| `initial_packets` | layout of the first flight: `[{"crypto": 890, "datagram": 1250, "pn_len": 2}, …]` — how many `ClientHello` bytes a packet carries and the size of its datagram (padded with PADDING to ≥ 1200, RFC 9000 §14.1) |
| `scramble_frames` | Chrome "scrambles" the Initial: the `ClientHello` is cut into many CRYPTO frames, mixed with PING and PADDING, and spread over the packets out of order. When enabled the engine does the same |
| `shuffle_transport_params` | the order of the transport parameters is random per connection |
| `transport_params` | `[{"id": "0x0001", "value": "80007530", "kind": "fixed"}, …]`; `kind`: `fixed` — as is, `scid` — the packet's SCID is inserted, `grease` — a reserved parameter (`31·N+27`: an identifier of the same length class and a random value of the same length on every connection), `version_information` — GREASE versions in the list are replaced by fresh ones |

What stays hard-wired — **the DCID length (8 bytes) and the QUIC version (1)**: the node finds the
session by the DCID, so this is a protocol parameter between our client and node, not a fingerprint.
The node does not parse the contents of the Initial.

A profile is **validated on load**: if it breaks the protocol (no x25519, TLS 1.3, `key_share`, an
AES-GCM cipher, a duplicate extension, an Initial datagram shorter than 1200 B, a packet number that does
not fit in `pn_len`…), loading is rejected with a list of reasons and nothing changes — the error is
visible at once, not on the first connection. Less serious issues (an extension with no builder and no
`raw_extensions` will be skipped…) come out as warnings.

## What is extracted from a capture

**TLS over TCP.** From each `ClientHello`, losslessly: the record-header version, `legacy_version`,
ciphers (with GREASE), extensions **in wire order**, SNI, groups, signatures, ALPN, ALPS (codepoint),
`key_share` (the group and length of each share), PSK modes, point formats, `compress_certificate`,
`status_request`, ECH (`enc`/`payload`), padding, splitting across records. From the server's reply —
`ServerHello` and the record lengths of the first flight; from the rest of the connection — the lengths
of `ApplicationData` records in both directions.

**QUIC.** Initial packets are encrypted with keys derived from a public salt and the plaintext DCID
(RFC 9001 §5.2), so the `ClientHello` can be extracted without anyone's secrets — as any DPI does. The
parser removes header protection, decrypts AES-128-GCM, parses the frames (CRYPTO/PING/PADDING/ACK),
reassembles the CRYPTO stream by offsets from several packets and datagrams, and parses the transport
parameters. QUIC version 1 is supported; other versions are skipped with a note. Retransmitted Initials
(timer-driven) are not part of the layout, duplicate packets (loopback delivers both the outgoing and
the incoming copy) are dropped.

**JA3** and **JA4** are computed (for QUIC — with the `q` prefix); JA4 depends on neither GREASE nor
order, so a profile rebuilt by the engine must give the same JA4 as the browser — tests and the
self-check verify this.

If the capture holds several different clients, the largest group by JA4 is taken (the rest are listed);
`--sni`, `--client`, `--ja4`, `--all` pick the right ones. QUIC groups are paired with TCP profiles in
order of frequency (the engine picks a QUIC block independently of the session's TCP profile).

## Limitations: where they come from and what to do

| Limitation | Source | State |
|---|---|---|
| The profile was a constant in code | architecture | **removed**: JSON, loaded at startup, `--browser-profile` |
| ECH payload is a constant 144 B (Chrome: random 144/176/208/240) | hard-wired in the builder | **removed**: `ech_payload_lengths`, random per connection |
| Hard-wired brotli / PSK `[1]` / point format `[0]` / ALPS `0x44cd` | hard-wired in the builder | **removed**: profile fields |
| Extensions with no builder were **silently omitted** | builder | **removed**: `raw_extensions` (body from the capture); no body — a warning |
| Needs `tcpdump` and privileges | tooling | **removed**: recording from the binary (`AF_PACKET`, `CAP_NET_RAW`) |
| The SNI of visited sites ended up in the profile | `meta` | **removed**: no site names in the JSON |
| The profile was not checked for reproducibility | — | **removed**: the engine self-checks at recording time |
| One fingerprint per capture | — | **removed**: `--all`, `profile merge` |
| QUIC was not parsed | parser | **removed**: Initial is decrypted, the `quic` block, the engine builds the Initial from the profile |
| Record lengths were synthetic | — | **removed**: the `shape` block, `--shape-profile` on the node |
| Cover flight was a typical chain | — | **removed**: `--flight-out` / `--cover-flight` |
| Recording on Linux only | `AF_PACKET` | on macOS/Windows: `profile build` from a `.pcap` made in Wireshark. Native capture (libpcap/Npcap) — a possible extension |
| Not reproduced: `legacy_version`≠`0x0303`, `session_id`≠32 B (TCP), `compression`≠`[0]`, non-standard `key_share`/`status_request`/SCT/EMS/ticket | **protocol**: `session_id` carries the version, cipher and tag; key exchange is X25519 only | remains; such differences appear in `notes` |
| DCID length (8 B) and QUIC version (1) | **protocol**: the node finds the session by the DCID | remains |
| A cover-flight record < 41 B | cover-frame header (25 B) + tag (16 B) | remains; the command warns |
| Not reproduced: the OS TCP/IP fingerprint (MSS, window, TTL), 0-RTT and session resumption, HelloRetryRequest, QUIC Retry/tokens, timer-driven Initial retransmissions | OS kernel / separate scenarios | remains |
| The shape is record lengths only | the timing pattern and a specific site are not recorded | remains |
| The mobile app (UniFFI) does not accept a JSON profile | no parameter in `SessionParams` | **can be improved**: add a parameter; `core::browser_profile::load_json` is ready |
| WebRTC UDP leg | no profile from JSON | a possible extension |
| The start of the connection is needed | TCP/TLS: `ClientHello` is the first packet | unavoidable, but recording catches new connections; open new tabs |
| Firefox headless did not get captured during testing | environment (Firefox snap), not the tool | capture a profile on your own machine; the Firefox-shaped branch of the parser was checked on synthetic data |

## API

```rust
use netrunner_core::{browser_profile, pcap};

// engine: replace the built-in pool with your own profiles (TLS, QUIC, traffic shape)
let report = browser_profile::load_file("chrome.json")?;      // or load_json(&str)
browser_profile::clear();                                      // back to the built-in ones
browser_profile::load_shape_file("chrome.json")?;              // the shape only (node)

// extraction: file(s) → profile
let analysis = pcap::analyze(&std::fs::read("chrome.pcap")?)?; // or analyze_many(&[..])
let profile = analysis.build_profile(&pcap::ProfileOptions::default())?;
let quic = analysis.build_quic(&pcap::ProfileOptions::default())?;
let ok = analysis.verify_profile(&profile, pcap::DEFAULT_SAMPLES).unwrap().ok();
let flight = analysis.measured_flight("your.domain")?;        // for --cover-flight
std::fs::write("chrome.json", profile.to_json())?;

// recording (Linux), feature `pcap`
let rec = pcap::capture::record(&pcap::capture::CaptureConfig::default(), &stop, &mut |p| { /* progress */ })?;
let analysis = rec.analyze();
```

The low-level pieces (`read_packets`, `assemble_flows`, `split_records`, `parse_client_hello`,
`quic::parse_initial`, `ja3_string`, `ja4`) are public. The `pcap` module is enabled by the `pcap`
feature; reading JSON (`browser_profile`) is always available, including in mobile and wasm builds.

## Verification

```bash
cargo test -p netrunner-core --features pcap --lib      # 330 tests
```

One of them (`garbage_client_hello_triggers_fallback_without_hanging`) waits for a DNS answer and times
out in an environment without a network — it is unrelated to profiles (it fails without these changes
too).

Among the tests: synthetic captures built from our own builder's `ClientHello`s; **a real Chrome 148
capture** over TCP and over QUIC (fixtures `core/src/pcap/testdata/chrome148_loopback.pcap`,
`chrome148_quic.pcap`) → JSON → profile → rebuild with the same JA4; the Initial keys — against the
RFC 9001 Appendix A vectors; hundreds of "scrambled" Initial layouts always parse back; the shipped
`profiles/*.json` are accepted by the real server-side parsing; recording from the binary was verified
by hand against live Chrome (TCP + QUIC in one run).

### What was found on a real Chrome 148

| Observation | Value |
|---|---|
| JA4 (TCP) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` (`8daaf6152771` is the well-known Chrome cipher hash) |
| `signature_algorithms` | 8 values, **without ML-DSA** (`0904`–`0906`); the built-in `CHROME_140` has 11 |
| extension order (TCP) | shuffled between connections; the set of 18 (with 2 GREASE) matches `CHROME_140` |
| ECH GREASE payload | random: 144 / 176 / 208 / 240 B |
| first flight (RSA-2048 `s_server`) | records `23, 832, 281, 53` (`Finished = 4+32+17 = 53`) |
| JA4 (QUIC) | `q13d0311h3_55b375c5d22e_653d80c3fe9d`: 3 ciphers, 11 extensions, **no GREASE extensions**, ALPN `h3`, ALPS, ECH |
| Initial | two packets of 1250 B (one ClientHello ≈ 1780 B does not fit), numbers start at **1**, packet-number length 1–2 B, empty SCID, 8 B DCID |
| Initial frames | **"scrambled"**: up to two dozen CRYPTO frames per packet of varying length (1–800 B), PING, PADDING in chunks, non-sequential offsets; on retransmission the layout is random again |
| transport parameters | 12 of them in **random order**; a GREASE parameter with an 8-byte identifier and an 8–15 B value; `version_information` with a GREASE version at a random position |
| retransmissions | on a timer (≈ 0.3 / 0.9 / 2.1 / 4 s) |

The built-in `CHROME_140` profile differs from Chrome 148 in its signature list, and the built-in UDP-leg
Initial looks different (one Initial, one CRYPTO frame, 7 extensions without ECH and ALPS, 3 ciphers, 8 transport parameters) — use
`profiles/chrome_148.json` (or extract a profile for your own browser version).
