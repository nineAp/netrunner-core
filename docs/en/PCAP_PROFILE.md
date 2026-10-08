# Browser profiles: record, JSON, load

🇷🇺 [Русская версия](../PCAP_PROFILE.md)

The engine builds its `ClientHello` from a **browser profile** — a "recipe" for the fingerprint
(ciphers, groups, signatures, extension order…). A profile is data: a JSON file. You can **extract it
from a real browser with one command**, edit it by hand or write it from scratch, and the client picks
it up at startup. No rebuild.

```text
 browser ──traffic──▶ netrunner-client profile record ──▶ profile.json ──▶ netrunner-client --browser-profile profile.json
                      (AF_PACKET, no tcpdump)       (pcap parsing, JA3/JA4,        (the engine builds ClientHello from JSON)
                                                     profile building, validation)
```

## Quick start

```bash
# 0. once: permission for a raw socket (or run through sudo)
sudo setcap cap_net_raw+ep ./netrunner-client

# 1. TURN THE VPN OFF, start recording and browse 3–5 different sites
./netrunner-client profile record --out chrome.json
#    stops by itself once 12 connections of one fingerprint are collected (or Ctrl+C / 120 s)

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
| `profile record --out F` | records traffic, builds the profile, writes JSON. Flags: `--iface` (all by default), `--port` (443; repeatable), `--seconds` (120), `--stop-after` (12; 0 — Ctrl+C/timer only), `--save-pcap F` (keep the raw capture), `--name`, `--sni`, `--client`, `--ja4` |
| `profile build CAP --out F` | the same from a ready `.pcap`/`.pcapng` (Wireshark, `tcpdump`, Windows/macOS) |
| `profile check F` | validates the JSON (whether the profile fits our protocol) and prints warnings |

Recording shows progress (connections, `ClientHello`s, distinct fingerprints), and at the end a
summary: JA4, extension shuffling and what justifies it, the observed ECH lengths, other fingerprints in
the capture, and notes on what the engine does not reproduce.

> To determine **extension shuffling** and the spread of ECH lengths several connections are needed:
> Chromium changes the order on each one. That is why `--stop-after` defaults to 12.
> Record without the VPN: otherwise the capture would hold our own tunnel instead of the browser. It is
> best to disable QUIC (`--disable-quic` in Chrome) — otherwise traffic goes over UDP.

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
| `meta` | — | any information (source, JA3/JA4, notes); not read by the engine |

Extension names: `server_name`, `status_request`, `supported_groups`, `ec_point_formats`,
`signature_algorithms`, `alpn`, `sct`, `padding`, `extended_master_secret`, `compress_certificate`,
`delegated_credential`, `session_ticket`, `supported_versions`, `psk_key_exchange_modes`, `key_share`,
`alps`, `ech`, `renegotiation_info`, `grease_first`, `grease_last`.

A profile is **validated on load**: if it breaks the protocol (no x25519, TLS 1.3, `key_share`, an
AES-GCM cipher, a duplicate extension…), loading is rejected with a list of reasons and nothing changes —
the error is visible at once, not on the first connection. Less serious issues (an extension with no
builder and no `raw_extensions` will be skipped, padding without a target…) come out as warnings.

## What is extracted from a capture

From each `ClientHello`, losslessly: the record-header version, `legacy_version`, ciphers (with GREASE),
extensions **in wire order**, SNI, groups, signatures, ALPN, ALPS (codepoint), `key_share` (the group
and length of each share), PSK modes, point formats, `compress_certificate`, `status_request`, ECH
(`enc`/`payload`), padding, splitting across records. From the server's reply — `ServerHello` and the
record lengths of the first flight (source data for
[`CoverFlight`](../../core/src/tlseng/decoy.rs)). **JA3** and **JA4** are computed; JA4 depends on
neither GREASE nor order, so a profile rebuilt by the engine must give the same JA4 as the browser —
tests verify this.

If the capture holds several different clients, the largest group by JA4 is taken (the rest are listed);
`--sni`, `--client`, `--ja4` pick the right one.

## Limitations: where they come from and what to do

| Limitation | Source | State |
|---|---|---|
| The profile was a constant in code | architecture | **removed**: JSON, loaded at startup, `--browser-profile` |
| ECH payload is a constant 144 B (Chrome: random 144/176/208/240) | hard-wired in the builder | **removed**: `ech_payload_lengths`, random per connection |
| Hard-wired brotli / PSK `[1]` / point format `[0]` / ALPS `0x44cd` | hard-wired in the builder | **removed**: profile fields |
| Extensions with no builder were **silently omitted** | builder | **removed**: `raw_extensions` (body from the capture); no body — a warning |
| Needs `tcpdump` and privileges | tooling | **removed**: recording from the binary (`AF_PACKET`, `CAP_NET_RAW`) |
| Recording on Linux only | `AF_PACKET` | on macOS/Windows: `profile build` from a `.pcap` made in Wireshark. Native capture (libpcap/Npcap) — a possible extension |
| Not reproduced: `legacy_version`≠`0x0303`, `session_id`≠32 B, `compression`≠`[0]`, non-standard `key_share`/`status_request`/SCT/EMS/ticket | **protocol**: `session_id` carries the version, cipher and tag; key exchange is X25519 only | remains; such differences appear in `notes` |
| TLS over TCP only; QUIC is not parsed | parser | **can be improved**: QUIC Initial packets are encrypted with keys derived from a public salt and the plaintext DCID, so the `ClientHello` can be extracted from them (our `quiceng` does the same when building). Not done; also needed for a QUIC-leg profile |
| A profile affects only the TCP leg | the UDP leg has its own profiles (`QuicProfile`, `WebrtcProfile`) | a possible extension — also from JSON |
| The mobile app (UniFFI) does not accept a JSON profile | no parameter in `SessionParams` | **can be improved**: add a parameter; `core::browser_profile::load_json` is ready |
| The start of the connection is needed | TCP/TLS: `ClientHello` is the first packet | unavoidable, but recording catches new connections; open new tabs |
| Firefox headless did not get captured during testing | environment (Firefox snap), not the tool | capture a profile on your own machine; the Firefox-shaped branch of the parser was checked on synthetic data |

## API

```rust
use netrunner_core::{browser_profile, pcap};

// engine: replace the built-in pool with your own profiles
let report = browser_profile::load_file("chrome.json")?;      // or load_json(&str)
browser_profile::clear();                                      // back to the built-in ones

// extraction: file → profile
let analysis = pcap::analyze(&std::fs::read("chrome.pcap")?)?;
let profile = analysis.build_profile(&pcap::ProfileOptions::default())?;
std::fs::write("chrome.json", profile.to_json())?;

// recording (Linux), feature `pcap`
let rec = pcap::capture::record(&pcap::capture::CaptureConfig::default(), &stop, &mut |p| { /* progress */ })?;
let analysis = rec.analyze();
```

The low-level pieces (`read_packets`, `assemble_flows`, `split_records`, `parse_client_hello`,
`ja3_string`, `ja4`) are public. The `pcap` module is enabled by the `pcap` feature; reading JSON
(`browser_profile`) is always available, including in mobile and wasm builds.

## Verification

```bash
cargo test -p netrunner-core --features pcap --lib      # 283 tests
```

Among them: synthetic captures built from our own builder's `ClientHello`s; **a real Chrome 148
capture** (fixture `core/src/pcap/testdata/chrome148_loopback.pcap`) → JSON → profile → rebuild with the
same JA4 and a random ECH length; the shipped `profiles/*.json` are accepted by the real server-side
parsing; recording from the binary was verified by hand against live Chrome.

### What was found on a real Chrome 148

| Observation | Value |
|---|---|
| JA4 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` (`8daaf6152771` is the well-known Chrome cipher hash) |
| `signature_algorithms` | 8 values, **without ML-DSA** (`0904`–`0906`); the built-in `CHROME_140` has 11 |
| extension order | shuffled between connections; the set of 18 (with 2 GREASE) matches `CHROME_140` |
| ECH GREASE payload | random: 144 / 176 / 208 / 240 B |
| first flight (RSA-2048 `s_server`) | records `23, 832, 281, 53` (`Finished = 4+32+17 = 53`) |

The built-in `CHROME_140` profile differs from Chrome 148 in its signature list — use
`profiles/chrome_148.json` (or extract a profile for your own browser version).
