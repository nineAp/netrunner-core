# Extracting a browser profile from a pcap

🇷🇺 [Русская версия](../PCAP_PROFILE.md)

The `netrunner_core::pcap` module (`core/src/pcap/`, feature `pcap`) reads a capture file, reassembles
TCP streams, extracts the `ClientHello` (and the server's first flight) and computes from them a
[`BrowserProfile`](../../core/src/tlseng/profile.rs) — the "recipe" our builder uses to construct its
own `ClientHello`. Profile values are no longer copied from dumps by hand but computed from the
capture itself; anything the builder cannot reproduce is listed in `notes`.

## Quick start

```bash
# 1. capture the start of the browser's connections (open 2–3 different sites)
sudo tcpdump -i any -w chrome.pcap 'tcp port 443'
#    better to disable QUIC (Chrome: --disable-quic), otherwise traffic goes over UDP and is not parsed

# 2. get the profile
cargo run -p netrunner-core --features pcap --example pcap_profile -- chrome.pcap --name CHROME_149
```

The output is a ready associated `const` for `impl BrowserProfile` in
`core/src/tlseng/profile.rs`, `ВНИМАНИЕ:` ("WARNING") comments with discrepancies and (if the server's
reply is visible) `CoverFlight { records: vec![…] }`.

| Flag | What it does |
|---|---|
| `--name NAME` | the constant's name |
| `--list` | only list the found `ClientHello`s with JA4, record length and ECH |
| `--sni SUBSTR` / `--client IP` / `--ja4 HASH` | pick the right client if the capture holds several |
| `--json` | the profile as JSON (to store/compare) |

> To determine **extension shuffling** at least two connections are needed: Chromium changes the order
> on every one. With a single `ClientHello` the flag is set heuristically (GREASE + ALPS/ECH), and
> `shuffle_evidence` says so honestly.

## What is extracted

From every `ClientHello`, losslessly: the record-header version, `legacy_version`, ciphers (with
GREASE), extensions **in wire order**, SNI, `supported_groups`, `signature_algorithms`,
`delegated_credential`, `supported_versions`, ALPN, ALPS (codepoint and protocols), `key_share` (the
group and length of each share), PSK modes, point formats, `compress_certificate`, `status_request`,
ECH (`enc`/`payload`), padding, the record length (whether the hello was split across records).

From the server's reply — `ServerHello` (cipher, selected version, group) and the lengths of the
`ApplicationData` records of the first flight up to the client's first encrypted record: for TLS 1.3
these are `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished` — the source data for
[`CoverFlight`](../../core/src/tlseng/decoy.rs).

Profile fields → where they come from:

| `BrowserProfile` field | Source |
|---|---|
| `cipher_suites`, `groups`, `signatures`, `delegated_signatures`, `versions`, `alpn` | the corresponding hello fields without GREASE |
| `extension_order` | extension order; first/last GREASE replaced by the `GREASE_SLOT_FIRST/LAST` markers |
| `has_grease` | whether there is GREASE in ciphers/extensions |
| `shuffle_extensions` | the "middle" order differs between the group's `ClientHello`s |
| `record_layer_version` | the version in the record header carrying the `ClientHello` |
| `target_padding_len` | the hello's record length, if there is a `padding` extension |
| `alps_protocols` | the ALPS protocols |

Also computed are **JA3** (string and MD5) and **JA4**. JA4 depends on neither GREASE nor extension
order, so it serves as an objective check: a profile rebuilt by our builder must give the same JA4 as
the browser (verified by a test).

## What is supported

* Containers: `pcap` (µs/ns, either byte order), `pcapng` (several sections and interfaces,
  `if_tsresol`, EPB/SPB). Gzip — `gunzip` first.
* Link layers: Ethernet (+VLAN/QinQ), Linux cooked v1/v2 (`-i any`), raw IP, BSD loopback.
* IPv4/IPv6 (extension headers; non-first fragments are skipped).
* TCP: reordering, retransmissions and overlaps, wrap-around of the sequence number past 2³²; at the
  first gap, assembly of that direction stops and a warning is written to `warnings`.
* Any ports (not only 443), several clients — grouped by JA4.
* A `ClientHello` split across several TCP segments and TLS records.

Not supported: decryption, QUIC (Initial packets are only counted and produce a warning), captures
without the start of the connection.

## What to know about the result

`notes` list what our builder does not reproduce exactly: `legacy_version`/`session_id`/`compression`
unlike ours, extensions with no dedicated builder (they will be empty), a different `key_share`
structure, non-standard `compress_certificate`/`psk_modes`/ALPS codepoint, **an ECH payload of a
different length**. A profile with non-empty `notes` will match the browser by JA3/JA4 but not by the
content of those extensions.

### What was found on a real Chrome 148

Checked on a real capture (Chrome 148, headless, loopback → `openssl s_server`, TLS 1.3; the file is
the test fixture `core/src/pcap/testdata/chrome148_loopback.pcap`):

| Observation | Value |
|---|---|
| JA4 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` (`8daaf6152771` is the well-known Chrome cipher hash) |
| `signature_algorithms` | 8 values, **without ML-DSA** (`0904`–`0906`); the `CHROME_140` profile has 11 |
| extension order | shuffled between connections; the set of 18 (with 2 GREASE) matches `CHROME_140` |
| **ECH GREASE payload** | **random length: 144 / 176 / 208 / 240 B** (the builder uses the constant 144) |
| first flight (RSA-2048 `s_server`) | records `23, 832, 281, 53` (`Finished = 4+32+17 = 53` — the `CoverFlight` formula is right) |

Two practical findings for the `CHROME_140` profile: (1) the signature list with ML-DSA does not match
Chrome 148; (2) a constant ECH payload of 144 B is a detector. The profile should be refreshed with
this tool for the target Chrome version, and the ECH payload length made random from the observed set.

## API

```rust
use netrunner_core::pcap::{analyze, ProfileOptions};

let analysis = analyze(&std::fs::read("chrome.pcap")?)?;       // Analysis
for h in &analysis.client_hellos { /* ClientHelloInfo: everything that was on the wire */ }
let profile = analysis.build_profile(&ProfileOptions {
    name: Some("CHROME_149".into()),
    sni_contains: Some("example".into()),
    ..Default::default()
})?;                                                            // CapturedProfile
println!("{}", profile.to_rust_source());                       // or profile.to_json()
let flight = analysis.flight_for(&analysis.client_hellos[0]);   // ServerFlight → CoverFlight
```

The low-level pieces (`read_packets`, `assemble_flows`, `split_records`, `parse_client_hello`,
`ja3_string`, `ja4`) are public too — they can be used separately.

## Tests

```bash
cargo test -p netrunner-core --features pcap --lib pcap    # 27 tests
```

Synthetic captures are built from the `ClientHello`s of our own builder (an end-to-end loop: build →
capture → profile → rebuild → the same JA4); `real_chrome_148_capture` is a regression on real browser
bytes. Containers, link layers, TCP assembly and TLS parsing are covered by separate tests, including
truncated and garbage inputs (no panics).
