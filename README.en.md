# Netrunner Core

A multiplexed VPN tunnel in Rust that masquerades as ordinary HTTPS (a Chrome TLS 1.3 session).
Client (Linux/OpenWrt/Android via UniFFI) + server node.

🇷🇺 [Русская версия](README.md) · Detailed documents: `docs/en/` (English); `docs/MAINTENANCE.md`, `docs/PROTOCOL_ANALYSIS.md`, `docs/UDP_LEG_RESEARCH.md` are Russian only.

**Features**

- up to 4 parallel TCP "legs" per session, seamless stream failover;
- end-to-end credit flow control, adaptive buffers, BBR on legs;
- authenticated handshake (X25519 + node static key), forward secrecy, AEAD (AES-GCM / ChaCha20-Poly1305);
- camouflage: Chrome 140 fingerprint (JA3/JA4, post-quantum `key_share`), server cover flight,
  irregular length padding, decoy site for scanners and active probes;
- optional: UDP leg (QUIC/WebRTC mimicry), multi-node mesh with onion routes;
- L3 VPN without TCP-in-TCP: TUN + userspace stack (`nrxp-smoltcp`), kill-switch, router mode.

> ⚠️ This is not Tor and does not promise "indistinguishable from HTTPS for DPI". Read the
> [security model](docs/en/SECURITY_MODEL.md), especially §7 (known limitations).

## Quick start: your own node in 5 minutes

A Linux VPS with `tcp/443` and `udp/443` open, Rust ≥ 1.91 (or Docker).

```bash
git clone git@github.com:nineAp/netrunner-core.git && cd netrunner-core
cargo build --release -p netrunner-server

export PROXY_NRXP_SECRET=$(openssl rand -hex 32)        # shared with clients
export PROXY_NRXP_PRIVATE_KEY=$(openssl rand -hex 32)   # stays on the node
export PROXY_NRXP_STRICT=true

sudo -E ./target/release/netrunner-server --port 443 --decoy-host www.debian.org --health-port 9091
```

Find `"nrxp_public_key":"…"` in the log — the node's public key. Check:
`curl -s http://127.0.0.1:9091/` → `{"status":"ok",…}`.

**Client** (Linux/OpenWrt) — `client.toml` (`chmod 600`):

```toml
remote_address  = "NODE_IP:443"
sni             = "www.debian.org"            # = --decoy-host
node_secret     = "<PROXY_NRXP_SECRET>"
node_public_key = "<nrxp_public_key from the node log>"
killswitch_enabled = true
```

```bash
cargo build --release -p netrunner-client --features cli --bin netrunner-client
sudo ./target/release/netrunner-client --config client.toml
```

> ⚠️ The node connects to any address a client asks for (including `127.0.0.1` and private
> networks). Read the [hardening checklist](docs/en/DEPLOYMENT.md#9-hardening-checklist) before handing out keys.

systemd, Docker, monitoring, upgrades and key rotation: **[deployment guide](docs/en/DEPLOYMENT.md)**.

## Documentation

| Document | Contents |
|---|---|
| [docs/en/DEPLOYMENT.md](docs/en/DEPLOYMENT.md) | deploying a node and a client: build, systemd/Docker, flags, firewall, monitoring, keys |
| [docs/en/PROTOCOL.md](docs/en/PROTOCOL.md) | full NRXP specification: handshake, keys, frames, multiplexing, UDP, mesh, constants |
| [docs/en/SECURITY_MODEL.md](docs/en/SECURITY_MODEL.md) | threat model, guarantees, secrets, residual risks |
| [docs/en/PCAP_PROFILE.md](docs/en/PCAP_PROFILE.md) | extracting a browser profile from a pcap capture (`--features pcap`) |
| [docs/en/MESH.md](docs/en/MESH.md) | mesh and onion routing: roles, protections, capabilities, limits |
| [docs/en/SECURITY.md](docs/en/SECURITY.md) | plain-language cryptography overview, comparison with MTProto |
| [docs/en/ARCH.md](docs/en/ARCH.md) | architecture overview |
| [docs/MAINTENANCE.md](docs/MAINTENANCE.md) | operations, CI, known pitfalls |
| [docs/PROTOCOL_ANALYSIS.md](docs/PROTOCOL_ANALYSIS.md) | quantitative analysis vs VLESS/Trojan/Hysteria2 (historical) |
| [docs/UDP_LEG_RESEARCH.md](docs/UDP_LEG_RESEARCH.md) | UDP leg research |

Code map: [`core/`](core) · [`server/`](server/README.MD) · [`client/`](client/README.MD) ·
[`client/openwrt/`](client/openwrt/README.md) · [`masque-edge/`](masque-edge/README.md) ·
[`edge-native/`](edge-native/README.md) · [`client-edge/`](client-edge/README.MD) · [`tools/`](tools/README.MD).

## Development

```bash
cargo test -p netrunner-core --lib      # 244 tests
make debug-server                        # local node on :8443
```

The client depends on the [`nrxp-smoltcp`](https://github.com/nineAp/nrxp-smoltcp) fork (git
dependency over HTTPS, see `client/Cargo.toml`); the server does not.

## License

[AGPL-3.0](LICENSE).
