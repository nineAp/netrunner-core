# Deploying netrunner-proxy

🇷🇺 [Русская версия](../DEPLOYMENT.md)

Step-by-step guide: from an empty VPS to a working node and client. The quick start is in the
[README](../../README.en.md); the protocol is in [PROTOCOL.md](PROTOCOL.md); threats and operator
requirements are in [SECURITY_MODEL.md](SECURITY_MODEL.md).

> The commands in §3–§4 were verified against this code base (`cargo build --release`, starting
> the server with keys, health/metrics, probes). The Docker build and the systemd unit in §7 are
> based on the repository's own files but were not run on a clean VPS; the firewall examples (§9)
> are a starting point — test them on your own system.

## Contents

1. [Deployment modes](#1-deployment-modes)
2. [Requirements](#2-requirements)
3. [Build](#3-build)
4. [Quick start: a standalone node](#4-quick-start-a-standalone-node)
5. [Reference: flags and variables](#5-reference-flags-and-variables)
6. [Camouflage (decoy)](#6-camouflage-decoy)
7. [Running as a service](#7-running-as-a-service)
8. [Client](#8-client)
9. [Hardening checklist](#9-hardening-checklist)
10. [Monitoring](#10-monitoring)
11. [Control plane, mesh, MASQUE, edge](#11-control-plane-mesh-masque-edge)
12. [Upgrades and key rotation](#12-upgrades-and-key-rotation)
13. [Verification and troubleshooting](#13-verification-and-troubleshooting)

---

## 1. Deployment modes

| Mode | What you need | Who is admitted |
|---|---|---|
| **Standalone** (recommended to start) | just a node and a client config | anyone who has the `nrxp_secret` and the node's public key |
| **With a control plane** (`--require-auth`) | an HTTP backend implementing the contract from [PROTOCOL.md §9](PROTOCOL.md#9-control-plane-http-contract) | users with a token, traffic limits |
| **Mesh** (`--mesh-enabled`) | a control plane + several nodes | as above, routed through a chain of nodes |

The rest of this guide covers standalone mode; the others are in §11.

## 2. Requirements

* Linux x86_64/aarch64 with a public IPv4 address, **TCP and UDP open on the same port** (443 by default).
* Rust stable ≥ 1.91 (required by `nrxp-smoltcp` for the client; tested on 1.95) **or** Docker.
* To build the client: HTTPS access to `gitea.netrunner-vpn.com` (the `nrxp-smoltcp` dependency,
  see [`client/Cargo.toml`](../../client/Cargo.toml)). **The server does not need this access.**
* Synchronized clocks (NTP) on the node and clients: tolerance is ±2 minutes.
* Recommended: a kernel with BBR (`modprobe tcp_bbr`) — the node requests BBR per leg socket by itself.

## 3. Build

```bash
git clone git@github.com:nineAp/netrunner-core.git netrunner-proxy && cd netrunner-proxy
cargo build --release -p netrunner-server        # → target/release/netrunner-server
```

Docker (builds both `netrunner-server` and `netrunner-masque-edge` inside the image):

```bash
docker build -t netrunner-proxy .
```

The image runs as `./netrunner-proxy …` (that is how the backend has historically passed the
command); the entrypoint `server/container-entrypoint.sh` starts MASQUE only with a complete
MASQUE configuration (§11).

## 4. Quick start: a standalone node

**1. Generate the secrets** (both are 32 bytes in hex; store them as secrets):

```bash
export PROXY_NRXP_SECRET=$(openssl rand -hex 32)        # shared entry secret: clients get it
export PROXY_NRXP_PRIVATE_KEY=$(openssl rand -hex 32)   # node private key: NEVER leaves the node
export PROXY_NRXP_STRICT=true                           # reject the anonymous scheme
```

**2. Start the node:**

```bash
sudo -E ./target/release/netrunner-server --host 0.0.0.0 --port 443 \
  --decoy-host www.debian.org --health-port 9091
```

**3. Take the public key from the log** — the `NRXP identity loaded` line:

```json
{"level":"INFO","fields":{"message":"NRXP identity loaded","nrxp_public_key":"5556…e00a","strict":true}}
```

**4. Give the client four values:** the address `IP:443`, `sni` (= `--decoy-host`),
`node_secret` (= `PROXY_NRXP_SECRET`), `node_public_key` (from the log). Client setup: §8.

**5. Check:**

```bash
curl -s http://127.0.0.1:9091/            # {"status":"ok","active_connections":0}
```

If the secrets are not set, the node starts in anonymous mode (v2) and warns loudly: there is no
node authentication, and it can be classified by a probe with no secrets
([SECURITY_MODEL §7.2](SECURITY_MODEL.md#72-strict-mode-and-scheme-downgrade)).
`PROXY_NRXP_SECRET` and `PROXY_NRXP_PRIVATE_KEY` must be set **together** — otherwise the node
panics at startup.

> ⚠ In standalone mode without `--require-auth`, access is determined **only** by `nrxp_secret`.
> Give it only to people you trust, and read §9 first (the node does not filter destinations).

## 5. Reference: flags and variables

`netrunner-server` flags:

| Flag | Default | Meaning |
|---|---|---|
| `-p, --port` | `8080` | TCP **and** UDP port (the UDP leg uses the same port) |
| `--host` | `0.0.0.0` | bind address |
| `--decoy-host` | `www.debian.org` | decoy site for "not ours" connections (`relay` mode) |
| `--decoy-mode` | `relay` | `relay` \| `self-hosted` (see §6) |
| `--decoy-preset`, `--decoy-sni`, `--decoy-local-site` | — / — / `127.0.0.1:8443` | `self-hosted` only |
| `--cover-flight` | typical chain | record lengths of the node's first reply: a list `27,4342,537,69` or a JSON file from `profile record --flight-out` (`NETRUNNER_COVER_FLIGHT`), see [PCAP_PROFILE.md](PCAP_PROFILE.md) |
| `--shape-profile` | synthetic | browser-profile JSON with a `shape` block: the node's record lengths follow the browser's (`NETRUNNER_SHAPE_PROFILE`) |
| `--require-auth` | off | require a token, validate it at `--backend-url` |
| `--backend-url` | — | control-plane URL (required with `--require-auth`/`--mesh-enabled`) |
| `--mesh-enabled`, `--mesh-max-hops`, `--mesh-quic-port` | off, `2`, `8443` | mesh (§11) |
| `--health-port` | off | `/health`, `127.0.0.1` only |
| `--metrics-port` | off | Prometheus `/metrics`, on **`0.0.0.0`** |

Environment variables:

| Variable | Where | Meaning |
|---|---|---|
| `PROXY_NRXP_SECRET`, `PROXY_NRXP_PRIVATE_KEY` | node | node credentials (only as a pair) |
| `PROXY_NRXP_STRICT` | node | `true` — reject anonymous clients |
| `PROXY_INTERNAL_SECRET` | node | node secret towards the control plane (`--require-auth`/mesh) |
| `PROXY_NODE_ID` | node | node UUID (mesh) |
| `NETRUNNER_DECOY_DOMAINS`, `NETRUNNER_DECOY_SITE_OUT` | node | domain catalog / storefront output path (`self-hosted`) |
| `NR_LEG_CC` | node/client | leg congestion control (default `bbr`, `off` — leave the OS default) |
| `MESH_QUIC_PORT`, `MASQUE_*` | node | see §11 |
| `RUST_LOG` | client | log level |

Logs are JSON on stdout; the node writes nothing to disk.

## 6. Camouflage (decoy)

### 6.1 `relay` mode (default, working)
Everything that fails the `ClientHello` check is transparently relayed to a real site (by the SNI
from the probe, or `--decoy-host`). A scanner sees a real site.

### 6.2 Choosing `--decoy-host`
A large, stable HTTPS site, **geographically close to the node**, that returns `200` regardless of
SNI/Host (default `www.debian.org`). Give clients the same domain as `sni`. It must resolve to a
public IP (loopback/private/your own IP are rejected). It is better for each node to have a
different decoy.

### 6.3 `self-hosted` mode
The node itself "is the site": `--decoy-mode self-hosted --decoy-preset hauler
--decoy-sni your.domain` + `NETRUNNER_DECOY_DOMAINS=your.domain`; the storefront is built at
startup into `NETRUNNER_DECOY_SITE_OUT` (default `/var/www/netrunner-decoy/index.html`) and must be
served by a local TLS terminator (nginx/Caddy with your domain's certificate) at
`--decoy-local-site`.

### 6.4 ⚠ Known `self-hosted` issue
Building the storefront works, but **forwarding the fallback to the local site currently does not
work** (the SSRF filter blocks loopback; verified by running it). Use `relay`. Details and the
effect on stealth — [SECURITY_MODEL §7.6](SECURITY_MODEL.md#76-self-hosted-mode-forwarding-to-the-local-site-does-not-work).

## 7. Running as a service

### systemd

```bash
sudo useradd -r -s /usr/sbin/nologin netrunner
sudo install -m 0755 target/release/netrunner-server /usr/local/bin/
sudo install -d -m 0750 -o root -g netrunner /etc/netrunner
sudo tee /etc/netrunner/node.env >/dev/null <<EOF
PROXY_NRXP_SECRET=$(openssl rand -hex 32)
PROXY_NRXP_PRIVATE_KEY=$(openssl rand -hex 32)
PROXY_NRXP_STRICT=true
EOF
sudo chmod 0640 /etc/netrunner/node.env && sudo chgrp netrunner /etc/netrunner/node.env

sudo tee /etc/systemd/system/netrunner-server.service >/dev/null <<'EOF'
[Unit]
Description=Netrunner node
After=network-online.target
Wants=network-online.target

[Service]
User=netrunner
EnvironmentFile=/etc/netrunner/node.env
ExecStart=/usr/local/bin/netrunner-server --host 0.0.0.0 --port 443 --decoy-host www.debian.org --health-port 9091
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitNOFILE=1048576
Restart=always
RestartSec=3
TimeoutStopSec=35

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now netrunner-server
journalctl -u netrunner-server | grep nrxp_public_key
```

(The repository's own units — `server/netrunner-server.service` — run as root from
`/root/netr-core`; the example above is stricter.) `TimeoutStopSec=35`: the server catches SIGTERM
and waits up to 30 s for clients to disconnect.

### Docker

```bash
docker run -d --name netrunner-proxy --restart always --network host \
  --ulimit nofile=1048576:1048576 \
  --log-driver json-file --log-opt max-size=50m --log-opt max-file=3 \
  --health-cmd="wget -q -O - http://127.0.0.1:9091/ | grep -q '\"status\":\"ok\"' || exit 1" \
  --health-interval=15s --health-start-period=20s \
  -e PROXY_NRXP_SECRET -e PROXY_NRXP_PRIVATE_KEY -e PROXY_NRXP_STRICT=true \
  netrunner-proxy ./netrunner-proxy --port 443 --decoy-host www.debian.org --health-port 9091
```

`--network host` is needed so the UDP leg and the single TCP/UDP port work without a NAT proxy.
`--cap-add NET_ADMIN` is needed only if the kernel forbids `TCP_CONGESTION=bbr` for an unprivileged
process (otherwise the node silently stays on the OS default).

## 8. Client

### Linux / OpenWrt (headless)

```bash
cargo build --release -p netrunner-client --features cli --bin netrunner-client
```

`/etc/netrunner/client.toml` (mode `0600`):

```toml
remote_address  = "203.0.113.10:443"      # numeric IPv4:port only
sni             = "www.debian.org"        # = the node's --decoy-host
node_secret     = "<PROXY_NRXP_SECRET>"
node_public_key = "<nrxp_public_key from the node log>"
auth_token      = ""                      # empty for a standalone node
# browser_profile = "/etc/netrunner/chrome.json"   # your own browser profile, see PCAP_PROFILE.md
# tunnel_legs   = 4                       # parallel TCP legs, 1–10 (--tunnel-legs); nodes older than this release accept ≤ 4
killswitch_enabled = true
tunnel_mode     = "bypass_lan"            # all | bypass_lan
```

```bash
sudo setcap cap_net_admin,cap_net_raw,cap_dac_override=eip ./target/release/netrunner-client
./target/release/netrunner-client --config /etc/netrunner/client.toml
```

All keys are also accepted via `NETRUNNER_*` variables and flags (`--help`). An empty
`node_secret`/`node_public_key` pair enables the anonymous scheme — for tests only.
A custom browser profile for camouflage (extract it from a real browser with one command or write the
JSON by hand): [PCAP_PROFILE.md](PCAP_PROFILE.md) — `netrunner-client profile record --out chrome.json`,
then `browser_profile = "chrome.json"` or `--browser-profile`.
OpenWrt (`router_mode`, procd, firewall zone): [`client/openwrt/README.md`](../../client/openwrt/README.md).
The mobile app and the Tauri client use the same `client/` through UniFFI
(`make build-android`).

> The client cannot be run for a local check without root (it needs a TUN device). To test the
> full path in isolated netns: `make test-router-wsl` (requires sudo).

## 9. Hardening checklist

Mandatory (rationale — [SECURITY_MODEL §10](SECURITY_MODEL.md#10-node-operator-requirements)):

- [ ] `PROXY_NRXP_STRICT=true`; secrets only in env/a secret store, not on the command line.
- [ ] **Egress filter for the node process.** The node connects to any client-supplied `host:port`,
  including `127.0.0.1`, private networks and `169.254.169.254`. nftables example
  (user `netrunner`; if the control plane is on a private network, add an exception):
  ```bash
  sudo nft -f - <<'EOF'
  table inet nr_egress {
    chain out {
      type filter hook output priority 0; policy accept;
      meta skuid "netrunner" ip  daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } drop
      meta skuid "netrunner" ip6 daddr { ::1, fc00::/7, fe80::/10 } drop
    }
  }
  EOF
  ```
  With Docker `--network host` the `skuid` rule will not work (root in the container) — filter by
  cgroup (`socket cgroupv2`) or run under a separate non-root UID (`--user`).
- [ ] **Inbound firewall:** open `tcp/443` and `udp/443` (+ `udp/8443` for mesh) to everyone;
  `--metrics-port` — only to the metrics collector's IP; `--health-port` listens on loopback.
  ```bash
  sudo ufw allow 443/tcp && sudo ufw allow 443/udp
  sudo ufw allow from <PROMETHEUS_IP> to any port 9093 proto tcp
  ```
- [ ] Limits: `LimitNOFILE`, and if needed `nft … ct count over 200 drop` on SYNs from one IP
  (the node has no global connection limit).
- [ ] NTP enabled. The node does not share a machine with valuable services.
- [ ] `--backend-url` is `https://` only.
- [ ] Permissions: `chmod 600` on files with secrets; the client's `client.toml` is `0600`.

## 10. Monitoring

`--metrics-port 9093` → `GET /metrics` (Prometheus). Key series:

| Metric | Meaning |
|---|---|
| `netrunner_vpn_established_total` | successful tunnel connections |
| `netrunner_scanner_fallback_total` | "not ours" connections (scanners, probes, foreign clients) |
| `netrunner_auth_failures_total` | valid handshake, authorization refused |
| `netrunner_handshake_total{version}` | handshakes by protocol version (how many clients remain on v2) |
| `netrunner_connections_active`, `netrunner_legs_active`, `netrunner_legs_expected` | load and leg health |
| `netrunner_nrxp_identity_configured`, `netrunner_nrxp_strict` | what the node was actually started with (should be `1`) |
| `netrunner_circuit_breaker_open` | the control plane is unreachable |
| `netrunner_datagram_legs_established_total` | UDP legs brought up |
| `netrunner_mesh_*` | mesh (routes, capsules, QUIC) |

```yaml
scrape_configs:
  - job_name: netrunner
    static_configs: [{ targets: ["NODE_IP:9093"] }]
```

`/health` → `200 {"status":"ok",…}` or `503 {"status":"stalled"}` (the process is alive but the
periodic task is stuck) — for docker/systemd healthchecks.

## 11. Control plane, mesh, MASQUE, edge

* **`--require-auth`**: requires a backend with the endpoints `/api/v1/internal/{validate,usage,usage/batch,node-health}`
  ([contract](PROTOCOL.md#9-control-plane-http-contract)), `--backend-url https://…`,
  `PROXY_INTERNAL_SECRET` (separate per node, never given to clients). The client token goes into
  `auth_token`.
* **Mesh** (`--mesh-enabled`): additionally `PROXY_NODE_ID`, NRXP credentials,
  `/internal/mesh/{peers,validate}`, open `udp/8443` (or `--mesh-quic-port`) between nodes.
  `--mesh-max-hops` 1…8 is a hard upper bound on route length. Details — [MESH.md](MESH.md).
* **MASQUE** (HTTP/3 relay for iOS, **experimental**, `udp/8444`):
  [`masque-edge/README.md`](../../masque-edge/README.md), config template
  `server/masque-edge.env.example`; needs a publicly trusted certificate.
* **Edge relays** in front of a node: [`edge-native`](../../edge-native/README.md) (VDS + Caddy,
  WSS), [`client-edge`](../../client-edge/README.MD) (Cloudflare Worker).
* Manual deploy of a single machine: `make setup-server && make deploy-server` (reads `.env`,
  template — `.env.example`).

## 12. Upgrades and key rotation

**Upgrading the binary/image:** build the new one, `systemctl restart netrunner-server`
(SIGTERM → up to 30 s to drain). Clients reconnect their legs within seconds. The protocol is
compatible both ways across versions ([PROTOCOL §2](PROTOCOL.md#2-protocol-versions-and-compatibility)).

**Rolling keys out to an existing fleet:** first nodes without `STRICT` (they accept both v2 and
v3+), hand the keys to clients, watch `netrunner_handshake_total{version="2"}`; when v2 ≈ 0 —
`PROXY_NRXP_STRICT=true`.

**Rotation:** a new `PROXY_NRXP_SECRET`/`PRIVATE_KEY` pair → restart → the new `nrxp_public_key`
from the log → distribute to clients. Old clients **will stop connecting** — this is expected
(otherwise rotation would revoke nothing); the node log will show
`Unauthorized ClientHello: Auth Tag mismatch`. If `PROXY_NRXP_PRIVATE_KEY` leaks, rotating is
mandatory (the node can be impersonated); if only `nrxp_secret` leaks — see
[SECURITY_MODEL §3 (A8)](SECURITY_MODEL.md#3-adversaries).

## 13. Verification and troubleshooting

```bash
curl -s http://127.0.0.1:9091/                      # health
curl -s http://127.0.0.1:9093/metrics | grep -E 'strict|identity|established|fallback'
curl -sk --resolve www.debian.org:443:NODE_IP https://www.debian.org/ -o /dev/null -w '%{http_code}\n'   # probe: should return 200 from the decoy site
```

After the probe, `netrunner_scanner_fallback_total` will increase — that is expected.

| Symptom | Cause |
|---|---|
| panic at startup "only set together" | only one of `PROXY_NRXP_SECRET`/`PRIVATE_KEY` is set |
| `Address already in use` | the port is taken (TCP, or UDP with the same number) |
| client cannot connect, node log shows `Auth Tag mismatch` | the client's `node_secret`/`node_public_key` differ from the node's; clock skew > ±2 min; rotation |
| client connects, immediately `auth_rejected` | node has `--require-auth`, token invalid/expired; check the circuit breaker |
| HTTP probe to the port hangs for 10 s | normal: we wait for a `ClientHello` up to `TLS_HELLO_TIMEOUT`, then fall back |
| `Stealth fallback: no safe target address` | the decoy does not resolve to a public IP (or `self-hosted`, §6.4) |
| no UDP leg | the UDP port is closed/throttled; the client stays on TCP (normal) |
| heavy lag during downloads | kernel without BBR (`modprobe tcp_bbr`), or `NR_LEG_CC=off` |

More — [MAINTENANCE.md](../MAINTENANCE.md) (operations, CI, pitfalls; Russian).
