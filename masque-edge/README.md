# Netrunner MASQUE Edge prototype

This crate is an experimental direct-egress server for Apple's Network Relay.
It supports standard TCP `CONNECT` and UDP `CONNECT-UDP` (RFC 9298) over
HTTP/3. UDP payloads stay in QUIC DATAGRAM frames and are not carried by NRXP's
TCP transport.

The current prototype is deliberately HTTP/3-only. Do not add
`HTTP2RelayURL` to the generated profile until a separate HTTP/2 listener is
deployed.

## Run locally

Generate a development certificate (an iPhone requires a publicly trusted
certificate in normal use):

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout dev-key.pem -out dev-cert.pem -days 2 \
  -subj '/CN=relay.example.com'

MASQUE_TOKEN='replace-with-a-random-secret' \
  cargo run -p netrunner-masque-edge -- serve \
  --bind 0.0.0.0:4433 \
  --cert dev-cert.pem \
  --key dev-key.pem
```

Production requires both TCP and UDP firewall rules to be considered, but this
HTTP/3 prototype itself listens on UDP only. For a public test expose UDP 443
and use a certificate whose SAN matches the relay hostname.

Private, loopback and link-local targets are rejected by default so a deployed
edge cannot be used to reach its own control plane or cloud metadata endpoint.
Use `--allow-private-targets` only in an isolated lab.

Build the container from the workspace root (the Dockerfile uses the workspace
lockfile):

```bash
docker build -f masque-edge/Dockerfile -t netrunner-masque-edge .
```

## Deploy next to the ordinary server

The root workspace image and `make deploy-server` ship both server binaries.
The core proxy keeps UDP/443 for its datagram leg; MASQUE uses UDP/8444:

```text
0.0.0.0:443/tcp  netrunner-proxy
0.0.0.0:443/udp  netrunner-proxy datagram leg
0.0.0.0:8444/udp netrunner-masque-edge
```

For the root Docker image, mount the certificate files read-only and pass the
MASQUE environment. Existing `./netrunner-proxy ...` arguments remain valid:

```bash
docker run -d --network host \
  -e MASQUE_ENABLED=true \
  -e MASQUE_TOKEN='replace-with-a-separate-random-secret' \
  -e MASQUE_CERT_FILE=/etc/letsencrypt/live/relay.example.com/fullchain.pem \
  -e MASQUE_KEY_FILE=/etc/letsencrypt/live/relay.example.com/privkey.pem \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  gitea.netrunner-vpn.com/nineap/netrunner-proxy:latest \
  ./netrunner-proxy --port 443
```

With `MASQUE_ENABLED=auto` (the image default), the sidecar starts only when
all three required values are present. A partial configuration fails the
container early instead of silently exposing a broken relay.

For the systemd/rsync path, copy `server/masque-edge.env.example` to
`/etc/netrunner/masque-edge.env`, fill it, set mode `0600`, and run
`make deploy-server`. Without that file the MASQUE unit is installed but
skipped, while the ordinary TCP server still starts.

## Generate an iOS profile

```bash
cargo run -p netrunner-masque-edge -- profile \
  --http3-url 'https://relay.example.com:8444/.well-known/masque/udp/{target_host}/{target_port}/' \
  --token 'replace-with-a-random-secret' \
  --output netrunner-relay.mobileconfig
```

With no `--match-domain`, the relay payload asks iOS to route all eligible TCP
and UDP flows. The bearer token is device-local profile material: generate a
different token for every device and make it revocable.

For a user-facing deployment, sign the generated profile with CMS before
serving it as `application/x-apple-aspen-config`:

```bash
openssl smime -sign -binary -nodetach \
  -in netrunner-relay.mobileconfig \
  -signer profile-signing-cert.pem \
  -inkey profile-signing-key.pem \
  -outform der \
  -out netrunner-relay-signed.mobileconfig
```

## First physical iPhone test

1. Deploy the server on a public hostname with UDP 443 open.
2. Generate a per-device profile using exactly that hostname and token.
3. Download the profile in Safari and install it from Settings.
4. Watch logs with `RUST_LOG=netrunner_masque_edge=debug`.
5. Verify one TCP destination, a QUIC-capable site, a WebRTC call and a UDP
   game before integrating the edge with the production control plane.

This is not production-hardened yet. Fine-grained destination ACLs, per-device
token lookup, rate limits, UDP amplification protection, metrics and HTTP/2
fallback are the next gates.
