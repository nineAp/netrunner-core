FROM rust:1.94-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p netrunner-masque-edge

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/netrunner-masque-edge /usr/local/bin/netrunner-masque-edge
EXPOSE 443/udp
# The common Let's Encrypt private-key path is root-readable and the default
# listener is a privileged port. Harden with a dedicated uid/capability after
# certificate delivery is moved away from the host's live directory.
ENTRYPOINT ["netrunner-masque-edge"]
