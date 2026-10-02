#!/bin/sh

# Resolve an old MASQUE bind that overlaps the proxy's native UDP listener or
# the inter-node QUIC listener. Arguments: bind address, proxy UDP port, mesh
# QUIC port. Preserve the configured address while selecting a free service
# port from the dedicated MASQUE range.
resolve_masque_bind() {
    bind="$1"
    proxy_port="$2"
    mesh_port="$3"
    host="${bind%:*}"
    port="${bind##*:}"

    if [ "$port" = "$proxy_port" ] || [ "$port" = "$mesh_port" ]; then
        port=8444
        while [ "$port" = "$proxy_port" ] || [ "$port" = "$mesh_port" ]; do
            port=$((port + 1))
        done
        bind="${host}:${port}"
    fi

    printf '%s\n' "$bind"
}
