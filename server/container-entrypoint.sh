#!/bin/sh

# Один контейнер, два независимых сокета:
#   netrunner-proxy       -> TCP/--port (обычно 443)
#   netrunner-proxy       -> UDP/--port (native datagram leg)
#   netrunner-masque-edge -> UDP/${MASQUE_BIND:-0.0.0.0:8444}
#
# MASQUE включается явно (MASQUE_ENABLED=true) либо автоматически, когда
# одновременно переданы авторизация, сертификат и ключ. Поэтому обновление образа
# через watchtower безопасно для старых нод без MASQUE-конфигурации.

set -u

case "${1:-}" in
    ./netrunner-proxy|/app/netrunner-proxy|netrunner-proxy)
        shift
        ;;
    ""|--*)
        # Пустая команда и прежний стиль `docker run IMAGE --port ...`
        # трактуются как аргументы основного серверного бинаря.
        ;;
    *)
        # Сохраняем обычную docker-семантику для отладочных команд вроде
        # `docker run --rm IMAGE /bin/sh`.
        exec "$@"
        ;;
esac

masque_pid=""
server_pid=""

terminate_children() {
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill -TERM "$server_pid" 2>/dev/null || true
    fi
    if [ -n "$masque_pid" ] && kill -0 "$masque_pid" 2>/dev/null; then
        kill -TERM "$masque_pid" 2>/dev/null || true
    fi
}

shutdown() {
    trap - TERM INT
    terminate_children
    [ -z "$server_pid" ] || wait "$server_pid" 2>/dev/null || true
    [ -z "$masque_pid" ] || wait "$masque_pid" 2>/dev/null || true
    exit 143
}

trap shutdown TERM INT

masque_mode="${MASQUE_ENABLED:-auto}"
masque_start=false
case "$masque_mode" in
    1|true|TRUE|yes|YES|on|ON)
        masque_start=true
        ;;
    0|false|FALSE|no|NO|off|OFF)
        masque_start=false
        ;;
    auto|AUTO)
        if { [ -n "${MASQUE_TOKEN:-}" ] || \
             { [ -n "${MASQUE_AUTH_URL:-}" ] && [ -n "${MASQUE_AUTH_SECRET:-${PROXY_INTERNAL_SECRET:-}}" ]; }; } && \
           [ -n "${MASQUE_CERT_FILE:-}" ] && \
           [ -n "${MASQUE_KEY_FILE:-}" ]; then
            masque_start=true
        elif [ -n "${MASQUE_TOKEN:-}${MASQUE_AUTH_URL:-}${MASQUE_AUTH_SECRET:-}${MASQUE_CERT_FILE:-}${MASQUE_KEY_FILE:-}" ]; then
            echo "MASQUE configuration is incomplete: auth, certificate and key are required" >&2
            exit 64
        fi
        ;;
    *)
        echo "invalid MASQUE_ENABLED value: $masque_mode" >&2
        exit 64
        ;;
esac

if [ "$masque_start" = true ]; then
    : "${MASQUE_CERT_FILE:?MASQUE_CERT_FILE is required when MASQUE is enabled}"
    : "${MASQUE_KEY_FILE:?MASQUE_KEY_FILE is required when MASQUE is enabled}"

    if [ -z "${MASQUE_TOKEN:-}" ] && [ -z "${MASQUE_AUTH_URL:-}" ]; then
        echo "MASQUE_TOKEN or MASQUE_AUTH_URL is required when MASQUE is enabled" >&2
        exit 64
    fi

    if [ ! -r "$MASQUE_CERT_FILE" ]; then
        echo "MASQUE certificate is not readable: $MASQUE_CERT_FILE" >&2
        exit 66
    fi
    if [ ! -r "$MASQUE_KEY_FILE" ]; then
        echo "MASQUE private key is not readable: $MASQUE_KEY_FILE" >&2
        exit 66
    fi

    # Old node containers have MASQUE_BIND=...:443 baked into their Docker
    # config. Watchtower replaces the image but preserves that environment, so
    # move only a colliding legacy bind before starting MASQUE. The proxy's
    # native datagram listener must retain the same UDP port as its TCP ingress.
    proxy_udp_port=8080
    mesh_udp_port="${MESH_QUIC_PORT:-8443}"
    expect_proxy_port=false
    expect_mesh_port=false
    for arg in "$@"; do
        if [ "$expect_proxy_port" = true ]; then
            proxy_udp_port="$arg"
            expect_proxy_port=false
            continue
        fi
        if [ "$expect_mesh_port" = true ]; then
            mesh_udp_port="$arg"
            expect_mesh_port=false
            continue
        fi
        case "$arg" in
            --port) expect_proxy_port=true ;;
            --port=*) proxy_udp_port="${arg#*=}" ;;
            --mesh-quic-port) expect_mesh_port=true ;;
            --mesh-quic-port=*) mesh_udp_port="${arg#*=}" ;;
        esac
    done

    requested_masque_bind="${MASQUE_BIND:-0.0.0.0:8444}"
    . /app/masque-bind.sh
    masque_bind="$(resolve_masque_bind "$requested_masque_bind" "$proxy_udp_port" "$mesh_udp_port")"
    if [ "$masque_bind" != "$requested_masque_bind" ]; then
        echo "MASQUE_BIND overlaps a proxy UDP port; moved the relay listener to $masque_bind" >&2
    fi

    if [ "${MASQUE_ALLOW_PRIVATE_TARGETS:-false}" = true ]; then
        /app/netrunner-masque-edge serve \
            --bind "$masque_bind" \
            --cert "$MASQUE_CERT_FILE" \
            --key "$MASQUE_KEY_FILE" \
            --allow-private-targets &
    else
        /app/netrunner-masque-edge serve \
            --bind "$masque_bind" \
            --cert "$MASQUE_CERT_FILE" \
            --key "$MASQUE_KEY_FILE" &
    fi
    masque_pid=$!
    echo "started netrunner-masque-edge as pid $masque_pid on $masque_bind" >&2
fi

/app/netrunner-proxy "$@" &
server_pid=$!
echo "started netrunner-proxy as pid $server_pid" >&2

# Контейнер должен быть перезапущен, если умер любой из двух обязательных для
# выбранной конфигурации процессов. Tini остаётся PID 1 и собирает потомков.
while :; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid" 2>/dev/null || true
        echo "netrunner-proxy exited; stopping container" >&2
        terminate_children
        [ -z "$masque_pid" ] || wait "$masque_pid" 2>/dev/null || true
        exit 1
    fi

    if [ -n "$masque_pid" ] && ! kill -0 "$masque_pid" 2>/dev/null; then
        wait "$masque_pid" 2>/dev/null || true
        echo "netrunner-masque-edge exited; stopping container" >&2
        terminate_children
        wait "$server_pid" 2>/dev/null || true
        exit 1
    fi

    sleep 1
done
