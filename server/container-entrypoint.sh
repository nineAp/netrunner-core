#!/bin/sh

# Один контейнер, два независимых сокета:
#   netrunner-proxy       -> TCP/--port (обычно 443)
#   netrunner-masque-edge -> UDP/${MASQUE_BIND:-0.0.0.0:443}
#
# MASQUE включается явно (MASQUE_ENABLED=true) либо автоматически, когда
# одновременно переданы токен, сертификат и ключ. Поэтому обновление образа
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
        if [ -n "${MASQUE_TOKEN:-}" ] && \
           [ -n "${MASQUE_CERT_FILE:-}" ] && \
           [ -n "${MASQUE_KEY_FILE:-}" ]; then
            masque_start=true
        elif [ -n "${MASQUE_TOKEN:-}${MASQUE_CERT_FILE:-}${MASQUE_KEY_FILE:-}" ]; then
            echo "MASQUE configuration is incomplete: token, certificate and key are all required" >&2
            exit 64
        fi
        ;;
    *)
        echo "invalid MASQUE_ENABLED value: $masque_mode" >&2
        exit 64
        ;;
esac

if [ "$masque_start" = true ]; then
    : "${MASQUE_TOKEN:?MASQUE_TOKEN is required when MASQUE is enabled}"
    : "${MASQUE_CERT_FILE:?MASQUE_CERT_FILE is required when MASQUE is enabled}"
    : "${MASQUE_KEY_FILE:?MASQUE_KEY_FILE is required when MASQUE is enabled}"

    if [ ! -r "$MASQUE_CERT_FILE" ]; then
        echo "MASQUE certificate is not readable: $MASQUE_CERT_FILE" >&2
        exit 66
    fi
    if [ ! -r "$MASQUE_KEY_FILE" ]; then
        echo "MASQUE private key is not readable: $MASQUE_KEY_FILE" >&2
        exit 66
    fi

    if [ "${MASQUE_ALLOW_PRIVATE_TARGETS:-false}" = true ]; then
        /app/netrunner-masque-edge serve \
            --bind "${MASQUE_BIND:-0.0.0.0:443}" \
            --cert "$MASQUE_CERT_FILE" \
            --key "$MASQUE_KEY_FILE" \
            --allow-private-targets &
    else
        /app/netrunner-masque-edge serve \
            --bind "${MASQUE_BIND:-0.0.0.0:443}" \
            --cert "$MASQUE_CERT_FILE" \
            --key "$MASQUE_KEY_FILE" &
    fi
    masque_pid=$!
    echo "started netrunner-masque-edge as pid $masque_pid on ${MASQUE_BIND:-0.0.0.0:443}" >&2
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
