#!/bin/sh
# End-to-end проверка router_mode без OpenWrt и без изменения маршрутов самой WSL.
#
# Топология живёт в двух временных network namespace:
#
#   LAN (192.168.250.2) -> router/lan0 -> router/wan0 -> WSL host
#                                                     |-> Netrunner server
#                                                     `-> test HTTP address
#
# До запуска VPN HTTP-сервер видит адрес LAN-клиента. Через VPN исходящее
# соединение создаёт Netrunner server, поэтому HTTP-сервер видит адрес WSL-host.
# Это позволяет отличить реальный проход через туннель от случайно работающего
# прямого forwarding-маршрута.

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CLIENT_BIN=${1:-"$ROOT_DIR/target/debug/netrunner-client"}
SERVER_BIN=${2:-"$ROOT_DIR/target/debug/netrunner-server"}

ROUTER_NS="nr-router-$$"
LAN_NS="nr-lan-$$"
WAN_HOST_IF="nrwh$$"
WAN_ROUTER_IF="nrwr$$"
LAN_ROUTER_IF="nrlr$$"
LAN_CLIENT_IF="nrlc$$"

WAN_HOST_IP=198.18.0.1
WAN_ROUTER_IP=198.18.0.2
LAN_ROUTER_IP=192.168.250.1
LAN_CLIENT_IP=192.168.250.2
INET_SERVER_IP=203.0.113.80
PROXY_PORT=18443
HTTP_PORT=18080

LAB_TMP=$(mktemp -d /tmp/netrunner-router-lab.XXXXXX)
CLIENT_CONFIG="$LAB_TMP/client.toml"
CLIENT_LOG="$LAB_TMP/client.log"
SERVER_LOG="$LAB_TMP/server.log"
HTTP_LOG="$LAB_TMP/http.log"

CLIENT_PID=""
SERVER_PID=""
HTTP_PID=""
TEST_SUCCEEDED=0

say() {
    printf '\n[%s] %s\n' "router-lab" "$*"
}

show_logs() {
    for log_file in "$CLIENT_LOG" "$SERVER_LOG" "$HTTP_LOG"; do
        if [ -s "$log_file" ]; then
            printf '\n--- %s ---\n' "$log_file" >&2
            tail -n 120 "$log_file" >&2
        fi
    done
}

stop_namespace_processes() {
    namespace=$1
    if sudo ip netns list | grep -q "^$namespace[[:space:]]"; then
        for namespace_pid in $(sudo ip netns pids "$namespace" 2>/dev/null); do
            sudo kill -TERM "$namespace_pid" 2>/dev/null || true
        done
    fi
}

cleanup() {
    status=$?
    trap - EXIT INT TERM
    set +e

    if [ -n "$CLIENT_PID" ]; then
        sudo kill -TERM "$CLIENT_PID" 2>/dev/null || true
    fi
    if [ -n "$SERVER_PID" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$HTTP_PID" ]; then
        kill -TERM "$HTTP_PID" 2>/dev/null || true
    fi

    stop_namespace_processes "$ROUTER_NS"
    stop_namespace_processes "$LAN_NS"

    sudo ip route del 192.168.250.0/24 via "$WAN_ROUTER_IP" dev "$WAN_HOST_IF" 2>/dev/null || true
    sudo ip addr del "$INET_SERVER_IP/32" dev lo 2>/dev/null || true
    sudo ip netns del "$LAN_NS" 2>/dev/null || true
    sudo ip netns del "$ROUTER_NS" 2>/dev/null || true
    sudo ip link del "$WAN_HOST_IF" 2>/dev/null || true

    if [ "$status" -ne 0 ] || [ "$TEST_SUCCEEDED" -ne 1 ]; then
        show_logs
        printf '\nСтенд удалён; логи сохранены: %s\n' "$LAB_TMP" >&2
    else
        rm -rf -- "$LAB_TMP"
    fi

    exit "$status"
}
trap cleanup EXIT INT TERM

fail() {
    printf '\nОШИБКА: %s\n' "$*" >&2
    exit 1
}

for command_name in sudo ip nft python3 curl grep tail; do
    command -v "$command_name" >/dev/null 2>&1 || fail "не найдена команда $command_name"
done

sudo -n true 2>/dev/null || fail "нужен passwordless sudo; сначала выполните sudo -v"
[ -c /dev/net/tun ] || fail "/dev/net/tun отсутствует в этой WSL"
[ -x "$CLIENT_BIN" ] || fail "клиент не найден: $CLIENT_BIN"
[ -x "$SERVER_BIN" ] || fail "сервер не найден: $SERVER_BIN"

"$CLIENT_BIN" --version >/dev/null 2>&1 || fail "клиент не запускается: $CLIENT_BIN"
"$SERVER_BIN" --version >/dev/null 2>&1 || fail "сервер не запускается: $SERVER_BIN"

say "Создаю изолированную WAN/LAN-топологию"
sudo ip netns add "$ROUTER_NS"
sudo ip netns add "$LAN_NS"

sudo ip link add "$WAN_HOST_IF" type veth peer name "$WAN_ROUTER_IF"
sudo ip link set "$WAN_ROUTER_IF" netns "$ROUTER_NS"
sudo ip link add "$LAN_ROUTER_IF" type veth peer name "$LAN_CLIENT_IF"
sudo ip link set "$LAN_ROUTER_IF" netns "$ROUTER_NS"
sudo ip link set "$LAN_CLIENT_IF" netns "$LAN_NS"

sudo ip addr add "$WAN_HOST_IP/30" dev "$WAN_HOST_IF"
sudo ip link set "$WAN_HOST_IF" up
sudo ip addr add "$INET_SERVER_IP/32" dev lo

sudo ip -n "$ROUTER_NS" link set lo up
sudo ip -n "$ROUTER_NS" link set "$WAN_ROUTER_IF" name wan0
sudo ip -n "$ROUTER_NS" addr add "$WAN_ROUTER_IP/30" dev wan0
sudo ip -n "$ROUTER_NS" link set wan0 up
sudo ip -n "$ROUTER_NS" link set "$LAN_ROUTER_IF" name lan0
sudo ip -n "$ROUTER_NS" addr add "$LAN_ROUTER_IP/24" dev lan0
sudo ip -n "$ROUTER_NS" link set lan0 up
sudo ip -n "$ROUTER_NS" route add default via "$WAN_HOST_IP"

sudo ip -n "$LAN_NS" link set lo up
sudo ip -n "$LAN_NS" link set "$LAN_CLIENT_IF" name eth0
sudo ip -n "$LAN_NS" addr add "$LAN_CLIENT_IP/24" dev eth0
sudo ip -n "$LAN_NS" link set eth0 up
sudo ip -n "$LAN_NS" route add default via "$LAN_ROUTER_IP"

sudo ip route add 192.168.250.0/24 via "$WAN_ROUTER_IP" dev "$WAN_HOST_IF"
sudo ip netns exec "$ROUTER_NS" sysctl -q -w net.ipv4.ip_forward=1 >/dev/null

say "Запускаю контрольный HTTP-сервер и локальный Netrunner server"
python3 -u -c '
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("source=" + self.client_address[0] + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s %s" % (self.client_address[0], fmt % args), flush=True)

ThreadingHTTPServer(("203.0.113.80", 18080), Handler).serve_forever()
' >"$HTTP_LOG" 2>&1 &
HTTP_PID=$!

RUST_LOG=info "$SERVER_BIN" \
    --host "$WAN_HOST_IP" \
    --port "$PROXY_PORT" \
    --decoy-host www.debian.org \
    >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

lan_curl() {
    sudo ip netns exec "$LAN_NS" curl \
        --noproxy '*' --silent --show-error --fail \
        --connect-timeout 1 --max-time 2 \
        "http://$INET_SERVER_IP:$HTTP_PORT/"
}

wait_for_response() {
    expected=$1
    attempts=0
    while [ "$attempts" -lt 40 ]; do
        response=$(lan_curl 2>/dev/null || true)
        if [ "$response" = "$expected" ]; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.25
    done
    return 1
}

wait_for_response "source=$LAN_CLIENT_IP" || fail "не работает контрольный прямой LAN-маршрут"
say "OK: до VPN HTTP видит LAN source=$LAN_CLIENT_IP"

cat >"$CLIENT_CONFIG" <<EOF
remote_address = "$WAN_HOST_IP:$PROXY_PORT"
sni = "www.debian.org"
auth_token = ""
node_secret = ""
node_public_key = ""
cache_dir = "$LAB_TMP/cache"
mtu = 1450
killswitch_enabled = true
log_level = "info"
tunnel_mode = "bypass_lan"
excluded_uids = []
excluded_domains = []
routed_cidrs = []
router_mode = true
lan_interfaces = ["lan0"]
EOF

start_client() {
    : >"$CLIENT_LOG"
    sudo ip netns exec "$ROUTER_NS" env RUST_LOG=info \
        "$CLIENT_BIN" --config "$CLIENT_CONFIG" \
        >"$CLIENT_LOG" 2>&1 &
    CLIENT_PID=$!
}

say "Запускаю router_mode и проверяю реальный проход через туннель"
start_client
wait_for_response "source=$INET_SERVER_IP" || fail "LAN HTTP не прошёл через Netrunner tunnel"
sudo ip netns exec "$ROUTER_NS" nft list table ip netrunner >/dev/null 2>&1 \
    || fail "таблица nftables netrunner не создана"
sudo ip -n "$ROUTER_NS" link show netr0 >/dev/null 2>&1 \
    || fail "TUN netr0 не создан"
say "OK: через VPN HTTP видит server-side source=$INET_SERVER_IP"

say "Имитирую аварийное падение клиента и проверяю killswitch"
sudo kill -KILL "$CLIENT_PID"
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

attempts=0
while sudo ip -n "$ROUTER_NS" link show netr0 >/dev/null 2>&1 && [ "$attempts" -lt 20 ]; do
    attempts=$((attempts + 1))
    sleep 0.1
done

sudo ip netns exec "$ROUTER_NS" nft list table ip netrunner >/dev/null 2>&1 \
    || fail "после crash исчезла fail-closed nftables-таблица"
sudo ip -n "$ROUTER_NS" route show table 100 | grep -q '^unreachable default' \
    || fail "после crash отсутствует unreachable fallback в table 100"

if lan_curl >/dev/null 2>&1; then
    fail "killswitch допустил прямую утечку после crash"
fi
say "OK: после SIGKILL прямой трафик не утёк"

say "Перезапускаю клиент поверх оставшихся правил"
start_client
wait_for_response "source=$INET_SERVER_IP" || fail "клиент не восстановился после crash/restart"
say "OK: повторный запуск идемпотентно восстановил tunnel"

say "Останавливаю клиент штатно и проверяю cleanup"
sudo kill -TERM "$CLIENT_PID"

attempts=0
while sudo kill -0 "$CLIENT_PID" 2>/dev/null && [ "$attempts" -lt 100 ]; do
    attempts=$((attempts + 1))
    sleep 0.1
done
if sudo kill -0 "$CLIENT_PID" 2>/dev/null; then
    fail "клиент не завершился по SIGTERM за 10 секунд"
fi
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

if sudo ip netns exec "$ROUTER_NS" nft list table ip netrunner >/dev/null 2>&1; then
    fail "после штатной остановки осталась nftables-таблица"
fi
if sudo ip -n "$ROUTER_NS" rule show | grep -q 'fwmark 0x1 lookup 100'; then
    fail "после штатной остановки осталось policy rule"
fi
wait_for_response "source=$LAN_CLIENT_IP" || fail "после cleanup не вернулся прямой LAN-маршрут"
say "OK: SIGTERM очистил routing, прямой маршрут восстановлен"

TEST_SUCCEEDED=1
say "Все router-mode проверки пройдены"
