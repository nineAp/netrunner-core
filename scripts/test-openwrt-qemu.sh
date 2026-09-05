#!/bin/sh
# End-to-end проверка OpenWrt-пакета netrunner-client внутри настоящей OpenWrt
# в QEMU. В отличие от scripts/test-router-wsl.sh (network namespace, хостовая
# glibc-система) здесь проверяется ровно то, что ломается только на железе:
# статический musl-бинарник на musl-системе, install.sh, procd-сервис,
# opkg/apk-зависимости и сосуществование с fw4.
#
# Топология:
#
#   netns nr-qemu-lan (192.168.250.2)
#     └─ veth ─ bridge nrqbr0 ─ tap nrqlan ─ eth2 (br-lan 192.168.250.1)
#                                              [ OpenWrt в QEMU ]
#                                            eth1 (198.18.0.2/30)
#                                              └─ tap nrqwan ─ host 198.18.0.1
#                                                   ├─ netrunner-server :18443
#                                                   └─ «интернет» 203.0.113.80:18080
#                                            eth0 ─ qemu slirp (только SSH + пакеты)
#
# До VPN контрольный HTTP видит адрес роутера (fw4 masquerade), через VPN —
# адрес хоста, на котором сервер открывает исходящее соединение. Это отличает
# реальный проход через туннель от обычного форвардинга.

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

OPENWRT_VERSION=${OPENWRT_VERSION:-25.12.5}
OPENWRT_CACHE=${OPENWRT_CACHE:-"$HOME/.cache/netrunner-openwrt-qemu"}
PACKAGE_TGZ=${1:-"$ROOT_DIR/dist-openwrt/netrunner-client-openwrt-x86_64.tar.gz"}
SERVER_BIN=${2:-"$ROOT_DIR/target/debug/netrunner-server"}

WAN_TAP=nrqwan
LAN_TAP=nrqlan
LAN_BRIDGE=nrqbr0
LAN_VETH_HOST=nrqv0
LAN_VETH_NS=nrqv1
LAN_NS=nr-qemu-lan

WAN_HOST_IP=198.18.0.1
WAN_ROUTER_IP=198.18.0.2
LAN_ROUTER_IP=192.168.250.1
LAN_CLIENT_IP=192.168.250.2
INET_SERVER_IP=203.0.113.80
PROXY_PORT=18443
HTTP_PORT=18080
SSH_PORT=${SSH_PORT:-2222}

MGMT_MAC=52:54:00:4e:52:01
WAN_MAC=52:54:00:4e:52:02
LAN_MAC=52:54:00:4e:52:03

LAB=$(mktemp -d /tmp/netrunner-openwrt-qemu.XXXXXX)
DISK="$LAB/openwrt.img"
SERIAL_LOG="$LAB/serial.log"
SERVER_LOG="$LAB/server.log"
HTTP_LOG="$LAB/http.log"
SSH_KEY="$LAB/id_lab"
MOUNT_DIR="$LAB/mnt"

QEMU_PID=""
SERVER_PID=""
HTTP_PID=""
LOOP_DEV=""
FORWARD_RULE=0
TEST_SUCCEEDED=0
DIRECT_SRC=""

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
-o LogLevel=ERROR -o ConnectTimeout=5 -o ServerAliveInterval=5 \
-o ServerAliveCountMax=3 -o PasswordAuthentication=no"

say() { printf '\n[%s] %s\n' "openwrt-qemu" "$*"; }

vm() { ssh $SSH_OPTS -i "$SSH_KEY" -p "$SSH_PORT" root@127.0.0.1 "$@"; }

# Снимок состояния обеих сторон — без него любое падение приходится
# воспроизводить вручную, а стенд к тому моменту уже разобран.
dump_state() {
    [ -n "$QEMU_PID" ] || return 0
    printf '\n--- guest: ip addr / route / rule ---\n' >&2
    vm 'ip -4 addr show; echo; ip route show; echo; ip rule show; echo;
        ip route show table 100 2>/dev/null; echo "forward=$(cat /proc/sys/net/ipv4/ip_forward)"' >&2 2>&1 || true
    printf '\n--- guest: nft ruleset (заголовки цепочек) ---\n' >&2
    vm 'nft list ruleset 2>&1 | grep -E "^(table|\s+chain|\s+type)" | head -40' >&2 2>&1 || true
    printf '\n--- guest: uci network/firewall zones ---\n' >&2
    vm 'uci show network | grep -vE "ip6|ula"; echo; uci show firewall | grep -E "zone|forwarding"' >&2 2>&1 || true
    printf '\n--- guest: доступность хоста и «интернета» ---\n' >&2
    vm "ping -c2 -W2 $WAN_HOST_IP 2>&1 | tail -3; ping -c2 -W2 $INET_SERVER_IP 2>&1 | tail -3;
        wget -q -T4 -O- http://$INET_SERVER_IP:$HTTP_PORT/ 2>&1 | head -2" >&2 2>&1 || true
    printf '\n--- host: LAN netns ---\n' >&2
    sudo ip netns exec "$LAN_NS" ip -4 addr show >&2 2>&1 || true
    sudo ip netns exec "$LAN_NS" ip route show >&2 2>&1 || true
    sudo ip netns exec "$LAN_NS" ping -c2 -W2 "$LAN_ROUTER_IP" 2>&1 | tail -3 >&2 || true
    printf '\n--- host: линки стенда ---\n' >&2
    ip -brief link show "$WAN_TAP" >&2 2>&1 || true
    ip -brief link show "$LAN_TAP" >&2 2>&1 || true
    ip -brief link show "$LAN_BRIDGE" >&2 2>&1 || true
    ip -4 addr show "$WAN_TAP" >&2 2>&1 || true
}

fail() {
    printf '\nОШИБКА: %s\n' "$*" >&2
    dump_state
    exit 1
}

show_logs() {
    for log_file in "$SERIAL_LOG" "$SERVER_LOG" "$HTTP_LOG"; do
        if [ -s "$log_file" ]; then
            printf '\n--- %s (хвост) ---\n' "$log_file" >&2
            tail -n 60 "$log_file" >&2
        fi
    done
}

cleanup() {
    status=$?
    trap - EXIT INT TERM
    set +e

    # KEEP_UP=1 удерживает стенд после падения: разбирать сетевую проблему
    # по одному снимку дороже, чем зайти в живого гостя.
    if [ "${KEEP_UP:-0}" = "1" ] && [ -n "$QEMU_PID" ]; then
        touch "$LAB/keep"
        printf '\nСтенд удержан. SSH: ssh %s -i %s -p %s root@127.0.0.1\n' \
            "$SSH_OPTS" "$SSH_KEY" "$SSH_PORT" >&2
        printf 'LAN-клиент: sudo ip netns exec %s <cmd>\n' "$LAN_NS" >&2
        printf 'Отпустить:  rm %s/keep\n' "$LAB" >&2
        while [ -f "$LAB/keep" ]; do sleep 2; done
    fi

    [ -n "$QEMU_PID" ] && kill -TERM "$QEMU_PID" 2>/dev/null
    [ -n "$SERVER_PID" ] && kill -TERM "$SERVER_PID" 2>/dev/null
    [ -n "$HTTP_PID" ] && kill -TERM "$HTTP_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && { sleep 1; kill -KILL "$QEMU_PID" 2>/dev/null; }

    mountpoint -q "$MOUNT_DIR" 2>/dev/null && sudo umount "$MOUNT_DIR"
    [ -n "$LOOP_DEV" ] && sudo losetup -d "$LOOP_DEV" 2>/dev/null

    [ "$FORWARD_RULE" = "1" ] && sudo iptables -D FORWARD \
        -i "$LAN_BRIDGE" -o "$LAN_BRIDGE" -j ACCEPT 2>/dev/null

    sudo ip netns del "$LAN_NS" 2>/dev/null
    sudo ip link del "$LAN_VETH_HOST" 2>/dev/null
    sudo ip link del "$LAN_BRIDGE" 2>/dev/null
    sudo ip link del "$LAN_TAP" 2>/dev/null
    sudo ip link del "$WAN_TAP" 2>/dev/null
    sudo ip route del "$LAN_ROUTER_IP/24" 2>/dev/null
    sudo ip route del 192.168.250.0/24 via "$WAN_ROUTER_IP" 2>/dev/null
    sudo ip addr del "$INET_SERVER_IP/32" dev lo 2>/dev/null

    if [ "$status" -ne 0 ] || [ "$TEST_SUCCEEDED" -ne 1 ]; then
        show_logs
        printf '\nСтенд удалён; логи сохранены: %s\n' "$LAB" >&2
    else
        rm -rf -- "$LAB"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- preflight --
for command_name in sudo ip nft python3 curl ssh ssh-keygen qemu-system-x86_64 \
                    gunzip tar losetup parted resize2fs e2fsck mountpoint; do
    command -v "$command_name" >/dev/null 2>&1 || fail "не найдена команда $command_name"
done
sudo -n true 2>/dev/null || fail "нужен passwordless sudo; сначала выполните sudo -v"
[ -c /dev/net/tun ] || fail "/dev/net/tun отсутствует"
[ -f "$PACKAGE_TGZ" ] || fail "не найден пакет: $PACKAGE_TGZ (сначала make build-openwrt)"
[ -x "$SERVER_BIN" ] || fail "не найден сервер: $SERVER_BIN"
"$SERVER_BIN" --version >/dev/null 2>&1 || fail "сервер не запускается: $SERVER_BIN"

ACCEL=tcg
[ -r /dev/kvm ] && [ -w /dev/kvm ] && ACCEL=kvm

# ------------------------------------------------------------------- образ --
IMAGE_NAME="openwrt-$OPENWRT_VERSION-x86-64-generic-ext4-combined.img.gz"
IMAGE_GZ="$OPENWRT_CACHE/$IMAGE_NAME"
IMAGE_URL="https://downloads.openwrt.org/releases/$OPENWRT_VERSION/targets/x86/64"
if [ ! -f "$IMAGE_GZ" ]; then
    say "Скачиваю OpenWrt $OPENWRT_VERSION"
    mkdir -p "$OPENWRT_CACHE"
    curl -sSLf -o "$IMAGE_GZ.part" "$IMAGE_URL/$IMAGE_NAME" \
        || fail "не скачался образ OpenWrt $OPENWRT_VERSION"

    # Битый образ в кэше выглядит как загадочный провал загрузки гостя, поэтому
    # сверяемся с официальной sha256 сразу, а не после десяти минут отладки.
    expected_sum=$(curl -sSLf "$IMAGE_URL/sha256sums" 2>/dev/null \
        | grep " [*]\{0,1\}$IMAGE_NAME\$" | cut -d' ' -f1)
    if [ -n "$expected_sum" ]; then
        actual_sum=$(sha256sum "$IMAGE_GZ.part" | cut -d' ' -f1)
        [ "$expected_sum" = "$actual_sum" ] || {
            rm -f "$IMAGE_GZ.part"
            fail "sha256 образа не сошлась: ждали $expected_sum, получили $actual_sum"
        }
    fi
    mv "$IMAGE_GZ.part" "$IMAGE_GZ"
fi

say "Готовлю диск и записываю пакет внутрь образа"
# OpenWrt паддит .gz до границы блока, поэтому gzip ругается "trailing garbage"
# и выходит с кодом 2 на совершенно корректном официальном образе. Под set -e
# это молча убивало прогон, так что предупреждение отделяем от реальной ошибки.
if ! gunzip -c "$IMAGE_GZ" > "$DISK" 2>"$LAB/gunzip.err"; then
    grep -q 'trailing garbage' "$LAB/gunzip.err" || {
        cat "$LAB/gunzip.err" >&2
        fail "не распаковался образ $IMAGE_GZ"
    }
fi
truncate -s 1G "$DISK"

LOOP_DEV=$(sudo losetup -Pf --show "$DISK")
sudo parted -s "$LOOP_DEV" resizepart 2 100% >/dev/null 2>&1 || true
sudo partprobe "$LOOP_DEV" 2>/dev/null || sudo losetup -c "$LOOP_DEV" 2>/dev/null || true
sudo e2fsck -fy "${LOOP_DEV}p2" >/dev/null 2>&1 || true
sudo resize2fs "${LOOP_DEV}p2" >/dev/null 2>&1 || true

mkdir -p "$MOUNT_DIR"
sudo mount "${LOOP_DEV}p2" "$MOUNT_DIR" || fail "не смонтировался rootfs образа"

ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY" -C netrunner-lab
sudo mkdir -p "$MOUNT_DIR/etc/dropbear" "$MOUNT_DIR/root/pkg"
sudo cp "$SSH_KEY.pub" "$MOUNT_DIR/etc/dropbear/authorized_keys"
sudo chmod 0600 "$MOUNT_DIR/etc/dropbear/authorized_keys"
sudo tar -xzf "$PACKAGE_TGZ" -C "$MOUNT_DIR/root/pkg"

sudo tee "$MOUNT_DIR/etc/uci-defaults/99-netrunner-lab" >/dev/null <<'UCI_EOF'
#!/bin/sh
# Стенд: eth-имена определяем по MAC, чтобы не зависеть от порядка PCI.
mac2if() {
    for path in /sys/class/net/*; do
        [ -e "$path/address" ] || continue
        if [ "$(cat "$path/address")" = "$1" ]; then
            basename "$path"
            return 0
        fi
    done
    return 1
}

MGMT_IF=$(mac2if 52:54:00:4e:52:01)
WAN_IF=$(mac2if 52:54:00:4e:52:02)
LAN_IF=$(mac2if 52:54:00:4e:52:03)

uci -q delete network.lan
uci -q delete network.wan
uci -q delete network.wan6
while uci -q delete network.@device[0]; do :; done

uci set network.lan=interface
uci set network.lan.device='br-lan'
uci set network.lan.proto='static'
uci set network.lan.ipaddr='192.168.250.1'
uci set network.lan.netmask='255.255.255.0'

uci add network device >/dev/null
uci set network.@device[-1].name='br-lan'
uci set network.@device[-1].type='bridge'
uci add_list network.@device[-1].ports="$LAN_IF"

# Шлюз на WAN появится только вторым этапом: сначала пакеты ставим через slirp.
uci set network.wan=interface
uci set network.wan.device="$WAN_IF"
uci set network.wan.proto='static'
uci set network.wan.ipaddr='198.18.0.2'
uci set network.wan.netmask='255.255.255.252'

uci set network.mgmt=interface
uci set network.mgmt.device="$MGMT_IF"
uci set network.mgmt.proto='dhcp'
uci commit network

# mgmt держим в зоне lan, чтобы SSH через slirp принимался; wan остаётся
# честной wan-зоной с masquerade, как на настоящем роутере.
uci -q set firewall.@zone[0].network='lan mgmt'
uci commit firewall

uci set dropbear.@dropbear[0].PasswordAuth='off'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'
uci commit dropbear
exit 0
UCI_EOF
sudo chmod 0755 "$MOUNT_DIR/etc/uci-defaults/99-netrunner-lab"

sudo umount "$MOUNT_DIR"
sudo losetup -d "$LOOP_DEV"
LOOP_DEV=""

# -------------------------------------------------------------- сеть хоста --
say "Поднимаю WAN/LAN-сегменты на хосте"
sudo ip tuntap add dev "$WAN_TAP" mode tap user "$(id -un)"
sudo ip addr add "$WAN_HOST_IP/30" dev "$WAN_TAP"
sudo ip link set "$WAN_TAP" up

sudo ip tuntap add dev "$LAN_TAP" mode tap user "$(id -un)"
sudo ip link add "$LAN_BRIDGE" type bridge
sudo ip link set "$LAN_TAP" master "$LAN_BRIDGE"
sudo ip link set "$LAN_TAP" up
sudo ip link set "$LAN_BRIDGE" up

# На хосте с Docker политика iptables FORWARD — DROP, а br_netfilter гоняет
# бриджованные кадры через эту же цепочку. Без явного ACCEPT LAN-сегмент стенда
# молча мёртв (ARP проходит, IP — нет). Правило скоупим на свой мост.
if command -v iptables >/dev/null 2>&1 &&
   sudo iptables -I FORWARD -i "$LAN_BRIDGE" -o "$LAN_BRIDGE" -j ACCEPT 2>/dev/null; then
    FORWARD_RULE=1
fi

sudo ip netns add "$LAN_NS"
sudo ip link add "$LAN_VETH_HOST" type veth peer name "$LAN_VETH_NS"
sudo ip link set "$LAN_VETH_HOST" master "$LAN_BRIDGE" up
sudo ip link set "$LAN_VETH_NS" netns "$LAN_NS"
sudo ip -n "$LAN_NS" link set lo up
sudo ip -n "$LAN_NS" link set "$LAN_VETH_NS" name eth0
sudo ip -n "$LAN_NS" addr add "$LAN_CLIENT_IP/24" dev eth0
sudo ip -n "$LAN_NS" link set eth0 up
sudo ip -n "$LAN_NS" route add default via "$LAN_ROUTER_IP"

sudo ip addr add "$INET_SERVER_IP/32" dev lo
sudo ip route add 192.168.250.0/24 via "$WAN_ROUTER_IP" dev "$WAN_TAP" 2>/dev/null || true

# ------------------------------------------------------- сервисы на хосте --
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

# Сервер биндится не мгновенно и умеет упасть на AddrInUse уже после строчки
# "Listening" — без этой проверки стенд уходит в тест и падает потом на
# невнятном "не прошёл через туннель".
attempts=0
until ss -ltn 2>/dev/null | grep -q "$WAN_HOST_IP:$PROXY_PORT"; do
    attempts=$((attempts + 1))
    [ "$attempts" -ge 30 ] && fail "netrunner-server не слушает $WAN_HOST_IP:$PROXY_PORT
$(tail -n 5 "$SERVER_LOG" 2>/dev/null)"
    kill -0 "$SERVER_PID" 2>/dev/null || fail "netrunner-server упал при старте
$(tail -n 5 "$SERVER_LOG" 2>/dev/null)"
    sleep 0.5
done
sleep 1
grep -q 'AddrInUse\|bind failed' "$SERVER_LOG" 2>/dev/null \
    && fail "порт $PROXY_PORT занят чужим процессом — остался стенд от прошлого прогона?"

# ------------------------------------------------------------------ запуск --
say "Стартую OpenWrt $OPENWRT_VERSION в QEMU (accel=$ACCEL)"
qemu-system-x86_64 \
    -machine q35 -accel "$ACCEL" -smp 2 -m 512 \
    -display none -monitor none -serial "file:$SERIAL_LOG" \
    -drive "file=$DISK,format=raw,if=ide" \
    -netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
    -device "e1000,netdev=mgmt,mac=$MGMT_MAC" \
    -netdev "tap,id=wan,ifname=$WAN_TAP,script=no,downscript=no" \
    -device "e1000,netdev=wan,mac=$WAN_MAC" \
    -netdev "tap,id=lan,ifname=$LAN_TAP,script=no,downscript=no" \
    -device "e1000,netdev=lan,mac=$LAN_MAC" \
    &
QEMU_PID=$!

say "Жду загрузки и SSH"
attempts=0
until vm true 2>/dev/null; do
    attempts=$((attempts + 1))
    [ "$attempts" -ge 120 ] && fail "OpenWrt не поднялась/недоступна по SSH за 120с"
    kill -0 "$QEMU_PID" 2>/dev/null || fail "QEMU завершился до готовности гостя"
    sleep 1
done
say "OK: гость доступен — $(vm '. /etc/openwrt_release; echo $DISTRIB_DESCRIPTION')"

# --------------------------------------------------------------- зависимости --
say "Ставлю зависимости пакета (kmod-tun, ip-full, ca-bundle)"
if vm 'command -v apk >/dev/null'; then
    PKG_MGR=apk
    vm 'apk update >/dev/null 2>&1 && apk add kmod-tun ip-full ca-bundle' \
        || fail "apk add не установил зависимости"
    NFT_JSON_OK=0
    vm 'apk add nftables-json >/dev/null 2>&1' && NFT_JSON_OK=1
else
    PKG_MGR=opkg
    vm 'opkg update >/dev/null 2>&1 && opkg install kmod-tun ip-full ca-bundle' \
        || fail "opkg install не установил зависимости"
    NFT_JSON_OK=0
    vm 'opkg install nftables-json >/dev/null 2>&1' && NFT_JSON_OK=1
fi
say "OK: пакетный менеджер $PKG_MGR, nftables-json установился: $NFT_JSON_OK"

say "Перевожу default route на тестовый WAN и отключаю slirp-маршрут"
vm "uci set network.wan.gateway='$WAN_HOST_IP'; \
    uci set network.mgmt.defaultroute='0'; \
    uci set network.mgmt.peerdns='0'; \
    uci commit network; /etc/init.d/network restart" >/dev/null 2>&1
sleep 5
attempts=0
until vm "ip route show default | grep -q $WAN_HOST_IP" 2>/dev/null; do
    attempts=$((attempts + 1))
    [ "$attempts" -ge 30 ] && fail "default route не переключился на $WAN_HOST_IP"
    sleep 1
done

# ------------------------------------------------------------------- тесты --
lan_curl() {
    sudo ip netns exec "$LAN_NS" curl \
        --noproxy '*' --silent --show-error --fail \
        --connect-timeout 2 --max-time 4 \
        "http://$INET_SERVER_IP:$HTTP_PORT/"
}

wait_for_response() {
    expected=$1
    attempts=0
    while [ "$attempts" -lt 60 ]; do
        response=$(lan_curl 2>/dev/null || true)
        if [ "$response" = "$expected" ]; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.5
    done
    return 1
}

wait_for_any_response() {
    attempts=0
    while [ "$attempts" -lt 60 ]; do
        response=$(lan_curl 2>/dev/null || true)
        if [ -n "$response" ]; then
            printf '%s' "$response"
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.5
    done
    return 1
}

say "Контрольная проверка: LAN ходит в «интернет» напрямую через роутер"
DIRECT_SRC=$(wait_for_any_response) || fail "LAN-клиент не ходит через OpenWrt даже без VPN"
say "OK: до VPN контрольный HTTP видит $DIRECT_SRC"
[ "$DIRECT_SRC" = "source=$INET_SERVER_IP" ] \
    && fail "прямой маршрут уже даёт server-side адрес — тест не различит туннель"

say "Ставлю пакет штатным install.sh"
vm 'cd /root/pkg/netrunner-client-openwrt-x86_64 && ./install.sh' \
    || fail "install.sh завершился с ошибкой"
vm 'test -x /usr/bin/netrunner-client' || fail "install.sh не положил бинарник"
vm 'test -x /etc/init.d/netrunner' || fail "install.sh не положил procd-сервис"
vm "[ \"\$(uci -q get firewall.netrunner.device)\" = netr0 ]" \
    || fail "install.sh не завёл зону fw4 для netr0 — router_mode будет отбит RST"
vm '/usr/bin/netrunner-client --version' >/dev/null 2>&1 \
    || fail "musl-бинарник не запускается на OpenWrt"
say "OK: $(vm '/usr/bin/netrunner-client --version' 2>&1 | head -1)"

say "Пишу боевой конфиг стенда в /etc/netrunner/client.toml"
vm "cat > /etc/netrunner/client.toml" <<CFG_EOF
remote_address = "$WAN_HOST_IP:$PROXY_PORT"
sni = "www.debian.org"
auth_token = ""
node_secret = ""
node_public_key = ""
cache_dir = "/tmp/netrunner"
mtu = 1450
killswitch_enabled = true
log_level = "info"
tunnel_mode = "bypass_lan"
excluded_uids = []
excluded_domains = []
routed_cidrs = []
router_mode = true
lan_interfaces = ["br-lan"]
CFG_EOF
vm 'chmod 600 /etc/netrunner/client.toml'

say "Проверяю procd-сервис: enable + start"
vm '/etc/init.d/netrunner enable && /etc/init.d/netrunner start'
sleep 3
vm 'pgrep -f netrunner-client >/dev/null' || {
    vm 'logread -e netrunner | tail -40' >&2 2>/dev/null || true
    fail "procd не удержал netrunner-client запущенным"
}
wait_for_response "source=$INET_SERVER_IP" || {
    vm 'logread -e netrunner | tail -40' >&2 2>/dev/null || true
    fail "LAN HTTP не прошёл через туннель при запуске через procd"
}
vm 'nft list table ip netrunner >/dev/null 2>&1' || fail "не создана таблица nftables netrunner"
vm 'ip link show netr0 >/dev/null 2>&1' || fail "не создан TUN netr0"
vm 'nft list table inet fw4 >/dev/null 2>&1' || fail "правила fw4 исчезли — конфликт с firewall OpenWrt"
vm 'logread -e netrunner | grep -q .' || fail "procd не пишет логи клиента в logread"
say "OK: через VPN контрольный HTTP видит source=$INET_SERVER_IP, fw4 цел"

say "Штатная остановка сервиса и проверка cleanup"
vm '/etc/init.d/netrunner stop'
attempts=0
while vm 'pgrep -f netrunner-client >/dev/null' 2>/dev/null && [ "$attempts" -lt 30 ]; do
    attempts=$((attempts + 1))
    sleep 1
done
vm 'pgrep -f netrunner-client >/dev/null' 2>/dev/null \
    && fail "клиент не завершился по SIGTERM от procd за 30с"
vm 'nft list table ip netrunner >/dev/null 2>&1' \
    && fail "после остановки сервиса осталась таблица nftables"
vm "ip rule show | grep -q 'fwmark 0x1 lookup 100'" \
    && fail "после остановки сервиса осталось policy rule"
wait_for_response "$DIRECT_SRC" || fail "после cleanup не вернулся прямой маршрут"
say "OK: procd stop снял routing/nftables, прямой маршрут вернулся"

# Дальше — crash-сценарий без procd: respawn мешает проверять killswitch.
vm '/etc/init.d/netrunner disable'

start_client_raw() {
    vm 'rm -f /tmp/nr.log; \
        start-stop-daemon -S -b -m -p /tmp/nr.pid -x /usr/bin/netrunner-client \
        -- --config /etc/netrunner/client.toml >/dev/null 2>&1' \
    || vm 'nohup /usr/bin/netrunner-client --config /etc/netrunner/client.toml \
           >/tmp/nr.log 2>&1 & echo $! > /tmp/nr.pid'
}

say "Ручной запуск клиента и проверка killswitch после SIGKILL"
start_client_raw
wait_for_response "source=$INET_SERVER_IP" || fail "клиент не поднял туннель при ручном запуске"

vm 'kill -KILL $(cat /tmp/nr.pid)'
attempts=0
while vm 'pgrep -f netrunner-client >/dev/null' 2>/dev/null && [ "$attempts" -lt 20 ]; do
    attempts=$((attempts + 1))
    sleep 0.5
done

vm 'nft list table ip netrunner >/dev/null 2>&1' \
    || fail "после crash исчезла fail-closed таблица nftables"
vm "ip route show table 100 | grep -q '^unreachable default'" \
    || fail "после crash нет unreachable default в table 100"
if lan_curl >/dev/null 2>&1; then
    fail "killswitch допустил прямую утечку LAN-трафика после crash"
fi
say "OK: после SIGKILL LAN-трафик не утёк мимо туннеля"

say "Перезапуск поверх оставшихся правил"
start_client_raw
wait_for_response "source=$INET_SERVER_IP" || fail "клиент не восстановился после crash/restart"
say "OK: повторный запуск идемпотентно восстановил туннель"

say "Штатный SIGTERM и финальный cleanup"
vm 'kill -TERM $(cat /tmp/nr.pid)'
attempts=0
while vm 'pgrep -f netrunner-client >/dev/null' 2>/dev/null && [ "$attempts" -lt 30 ]; do
    attempts=$((attempts + 1))
    sleep 1
done
vm 'pgrep -f netrunner-client >/dev/null' 2>/dev/null \
    && fail "клиент не завершился по SIGTERM за 30с"
vm 'nft list table ip netrunner >/dev/null 2>&1' \
    && fail "после SIGTERM осталась таблица nftables"
wait_for_response "$DIRECT_SRC" || fail "после SIGTERM не вернулся прямой маршрут"
say "OK: SIGTERM очистил routing, прямой маршрут восстановлен"

TEST_SUCCEEDED=1
say "Все проверки на настоящей OpenWrt $OPENWRT_VERSION пройдены (nftables-json: $NFT_JSON_OK)"
