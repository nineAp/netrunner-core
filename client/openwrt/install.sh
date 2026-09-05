#!/bin/sh
set -eu

if [ "$(id -u)" != "0" ]; then
    echo "Запустите installer от root." >&2
    exit 1
fi

BASE_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
EXPECTED_ARCH=$(sed -n '1p' "$BASE_DIR/ARCH")

case "$(uname -m)" in
    x86_64|amd64) ACTUAL_ARCH=x86_64 ;;
    aarch64|arm64) ACTUAL_ARCH=aarch64 ;;
    armv7l|armv7) ACTUAL_ARCH=armv7 ;;
    *) ACTUAL_ARCH=unsupported ;;
esac

if [ "$ACTUAL_ARCH" != "$EXPECTED_ARCH" ]; then
    echo "Архитектура пакета: $EXPECTED_ARCH, устройство: $(uname -m)." >&2
    exit 1
fi

if [ ! -f /etc/openwrt_release ]; then
    echo "Предупреждение: /etc/openwrt_release не найден; это пакет для OpenWrt." >&2
fi

missing=""
for command_name in ip nft; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        missing="$missing $command_name"
    fi
done
if [ -n "$missing" ]; then
    echo "Не найдены команды:$missing" >&2
    echo "OpenWrt 25.12+: apk add kmod-tun ip-full nftables-json ca-bundle" >&2
    echo "OpenWrt 24.10-: opkg update && opkg install kmod-tun ip-full nftables-json ca-bundle" >&2
    exit 1
fi

if [ ! -c /dev/net/tun ]; then
    echo "/dev/net/tun не найден. Установите kmod-tun и загрузите модуль tun." >&2
    exit 1
fi

mkdir -p /usr/bin /etc/netrunner /etc/init.d
cp "$BASE_DIR/netrunner-client" /usr/bin/netrunner-client
chmod 0755 /usr/bin/netrunner-client

if [ ! -e /etc/netrunner/client.toml ]; then
    cp "$BASE_DIR/client.toml.example" /etc/netrunner/client.toml
    chmod 0600 /etc/netrunner/client.toml
    echo "Создан /etc/netrunner/client.toml — заполните адрес, токен и ключи."
else
    echo "Существующий /etc/netrunner/client.toml сохранён."
fi

cp "$BASE_DIR/netrunner.init" /etc/init.d/netrunner
chmod 0755 /etc/init.d/netrunner

# router_mode заворачивает транзитный трафик в netr0, но fw4 об этом интерфейсе
# не знает: цепочка forward у него заканчивается на handle_reject, а
# forward_lan умеет только accept_to_wan/accept_to_lan. netr0 не попадает ни в
# одну зону, поэтому КАЖДОЕ соединение клиента LAN получает RST сразу после
# включения туннеля. Проверять это на голом Linux бесполезно — там fw4 нет,
# ловится только на настоящей OpenWrt (scripts/test-openwrt-qemu.sh).
if command -v uci >/dev/null 2>&1 && [ -f /etc/config/firewall ]; then
    if [ "$(uci -q get firewall.netrunner.device)" = "netr0" ]; then
        echo "Зона firewall 'netrunner' уже настроена."
    else
        uci -q batch <<'FW_EOF'
set firewall.netrunner=zone
set firewall.netrunner.name='netrunner'
set firewall.netrunner.device='netr0'
set firewall.netrunner.input='REJECT'
set firewall.netrunner.output='ACCEPT'
set firewall.netrunner.forward='REJECT'
set firewall.netrunner.masq='0'
set firewall.netrunner.mtu_fix='1'
set firewall.netrunner_from_lan=forwarding
set firewall.netrunner_from_lan.src='lan'
set firewall.netrunner_from_lan.dest='netrunner'
FW_EOF
        uci commit firewall
        /etc/init.d/firewall reload >/dev/null 2>&1 || true
        echo "Добавлена зона firewall 'netrunner' (netr0) и forwarding lan -> netrunner."
        echo "Если LAN-зона называется не 'lan', поправьте firewall.netrunner_from_lan.src."
    fi
else
    echo "Предупреждение: uci/fw4 не найдены — зону для netr0 заведите вручную," >&2
    echo "иначе router_mode будет отбивать транзитный трафик через RST." >&2
fi

echo "Netrunner установлен. После настройки выполните:"
echo "  /etc/init.d/netrunner enable"
echo "  /etc/init.d/netrunner start"
echo "Логи: logread -e netrunner"
