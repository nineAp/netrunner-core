#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <binary> <x86_64|aarch64|armv7> <dist-dir>" >&2
    exit 2
fi

BINARY=$1
ARCH=$2
DIST_DIR=$3

case "$ARCH" in
    x86_64|aarch64|armv7) ;;
    *) echo "unsupported package architecture: $ARCH" >&2; exit 2 ;;
esac

[ -f "$BINARY" ] || {
    echo "binary not found: $BINARY" >&2
    exit 1
}

ROOT_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT
PACKAGE_DIR="$STAGING/netrunner-client-openwrt-$ARCH"

mkdir -p "$PACKAGE_DIR" "$DIST_DIR"
cp "$BINARY" "$PACKAGE_DIR/netrunner-client"
cp "$ROOT_DIR/client/openwrt/client.toml.example" "$PACKAGE_DIR/client.toml.example"
cp "$ROOT_DIR/client/openwrt/netrunner.init" "$PACKAGE_DIR/netrunner.init"
cp "$ROOT_DIR/client/openwrt/install.sh" "$PACKAGE_DIR/install.sh"
cp "$ROOT_DIR/client/openwrt/README.md" "$PACKAGE_DIR/README.md"
printf '%s\n' "$ARCH" > "$PACKAGE_DIR/ARCH"
printf '%s\n' "$(git -C "$ROOT_DIR" rev-parse --short HEAD)" > "$PACKAGE_DIR/VERSION"
chmod 0755 "$PACKAGE_DIR/netrunner-client" "$PACKAGE_DIR/install.sh" "$PACKAGE_DIR/netrunner.init"

tar -czf "$DIST_DIR/netrunner-client-openwrt-$ARCH.tar.gz" \
    -C "$STAGING" "netrunner-client-openwrt-$ARCH"
