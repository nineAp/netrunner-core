# Netrunner client для OpenWrt

Архив содержит статический musl-бинарник, пример TOML-конфига и сервис
`procd`. Поддерживаемые CI-архитектуры: `x86_64`, `aarch64`, `armv7`.
MIPS пока не собирается.

После успешного CI архивы лежат в generic package
`netrunner-client-openwrt@latest`. Например, ARM64:

```sh
wget -O /tmp/netrunner-openwrt.tar.gz \
  https://gitea.netrunner-vpn.com/api/packages/nineap/generic/netrunner-client-openwrt/latest/netrunner-client-openwrt-aarch64.tar.gz
```

## Установка

```sh
tar -xzf netrunner-client-openwrt-<arch>.tar.gz
cd netrunner-client-openwrt-<arch>
./install.sh
vi /etc/netrunner/client.toml
/etc/init.d/netrunner enable
/etc/init.d/netrunner start
logread -e netrunner
```

Нужны `kmod-tun`, полный `ip` и CA bundle (его читает `rustls-platform-verifier`
при обращении к control-plane). `nft` на стоковой OpenWrt уже стоит вместе с
fw4; отдельный `nftables-json` клиенту не нужен — он вызывает только текстовые
`nft add ...`. Installer проверяет пользовательские команды, но пакеты
автоматически не меняет.

Зато installer **меняет конфиг firewall**: заводит зону `netrunner` для
устройства `netr0` и forwarding `lan -> netrunner`. Без этого `router_mode`
не работает вообще: fw4 заканчивает цепочку `forward` на `handle_reject`, а
`forward_lan` умеет только `accept_to_wan`/`accept_to_lan`, поэтому транзитный
трафик, уже завёрнутый в туннель, отбивается RST — клиент LAN видит
«Connection refused». Если LAN-зона называется не `lan`, поправьте
`firewall.netrunner_from_lan.src`.

`router_mode = true` перехватывает IPv4 с перечисленных `lan_interfaces`.
Пока туннель работает, транзитный IPv6 блокируется, чтобы он не обходил VPN.
Режим `resources` для роутера пока намеренно запрещён; доступны `all` и
`bypass_lan`.

Клиент не выполняет логин в control-plane самостоятельно: `auth_token`,
`node_secret`, `node_public_key`, адрес и SNI выбранной ноды должны быть
записаны в `/etc/netrunner/client.toml`. Храните файл с правами `0600`.

## Проверка без OpenWrt-устройства

WSL2/Linux может проверить весь Linux data-plane в изолированных network
namespace, не меняя маршруты основной системы:

```sh
make test-router-wsl
```

Тест поднимает локальный Netrunner server и виртуальные LAN/router,
проверяет прохождение HTTP через TUN, отсутствие утечки после `SIGKILL`,
идемпотентный restart и очистку nftables/policy-routing по `SIGTERM`.

Чтобы прогнать тот же сценарий точным статическим OpenWrt x86_64-бинарником:

```sh
make build-openwrt OPENWRT_TARGET=x86_64-unknown-linux-musl
make test-router-wsl \
  ROUTER_CLIENT_BIN=target/x86_64-unknown-linux-musl/release/netrunner-client
```

## Проверка в настоящей OpenWrt (QEMU)

netns-стенд гоняет data-plane на хостовой glibc-системе без procd и без fw4,
поэтому целый класс проблем он не видит. Полный прогон внутри реальной
OpenWrt x86-64:

```sh
make test-openwrt-qemu
```

Стенд качает официальный образ, кладёт архив внутрь rootfs, поднимает гостя с
тремя интерфейсами (slirp для SSH и пакетов, WAN и LAN на tap) и проверяет:
установку через `install.sh`, запуск musl-бинарника на musl-системе,
зависимости из `apk`/`opkg`, procd-сервис и `logread`, реальный проход
транзитного трафика через туннель, целость правил fw4, killswitch после
`SIGKILL`, идемпотентный рестарт и очистку по `SIGTERM`.

Другая версия — `make test-openwrt-qemu OPENWRT_VERSION=24.10.8` (там `opkg`
вместо `apk`). Нужны `qemu-system-x86_64`, passwordless `sudo` и `/dev/net/tun`.
