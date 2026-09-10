-include .env
# Настройки
SERVER_IP := $(strip $(SERVER_IP))
DEV_IP :=$(strip $(DEV_IP))
REMOTE_USER := $(strip $(REMOTE_USER))
REMOTE_PATH := $(strip $(REMOTE_PATH))
SERVICE_NAME := $(strip $(SERVICE_NAME))
MASQUE_SERVICE_NAME ?= netrunner-masque-edge
MASQUE_SERVICE_NAME := $(strip $(MASQUE_SERVICE_NAME))

# Безопасное олучение путей из ENV или дефолтов
ANDROID_ADB_HOST := $(strip $(ANDROID_ADB_HOST))
ANDROID_BUILD_SRC := $(strip $(ANDROID_BUILD_SRC))
ANDROID_PROJECT_LIBS := $(strip $(ANDROID_PROJECT_LIBS))
# Соседний с jniLibs каталог (.../src/main/java/uniffi), куда Kotlin-плагин
# netrunner-app реально ждёт biндинги (jniLibs — для .so, Gradle не собирает
# из него .kt) — см. комментарий у build-android ниже.
ANDROID_PROJECT_JAVA_UNIFFI := $(dir $(ANDROID_PROJECT_LIBS))java/uniffi

# Дев-авторизация прокси (см. netrunner-proxy/.env) — секрет общий с
# netrunner-backend/.env.dev, адрес — дев-стек backend (make dev там).
PROXY_INTERNAL_SECRET := $(strip $(PROXY_INTERNAL_SECRET))
DEV_BACKEND_URL := $(strip $(DEV_BACKEND_URL))
# Опции для стабильного SSH/Rsync в условиях плохого коннекта
# IPQoS=throughput помогает проталкивать пакеты через тайские магистрали
SSH_OPTS = -o IPQoS=throughput -o ServerAliveInterval=30
RSYNC_OPTS = -avz --inplace --progress -e "ssh $(SSH_OPTS)"


.PHONY: debug-client debug-server local-server build-android build-openwrt test-router-wsl test-openwrt-qemu build-server build-edge deploy-server deploy-dev logs logs-masque ssh setup-server release-all

# --- Релизный цикл ---
# --- Релизный цикл ---
release-all: build-server deploy-server build-android
	@echo "--- [Android] Проверка путей ---"
	@if [ ! -d "$(ANDROID_BUILD_SRC)" ]; then echo "Ошибка: Директория сборки $(ANDROID_BUILD_SRC) не найдена!"; exit 1; fi
	
	@echo "--- [Android] Синхронизация библиотек в проект ---"
	@mkdir -p $(ANDROID_PROJECT_LIBS)
	# Используем rsync локально: это безопаснее и быстрее, чем cp -r
	# Удалит в jniLibs всё, чего нет в gen, чтобы билд был чистым
	rsync -av "$(ANDROID_BUILD_SRC)/" "$(ANDROID_PROJECT_LIBS)/"
	
	@echo "--- [ADB] Подключение к устройству ---"
	@if [ -z "$(port)" ]; then \
		echo "Ошибка: укажите порт, например: make release-all port=5555"; \
		exit 1; \
	fi
	adb connect $(ANDROID_ADB_HOST):$(port)
	@echo "--- Релиз полностью завершен ---"
 

debug-client:
	@echo "--- Сборка клиента (Debug) ---"
	cargo build --features cli --bin netrunner-client
	@echo "--- Применение прав ---"
	sudo setcap cap_net_admin,cap_net_raw,cap_dac_override=eip ./target/debug/netrunner-client
	@echo "--- Запуск клиента ---"
	sudo RUST_LOG=warn,netrunner_client=trace ./target/debug/netrunner-client

debug-server:
	@echo "--- Сборка сервера (Debug) ---"
	cargo build --bin netrunner-server
	@echo "--- Запуск сервера локально (с авторизацией против дев-бэкенда) ---"
	sudo PROXY_INTERNAL_SECRET=$(PROXY_INTERNAL_SECRET) ./target/debug/netrunner-server \
		--port=8443 --host=0.0.0.0 \
		--require-auth --backend-url $(DEV_BACKEND_URL)

# Анонимный (v2, без --require-auth и без бэкенда) сервер на LAN — не трогает
# ни прод-, ни дев-инфру. Совпадает по режиму хендшейка со статическими
# узлами netrunner-app (nrxpSecret/nrxpPublicKey: null, см. STATIC_NODES в
# useNodesStore.ts и build-android-arm64-local в netrunner-app/Makefile) —
# существует именно для связки с ними, чтобы гонять новую UDP-ногу под
# отладочным логом, не дожидаясь выкладки на реальную ноду. --decoy-host не
# указан нарочно — дефолт (www.debian.org, см. server/src/main.rs) совпадает
# с SNI, который для локального узла ждёт netrunner-app.
LOCAL_SERVER_PORT ?= 8443
local-server:
	@echo "--- Локальный анонимный сервер: 0.0.0.0:$(LOCAL_SERVER_PORT) ---"
	@echo "--- IP этой машины в LAN (вписать в VITE_LOCAL_NODE_IP на стороне netrunner-app): ---"
	@ip -4 -o addr show scope global | awk '{print "    " $$4}' | cut -d/ -f1
	RUST_LOG=debug,netrunner_core=trace cargo run --bin netrunner-server -- \
		--port=$(LOCAL_SERVER_PORT) --host=0.0.0.0

ABIS = arm64-v8a armeabi-v7a x86_64 x86

# ВАЖНО: `--bin netrunner-client` (как было раньше) НЕ собирает cdylib вообще —
# client/src/main.rs это отдельная, самодостаточная точка входа (свой mod net;
# mod tun;, не `use netrunner_client::...`), поэтому `cargo build --bin X`
# компилирует ТОЛЬКО бинарь и не выпускает libnetrunner_client.so (проверено
# напрямую: `cargo build --bin netrunner-client --release` не создаёт .so,
# `cargo build --lib` — создаёт). Именно эта команда должна была собирать
# либы для мобилки, а на деле никогда их не производила. `-p` x2 + `--lib`
# собирает ИМЕННО библиотеки (netrunner-client И netrunner-logger — оба
# отдельные cdylib, второй сам по себе не строится просто как транзитивная
# зависимость первого), без бесполезной для мобилки Linux-десктопной CLI.
build-android:
	@for abi in $(ABIS); do \
		echo "Building for $$abi..."; \
		cargo ndk -t $$abi -o ./gen build --release -p netrunner-client -p netrunner-logger --lib; \
	done
	cargo run --bin bindgen-tool generate \
		--library gen/arm64-v8a/libnetrunner_client.so \
		--language kotlin \
		--no-format \
		--out-dir gen

	@echo "--- [Android] Синхронизация библиотек в проект ---"
	@mkdir -p $(ANDROID_PROJECT_LIBS)
	# Используем rsync локально: это безопаснее и быстрее, чем cp -r
	# Удалит в jniLibs всё, чего нет в gen, чтобы билд был чистым
	rsync -av "$(ANDROID_BUILD_SRC)/" "$(ANDROID_PROJECT_LIBS)/"

	# jniLibs/uniffi/... (выше) — не то же самое, что реально собирает Gradle:
	# jniLibs — каталог для ПРЕДСОБРАННЫХ .so, Kotlin-исходники из него не
	# компилируются. VpnPlugin.kt импортирует биндинги из java/uniffi/ —
	# отдельного каталога, который эта цель раньше не трогала вообще (в
	# отличие от fetch-client-libs.mjs в netrunner-app, который всегда
	# раскладывал скачанный пакет в оба места). Без этого шага здесь остаётся
	# старый .kt — при разошедшейся FFI-сигнатуре Kotlin не компилируется
	# ("Unresolved reference: SessionParams" и т.п.), а не просто использует
	# старый код. --delete: здесь нет ничего, кроме сгенерированного,
	# vs. jniLibs-рsync выше, который трогать не стал — не хотелось менять
	# поведение шага, не имеющего отношения к найденному багу.
	@mkdir -p $(ANDROID_PROJECT_JAVA_UNIFFI)
	rsync -av --delete "$(ANDROID_BUILD_SRC)/uniffi/" "$(ANDROID_PROJECT_JAVA_UNIFFI)/"

build-server:
	@echo "--- Сборка серверных бинарников (Release) ---"
	cargo build --release -p netrunner-server -p netrunner-masque-edge

# Локальная сборка одного статического OpenWrt-архива. Пример:
#   make build-openwrt OPENWRT_TARGET=aarch64-unknown-linux-musl
OPENWRT_TARGET ?= x86_64-unknown-linux-musl
build-openwrt:
	@command -v cargo-zigbuild >/dev/null || { echo "Установите cargo-zigbuild: cargo install --locked cargo-zigbuild --version 0.23.3"; exit 1; }
	@case "$(OPENWRT_TARGET)" in \
		x86_64-unknown-linux-musl) arch=x86_64 ;; \
		aarch64-unknown-linux-musl) arch=aarch64 ;; \
		armv7-unknown-linux-musleabihf) arch=armv7 ;; \
		*) echo "Неподдерживаемый OPENWRT_TARGET=$(OPENWRT_TARGET)"; exit 1 ;; \
	esac; \
	cargo zigbuild --locked --release -p netrunner-client --features cli --bin netrunner-client --target "$(OPENWRT_TARGET)"; \
	sh scripts/package-openwrt-client.sh "target/$(OPENWRT_TARGET)/release/netrunner-client" "$$arch" dist-openwrt

# Полный router-mode тест в изолированных Linux network namespace. По умолчанию
# использует быстрый native debug-бинарник. Точный x86_64 musl-бинарник можно
# проверить так:
#   make build-openwrt OPENWRT_TARGET=x86_64-unknown-linux-musl
#   make test-router-wsl ROUTER_CLIENT_BIN=target/x86_64-unknown-linux-musl/release/netrunner-client
ROUTER_CLIENT_BIN ?= target/debug/netrunner-client
test-router-wsl:
	cargo build --locked -p netrunner-server --bin netrunner-server
	@if [ "$(ROUTER_CLIENT_BIN)" = "target/debug/netrunner-client" ]; then \
		cargo build --locked -p netrunner-client --features cli --bin netrunner-client; \
	fi
	sh scripts/test-router-wsl.sh "$(ROUTER_CLIENT_BIN)" target/debug/netrunner-server

# Тот же router-mode сценарий, но внутри настоящей OpenWrt в QEMU: проверяет
# то, чего netns-стенд не видит в принципе — musl-бинарник на musl-системе,
# install.sh, procd-сервис, opkg/apk-зависимости и сосуществование с fw4.
#   make test-openwrt-qemu OPENWRT_VERSION=24.10.8
OPENWRT_VERSION ?= 25.12.5
test-openwrt-qemu:
	cargo build --locked -p netrunner-server --bin netrunner-server
	$(MAKE) build-openwrt OPENWRT_TARGET=x86_64-unknown-linux-musl
	OPENWRT_VERSION=$(OPENWRT_VERSION) sh scripts/test-openwrt-qemu.sh \
		dist-openwrt/netrunner-client-openwrt-x86_64.tar.gz \
		target/debug/netrunner-server

# Сборка wasm-клиента для Cloudflare Workers (client-edge/) — тот же
# worker-build, что и wrangler.toml::[build].command запускает сам при
# `wrangler deploy`, только локально, без деплоя, чтобы проверить, что
# крейт вообще собирается. worker-build сам находит .cargo/config.toml с
# нужным `getrandom_backend="wasm_js"` и кладёт shim.mjs в client-edge/build/.
build-edge:
	@echo "--- Сборка edge-клиента (Cloudflare Workers, wasm32) ---"
	@# Раньше проверялось только "command -v worker-build" (бинарь ЕСТЬ), а не
	@# версия — если worker-build 0.8.x стоит глобально (например, для другого
	@# проекта или после `cargo install worker-build` без пина), сборка тут
	@# падает на "Unsupported version worker@0.6.7" / конфликте wasm-bindgen,
	@# потому что этот крейт закреплён на worker=0.6 + wasm-bindgen=0.2.105
	@# (см. комментарий в client-edge/Cargo.toml) — схему бандлера worker-build
	@# 0.1.x. Проверяем ИМЕННО версию, не только факт установки.
	@cargo install --list | grep -q '^worker-build v0\.1\.' || cargo install -q worker-build --version ^0.1 --force
	cd client-edge && worker-build --release

setup-server:
	@echo "--- Подготовка сервера ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP) "\
		apt-get update && \
		apt-get install -y build-essential libssl-dev pkg-config rsync && \
		mkdir -p $(REMOTE_PATH) /etc/netrunner"
	@echo "MASQUE включится после создания /etc/netrunner/masque-edge.env (пример: server/masque-edge.env.example)."

# Деплой с использованием rsync и принудительной очисткой
deploy-server: build-server
	@echo "--- [1/4] Остановка сервиса и очистка зависших процессов ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP) "\
		systemctl stop $(MASQUE_SERVICE_NAME) || true; \
		systemctl stop $(SERVICE_NAME) || true; \
		pkill -9 $(SERVICE_NAME) || true; \
		rm -f $(REMOTE_PATH)/$(SERVICE_NAME).tmp $(REMOTE_PATH)/$(MASQUE_SERVICE_NAME).tmp"
	
	@echo "--- [2/4] Копирование серверных бинарников (rsync) ---"
	rsync $(RSYNC_OPTS) target/release/netrunner-server target/release/netrunner-masque-edge $(REMOTE_USER)@$(SERVER_IP):$(REMOTE_PATH)/
	
	@echo "--- [3/4] Обновление конфигурации systemd ---"
	rsync $(RSYNC_OPTS) server/netrunner-server.service server/netrunner-masque-edge.service $(REMOTE_USER)@$(SERVER_IP):/etc/systemd/system/
	
	@echo "--- [4/4] Перезапуск сервисов ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP) "\
		systemctl daemon-reload && \
		systemctl enable $(SERVICE_NAME) && \
		systemctl enable $(MASQUE_SERVICE_NAME) && \
		systemctl start $(SERVICE_NAME) && \
		systemctl start $(MASQUE_SERVICE_NAME) && \
		systemctl is-active --quiet $(SERVICE_NAME) && \
		(systemctl is-active --quiet $(MASQUE_SERVICE_NAME) || test ! -f /etc/netrunner/masque-edge.env)"
	@echo "--- Деплой завершен успешно! ---"


deploy-dev: build-server
	@echo "--- [1/4] Остановка сервиса и очистка зависших процессов DEV ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(DEV_IP) "\
		systemctl stop $(MASQUE_SERVICE_NAME) || true; \
		systemctl stop $(SERVICE_NAME) || true; \
		pkill -9 $(SERVICE_NAME) || true; \
		rm -f $(REMOTE_PATH)/$(SERVICE_NAME).tmp $(REMOTE_PATH)/$(MASQUE_SERVICE_NAME).tmp"
	
	@echo "--- [2/4] Копирование серверных бинарников (rsync) ---"
	rsync $(RSYNC_OPTS) target/release/netrunner-server target/release/netrunner-masque-edge $(REMOTE_USER)@$(DEV_IP):$(REMOTE_PATH)/
	
	@echo "--- [3/4] Обновление конфигурации systemd ---"
	# Локальный файл называется *.dev.service (чтобы не путать с прод-юнитом в
	# репозитории), но systemctl start $(SERVICE_NAME) ищет ровно
	# "$(SERVICE_NAME).service" — без явного целевого имени rsync клал файл
	# под своим исходным именем, и юнит с новым портом/конфигом никогда не
	# подхватывался (systemctl тихо продолжал использовать старый файл).
	rsync $(RSYNC_OPTS) server/netrunner-server.dev.service $(REMOTE_USER)@$(DEV_IP):/etc/systemd/system/$(SERVICE_NAME).service
	rsync $(RSYNC_OPTS) server/netrunner-masque-edge.service $(REMOTE_USER)@$(DEV_IP):/etc/systemd/system/
	
	@echo "--- [4/4] Перезапуск сервисов ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(DEV_IP) "\
		systemctl daemon-reload && \
		systemctl enable $(SERVICE_NAME) && \
		systemctl enable $(MASQUE_SERVICE_NAME) && \
		systemctl start $(SERVICE_NAME) && \
		systemctl start $(MASQUE_SERVICE_NAME) && \
		systemctl is-active --quiet $(SERVICE_NAME) && \
		(systemctl is-active --quiet $(MASQUE_SERVICE_NAME) || test ! -f /etc/netrunner/masque-edge.env)"
	@echo "--- Деплой завершен успешно! ---"

logs:
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP) "journalctl -u $(SERVICE_NAME) -f"

logs-masque:
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP) "journalctl -u $(MASQUE_SERVICE_NAME) -f"

ssh:
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP)
