-include .env
# Настройки
SERVER_IP := $(strip $(SERVER_IP))
DEV_IP :=$(strip $(DEV_IP))
REMOTE_USER := $(strip $(REMOTE_USER))
REMOTE_PATH := $(strip $(REMOTE_PATH))
SERVICE_NAME := $(strip $(SERVICE_NAME))

# Безопасное олучение путей из ENV или дефолтов
ANDROID_ADB_HOST := $(strip $(ANDROID_ADB_HOST))
ANDROID_BUILD_SRC := $(strip $(ANDROID_BUILD_SRC))
ANDROID_PROJECT_LIBS := $(strip $(ANDROID_PROJECT_LIBS))

# Дев-авторизация прокси (см. netrunner-proxy/.env) — секрет общий с
# netrunner-backend/.env.dev, адрес — дев-стек backend (make dev там).
PROXY_INTERNAL_SECRET := $(strip $(PROXY_INTERNAL_SECRET))
DEV_BACKEND_URL := $(strip $(DEV_BACKEND_URL))
# Опции для стабильного SSH/Rsync в условиях плохого коннекта
# IPQoS=throughput помогает проталкивать пакеты через тайские магистрали
SSH_OPTS = -o IPQoS=throughput -o ServerAliveInterval=30
RSYNC_OPTS = -avz --inplace --progress -e "ssh $(SSH_OPTS)"


.PHONY: debug-client debug-server build-android build-server deploy-server logs ssh setup-server release-all

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
	cargo build --bin netrunner-client
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

ABIS = arm64-v8a armeabi-v7a x86_64 x86

build-android:
	@for abi in $(ABIS); do \
		echo "Building for $$abi..."; \
		cargo ndk -t $$abi -o ./gen build --bin netrunner-client --release; \
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

build-server:
	@echo "--- Сборка сервера (Release) ---"
	cargo build --bin netrunner-server --release 

setup-server:
	@echo "--- Подготовка сервера ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP) "\
		apt-get update && \
		apt-get install -y build-essential libssl-dev pkg-config rsync && \
		mkdir -p $(REMOTE_PATH)"

# Деплой с использованием rsync и принудительной очисткой
deploy-server: build-server
	@echo "--- [1/4] Остановка сервиса и очистка зависших процессов ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP) "\
		systemctl stop $(SERVICE_NAME) || true; \
		pkill -9 $(SERVICE_NAME) || true; \
		rm -f $(REMOTE_PATH)/$(SERVICE_NAME).tmp"
	
	@echo "--- [2/4] Копирование бинарника (rsync) ---"
	rsync $(RSYNC_OPTS) target/release/netrunner-server $(REMOTE_USER)@$(SERVER_IP):$(REMOTE_PATH)/
	
	@echo "--- [3/4] Обновление конфигурации systemd ---"
	rsync $(RSYNC_OPTS) server/netrunner-server.service $(REMOTE_USER)@$(SERVER_IP):/etc/systemd/system/
	
	@echo "--- [4/4] Перезапуск сервиса ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP) "\
		systemctl daemon-reload && \
		systemctl enable $(SERVICE_NAME) && \
		systemctl start $(SERVICE_NAME)"
	@echo "--- Деплой завершен успешно! ---"


deploy-dev: build-server
	@echo "--- [1/4] Остановка сервиса и очистка зависших процессов DEV ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(DEV_IP) "\
		systemctl stop $(SERVICE_NAME) || true; \
		pkill -9 $(SERVICE_NAME) || true; \
		rm -f $(REMOTE_PATH)/$(SERVICE_NAME).tmp"
	
	@echo "--- [2/4] Копирование бинарника (rsync) ---"
	rsync $(RSYNC_OPTS) target/release/netrunner-server $(REMOTE_USER)@$(DEV_IP):$(REMOTE_PATH)/
	
	@echo "--- [3/4] Обновление конфигурации systemd ---"
	# Локальный файл называется *.dev.service (чтобы не путать с прод-юнитом в
	# репозитории), но systemctl start $(SERVICE_NAME) ищет ровно
	# "$(SERVICE_NAME).service" — без явного целевого имени rsync клал файл
	# под своим исходным именем, и юнит с новым портом/конфигом никогда не
	# подхватывался (systemctl тихо продолжал использовать старый файл).
	rsync $(RSYNC_OPTS) server/netrunner-server.dev.service $(REMOTE_USER)@$(DEV_IP):/etc/systemd/system/$(SERVICE_NAME).service
	
	@echo "--- [4/4] Перезапуск сервиса ---"
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(DEV_IP) "\
		systemctl daemon-reload && \
		systemctl enable $(SERVICE_NAME) && \
		systemctl start $(SERVICE_NAME)"
	@echo "--- Деплой завершен успешно! ---"

logs:
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP) "journalctl -u $(SERVICE_NAME) -f"

ssh:
	ssh $(SSH_OPTS) $(REMOTE_USER)@$(SERVER_IP)
