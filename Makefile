# Настройки
SERVER_IP = 62.60.244.156
REMOTE_USER = root
REMOTE_PATH = /root/netr-core
SERVICE_NAME = netrunner-server

.PHONY: debug-client debug-server build-android build-server deploy-server logs

debug-client:
	@echo "--- Сборка клиента (Debug) ---"
	cargo build --bin netrunner-client
	@echo "--- Запуск клиента через sudo ---"
	sudo ./target/debug/netrunner-client

debug-server:
	@echo "--- Сборка сервера (Debug) ---"
	cargo build --bin netrunner-server
	@echo "--- Запуск сервера локально ---"
	sudo ./target/debug/netrunner-server --port=4443 --host=0.0.0.0

# Сборка
build-android:
	cargo ndk -t arm64-v8a -o ./gen build --bin netrunner-client --release
	cargo run --bin bindgen-tool generate --library gen/arm64-v8a/libnetrunner_client.so --language kotlin --out-dir gen/arm64-v8a

build-server:
	cargo build --bin netrunner-server --release

setup-server:
	@echo "--- Обновление системы и установка зависимостей ---"
	ssh $(REMOTE_USER)@$(SERVER_IP) "\
		apt-get update && \
		apt-get upgrade -y && \
		apt-get install -y build-essential libssl-dev pkg-config && \
		mkdir -p $(REMOTE_PATH)"

# Деплой
deploy-server: build-server
	@echo "--- Останавливаем старый сервер ---"
	ssh $(REMOTE_USER)@$(SERVER_IP) "systemctl stop $(SERVICE_NAME)" || true
	
	@echo "--- Копируем бинарник ---"
	ssh $(REMOTE_USER)@$(SERVER_IP) "mkdir -p $(REMOTE_PATH)"
	scp target/release/netrunner-server $(REMOTE_USER)@$(SERVER_IP):$(REMOTE_PATH)/
	
	@echo "--- Копируем файл сервиса ---"
	scp server/netrunner-server.service $(REMOTE_USER)@$(SERVER_IP):/etc/systemd/system/$(SERVICE_NAME).service
	
	@echo "--- Запускаем сервис ---"
	ssh $(REMOTE_USER)@$(SERVER_IP) "\
		systemctl daemon-reload && \
		systemctl enable $(SERVICE_NAME) && \
		systemctl start $(SERVICE_NAME)"

# Логи
logs:
	ssh $(REMOTE_USER)@$(SERVER_IP) "journalctl -u $(SERVICE_NAME) -f"

	# Вход на сервер
ssh:
	ssh $(REMOTE_USER)@$(SERVER_IP)