#!/bin/bash
# Netrunner Deployment Protocol: Local Build & Container Uplink

GITHUB_USER="nineap"
IMAGE_NAME="netrunner-proxy"
REGISTRY="ghcr.io"
FULL_IMAGE_NAME="$REGISTRY/$GITHUB_USER/$IMAGE_NAME"

echo "[*] СТАДИЯ 1: Локальная компиляция проекта в WSL..."
# Запускаем сборку обоих серверных бинарников на твоей машине. Локальный
# Cargo сам разберется с SSH-ключами.
cargo build --release -p netrunner-server -p netrunner-masque-edge

if [ $? -ne 0 ]; then
    echo "[!] ERR: Локальная компиляция Cargo провалилась. Проверь ошибки кода."
    exit 1
fi
echo "[+] СТАДИЯ 1: Оба серверных бинарника успешно собраны локально."

echo "[*] СТАДИЯ 2: Упаковка готового бинарника в Docker..."
# Собираем образ. Флаг --progress=plain покажет тебе лог, если что-то пойдет не так
docker build --progress=plain -t $FULL_IMAGE_NAME:latest .
BUILD_STATUS=$?

if [ $BUILD_STATUS -ne 0 ]; then
    echo "[!] ERR: Сборка Docker образа завершилась ошибкой."
    exit 1
fi

echo "[*] СТАДИЯ 3: Отправка готового пакета на GitHub Registry..."
docker push $FULL_IMAGE_NAME:latest

echo "[+] СЛУЖБА ДОСТАВКИ: Пакет $FULL_IMAGE_NAME:latest успешно задеплоен и готов к установке на ноды."
