# Network Module Documentation

## Overview

Данный модуль реализует сетевую часть VPN ядра:

- входные TCP соединения (SOCKS / туннель)
- мультиплексирование потоков поверх одного соединения
- транспорт кадров (Frame)
- проксирование TCP/UDP
- управление туннелем (TunnelEngine)

Архитектура:

- network — точка входа (listener + режим)
- connection — логика соединений
- muxer — мультиплексирование потоков
- handler — обработка входящих фреймов
- engine — основной цикл туннеля
- bridge — проксирование сокетов

---

## High-Level Architecture

Система работает по схеме:

Client (SOCKS)
→ Muxer
→ TunnelEngine (шифрованный канал)
→ Server
→ StreamHandler
→ TCP/UDP target

И обратно.

Ключевая идея:
ОДНО TCP соединение = МНОГО логических потоков (stream_id)

---

## Network

### Назначение

Точка входа:

- запускает TCP listener
- определяет режим (Client / Server)
- управляет lifecycle

### Режимы

#### Client

- Подключается к удалённому proxy
- Поднимает SOCKS сервер
- Каждый входящий клиент → новый stream

#### Server

- Принимает туннельные соединения
- Обрабатывает handshake
- Создаёт TunnelEngine

---

## NetworkConfig

Глобальная конфигурация (OnceLock)

### Основные параметры

- mtu — системный MTU
- max_wire_frame_size — MTU минус overhead
- safe_payload_size — безопасный payload
- tcp_buffer_size — буфер TCP
- udp_buffer_size — буфер UDP
- channel_capacity — размер каналов

### Расчёт

safe_payload = MTU

- IPv4/UDP overhead (~28)
- frame header
- padding

Цель:

- не фрагментировать пакеты
- держаться в ~1400 байт

---

## Connection

Обёртка над TCP соединением

### Содержит:

- inbound (read half)
- outbound (write half)
- read buffer
- codec (шифрование + framing)

### Основные функции

#### read_socks_request

- читает из буфера
- использует Parser trait
- ждёт пока данных достаточно

#### send_socks_reply

- сериализует ответ
- отправляет клиенту

---

## ClientHandler

### Назначение

- реализует SOCKS5 сервер
- преобразует запросы в multiplexed streams

### Flow

1. SOCKS handshake
2. SOCKS request (CONNECT / UDP)
3. Создание stream_id
4. Регистрация канала
5. Отправка FrameType::Connect
6. Ожидание ответа от сервера
7. Запуск bridge

---

## ServerHandler

### Назначение

- принимает туннель
- делает TLS-like handshake
- запускает TunnelEngine

### Особенность: Stealth Fallback

Если:

- handshake не прошёл
- таймаут

→ соединение проксируется как обычный TLS (на ubuntu.com:443)

Это:

- маскирует трафик
- снижает вероятность блокировки

---

## Muxer

### Назначение

Мультиплексирование потоков

### Компоненты

- control_tx — управляющие сообщения
- data_tx — данные
- streams — map stream_id → channel
- id_gen — генератор ID

---

## Stream ID

Генерация:

- клиент: 1, 3, 5, ...
- сервер: 2, 4, 6, ...

Это гарантирует:

- отсутствие коллизий
- определение стороны

---

## MuxMessage

Структура:

- stream_id
- frame_type
- data

---

## Отправка данных

### send_data_safe

Если payload большой:

- режется на куски (~1300 байт)
- отправляется последовательно

Причина:

- не превышать MTU
- избежать фрагментации

---

## StreamHandler

### Назначение

Обработка входящих Frame

### Типы Frame

- Connect
- UdpConnect
- Data
- UdpData
- Close

---

## TCP Flow (Server)

1. Получен Connect
2. Парсится target
3. Открывается TCP соединение
4. Отправляется SOCKS reply
5. Запускается run_tcp_bridge

---

## UDP Flow

1. bind UDP socket
2. connect(target)
3. запуск run_udp_bridge

---

## TunnelEngine

### Центральный компонент

Отвечает за:

- чтение из сети
- декодирование
- dispatch
- шифрование
- запись

---

## Reader Task

Цикл:

1. read_buf
2. codec.inbound()
3. извлечение frame
4. handler.handle(frame)

### Ошибки

- Wait → ждём данных
- Drop → критическая ошибка (tampering)

---

## Writer Task

Обрабатывает:

- control сообщения (приоритет)
- heartbeat
- data сообщения

### Heartbeat

Каждые 15 секунд:
FrameType::Heartbeat

---

## handle_outbound

Flow:

1. chunking (4KB)
2. encrypt_data()
3. write_all()

---

## Bridge Layer

### run_tcp_bridge

Два направления:

1. socket → muxer
2. muxer → socket

Особенности:

- неблокирующий select
- graceful close
- отправка Close frame

---

### run_udp_bridge

Аналог TCP, но:

- recv/send
- без stream (datagram)

---

## Поток данных (End-to-End)

Client:

browser → SOCKS → ClientHandler
→ Muxer → TunnelEngine
→ encrypted TCP

Server:

→ TunnelEngine → StreamHandler
→ TCP connect → target

Ответ обратно тем же путём.

---

## Error Handling

Критические ошибки:

- codec Drop → разрыв туннеля
- write error → закрытие stream
- read EOF → завершение

Некритические:

- закрыт канал → удаление stream
- неизвестный stream → игнор

---

## Concurrency Model

Используется:

- tokio tasks
- mpsc каналы
- Arc + DashMap

Параллелизм:

- каждый stream независим
- reader / writer разделены

---

## Design Decisions

### 1. Один туннель

Плюсы:

- меньше соединений
- проще маскировка

Минусы:

- single point of failure

---

### 2. Multiplexing

Плюсы:

- высокая эффективность
- меньше latency

---

### 3. Chunking

Причины:

- MTU ограничения
- стабильность

---

### 4. Stealth fallback

Критично для:

- обход DPI
- маскировка под TLS

---

## Limitations

- Нет QoS между потоками
- Нет backpressure контроля
- Нет retransmission (TCP полагается на underlying)
- Нет stream prioritization
- UDP без гарантии доставки

---

## Summary

Модуль реализует:

- TCP listener (client/server)
- multiplexed туннель
- безопасную передачу данных
- проксирование TCP/UDP
- fallback механизм маскировки

Это полноценное сетевое ядро VPN:

- scalable
- асинхронное
- расширяемое
