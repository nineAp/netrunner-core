--- 

# TLS Engine (Masking + Parsing)

## Обзор

Этот модуль реализует:

- Генерацию TLS ClientHello / ServerHello с профилями браузеров
- Гибкую сборку TLS Extensions (включая GREASE, padding, ALPS)
- Парсинг TLS-records и handshake-сообщений
- Маскировку под реальные браузеры (Chrome / Firefox)
- Минимальный TLS-стек для кастомного протокола

Фокус: **fingerprint mimicry**, а не полный TLS стек.

---

## Архитектура

```
tlseng/
├── consts.rs        # TLS константы
├── extension.rs     # Extensions builder + parser
├── handshake.rs     # ClientHello / ServerHello
├── profile.rs       # Browser / Server profiles
├── tls_record.rs    # TLS record layer
├── types.rs         # enums + структуры
```

---

## Основные компоненты

### 1. TLS Record Layer

Файл: `tls_record.rs`

Реализует базовый TLS record:

```rust
struct TlsRecord {
    content_type: ContentType,
    version: ProtocolVersion,
    payload: Bytes
}
```

Поддержка:

- Handshake (0x16)
- ApplicationData (0x17)
- Alert (0x15)

Особенности:

- Минимальная валидация длины
- Быстрая сериализация без аллокаций
- ApplicationData требует минимум 17 байт (под AEAD)

---

### 2. Handshake Layer

Файл: `handshake.rs`

#### ClientHello

Генерация:

```rust
ClientHello::make_client_hello(profile, host, keys)
```

Что делает:

- Генерирует `random` (через session keys)
- Формирует `session_id`:
  - 16 байт random
  - 16 байт auth tag

- Вставляет cipher suites из профиля
- Добавляет extensions через `ExtensionBuilder`
- Оборачивает в TLS Record

Особенности:

- TLS 1.3 masked как TLS 1.2 (version = 0x0303)
- Поддержка padding (для fingerprint совпадения)
- Полный контроль порядка extensions

---

#### ServerHello

```rust
ServerHello::make_server_hello(...)
```

- Выбор cipher suite:
  - либо server order
  - либо client order

- Всегда включает:
  - supported_versions
  - key_share

Минимальный TLS 1.3 ServerHello

---

### 3. Extension System

Файл: `extension.rs`

#### ExtensionStack (Parser)

- Парсит список extensions
- Проверяет корректность длины
- Позволяет искать extension по типу

```rust
find_by_type(etype) -> Option<Bytes>
```

---

#### ExtensionBuilder

Ключевой компонент маскировки.

```rust
ExtensionBuilder::apply_profile(profile, host, pub_key, overhead)
```

Поддерживает:

| Extension             | Реализация |
| --------------------- | ---------- |
| SNI                   | ✔          |
| ALPN                  | ✔          |
| ALPS                  | ✔          |
| Supported Groups      | ✔          |
| Signature Algorithms  | ✔          |
| KeyShare              | ✔          |
| PSK Modes             | ✔          |
| Padding               | ✔          |
| GREASE                | ✔          |
| Compress Certificate  | ✔          |
| SCT                   | ✔          |
| Delegated Credentials | ✔          |

---

#### Особенности

##### GREASE

```rust
TlsExtensions::is_grease(id)
```

- Проверка по паттерну `0x?a?a`
- Вставляется только если `profile.has_grease`

---

##### Padding

```rust
padding(target_size, overhead)
```

- Доводит ClientHello до нужного размера
- Используется для bypass DPI / fingerprint

---

##### ALPS (Application Settings)

```rust
application_settings(["h2"])
```

- Chromium-only behavior
- Добавляется только если есть в профиле

---

### 4. Profiles (Fingerprint Mimicry)

Файл: `profile.rs`

#### BrowserProfile

Определяет fingerprint:

```rust
pub struct BrowserProfile {
    groups
    signatures
    versions
    cipher_suites
    extension_order
    alpn
    grease
    padding
}
```

---

#### Примеры

##### Chrome 131

- GREASE: включен
- ALPS: включен
- Padding: 512 bytes
- TLS 1.3 only
- Record version: TLS 1.0 (как в реальном Chrome)

##### Firefox 130

- GREASE: выключен
- ALPS: нет
- Padding: нет
- TLS 1.2 + 1.3

---

#### Extension Order — критично

```rust
ExtensionOrder::CHROMIUM_131
```

Порядок полностью повторяет реальный браузер.

Это ключ к обходу:

- JA3 fingerprint
- DPI
- TLS fingerprinting

---

### 5. Типы и константы

Файл: `types.rs`

Содержит:

- `ContentType`
- `ProtocolVersion`
- `HelloType`
- `TlsGroups`
- `TlsSignatures`
- `TlsVersions`
- `TlsExtensions`

---

#### Важно

##### TLS Versions

```rust
TlsVersions::TLS_13_ONLY
TlsVersions::MODERN
```

Метод:

```rust
max() -> ProtocolVersion
```

---

##### Supported Groups

```rust
X25519 (0x001d) — основной
```

---

##### Signature Algorithms

Совместимы с браузерами:

- ECDSA
- RSA-PSS
- RSA PKCS1

---

## Парсинг

Все структуры реализуют трейт:

```rust
trait Parser {
    fn can_parse(...)
    fn parse(...)
}
```

Подход:

1. `can_parse` — быстрый pre-check без аллокаций
2. `parse` — безопасный разбор

---

## Безопасность и ограничения

### Что есть

- Корректная структура TLS
- Реалистичный fingerprint
- Минимальная валидация

### Чего нет

- Полного TLS state machine
- Certificate validation
- Finished / handshake verify
- AEAD шифрования (в этом модуле)

---

## Основной use-case

Этот движок предназначен для:

- TLS fingerprint spoofing
- DPI bypass
- Proxy / tunneling протоколов
- Эмуляции браузера на уровне TLS

---

## Пример использования

```rust
let client_hello = ClientHello::make_client_hello(
    &BrowserProfile::CHROME_131,
    "example.com",
    &session_keys
);
```

---

## Ключевые идеи

1. TLS используется как транспорт маскировки
2. Fingerprint важнее криптографии
3. Поведение должно совпадать с браузером
4. Порядок и длины критичны
5. GREASE обязателен для Chromium

---

Если нужно — могу:

- разобрать отличия от real Chrome packet capture
- добавить JA3 генерацию
- указать где fingerprint ещё палится (важно)
