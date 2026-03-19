# Netrunner TLS Engine (`tlseng`)

Модуль `tlseng` — это высокопроизводительное ядро для генерации, парсинга и манипуляции TLS-трафиком (TLS 1.2 / TLS 1.3). Основная задача движка — **обход систем глубокого анализа трафика (DPI)** и активных проб (Active Probing) путем идеальной мимикрии под легитимный трафик современных браузеров.

Движок не является полноценной реализацией криптографического стека TLS. Это "умный фасад", который формирует криптографически достоверные пакеты `ClientHello` и `ServerHello`, позволяя скрыто передавать авторизационные данные и устанавливать защищенные туннели, неотличимые от обычного HTTPS-трафика.

## 🌟 Ключевые возможности

- **Perfect Fingerprint Mimicry (JA3 / JA4):** Полная имитация параметров расширений, порядка их следования, поддерживаемых групп и наборов шифров. Движок генерирует отпечатки, на 100% совпадающие с реальными браузерами (Chrome, Edge, Firefox, Safari).
- **Stealth Authentication (Stateless):** Уникальный механизм скрытой авторизации. Токен доступа (Auth Tag) маскируется внутри поля `Session ID` (TLS 1.3 эхо), что позволяет серверу аутентифицировать клиента еще до начала обмена Application Data, не привлекая внимания DPI.
- **Advanced GREASE Support:** Автоматическая и контекстно-зависимая генерация случайных идентификаторов (GREASE) согласно RFC 8701 для обхода сигнатурных фильтров, специфичных для Chromium-браузеров.
- **Smart Padding:** Интеллектуальный расчет расширения `Padding` с учетом размера всех заголовков (overhead) для выравнивания пакета `ClientHello` до заданного размера (например, ровно 512 байт для Chrome), исключая эвристическое детектирование по длине пакета.
- **Zero-Copy Parsing:** Использование крейта `bytes` (`Bytes`, `BytesMut`) для парсинга и сериализации пакетов без лишних аллокаций в памяти.

## 🏗 Архитектура модулей

Структура модуля разделена на логические компоненты для максимальной гибкости и расширяемости:

- **`profile/`**: База данных профилей браузеров и серверов (`BrowserProfile`, `ServerProfile`). Содержит константы для версий, шифров, наличия GREASE, ALPS и целевого размера паддинга.
- **`extension/`**: Мощный и потокобезопасный `ExtensionBuilder` для сборки TLS-расширений (SNI, ALPN, KeyShare, ALPS, Supported Versions и т.д.) в строгом соответствии с профилем.
- **`handshake/`**: Реализация структур `ClientHello` и `ServerHello`. Управляет генерацией рандома, встраиванием скрытых тегов и выбором шифров.
- **`tls_record/`**: Низкоуровневая инкапсуляция данных в `TlsRecord` с правильным указанием версий (маскировка Record Layer Version под `0x0301`).
- **`types/` и `consts/`**: Строго типизированные перечисления (Enums) и константы протокола TLS.

## 🛠 Глубокое погружение: Как это работает

### 1. Профилирование трафика

Движок не хардкодит расширения. Вместо этого `ExtensionBuilder` принимает `BrowserProfile`. Профиль указывает, нужны ли GREASE-значения, какой должен быть `ExtensionOrder` (порядок следования) и до какого размера "надувать" пакет паддингом. Это позволяет в одну строчку переключать маскировку с Chrome 131 на Firefox 130.

### 2. Скрытая авторизация (Session ID Auth)

В TLS 1.3 поле `Session ID` сохранено для обратной совместимости (Middlebox Compatibility Mode).
`tlseng` использует это 32-байтовое поле как контейнер:

1.  **Клиент:** Заполняет первые 16 байт случайными данными, а в последние 16 байт записывает HMAC (Auth Tag), сгенерированный на основе локального времени и мастер-ключа.
2.  **DPI:** Видит стандартный 32-байтовый массив, неотличимый от обычного рандома.
3.  **Сервер:** Извлекает последние 16 байт из `ClientHello` и верифицирует их. Если проверка не пройдена, соединение разрывается (защита от активного сканирования). Если пройдена — сервер возвращает этот же `Session ID` эхом в `ServerHello`.

## 🚀 Примеры использования

### Генерация `ClientHello` (на стороне клиента)

Создание маскировочного пакета под Chrome 131 со встроенной авторизацией:

```rust
use crate::tlseng::profile::BrowserProfile;
use crate::tlseng::extension::ExtensionBuilder;
use crate::tlseng::handshake::ClientHello;
use crate::tlseng::tls_record::TlsRecord;
use bytes::Bytes;

pub fn make_client_hello(profile: &BrowserProfile, host: &str, keys: &SessionKeys) -> Bytes {
    let tls_random = keys.salt.get_local();

    // Расчет размера заголовков для точного Padding
    let overhead = 5 + 4 + 2 + 32 + 1 + 32 + 2 + (profile.cipher_suites.len() * 2) + 2 + 2;

    // Сборка расширений по профилю
    let mut ext_builder = ExtensionBuilder::new();
    ext_builder.apply_profile(profile, host, &keys.ecdh.public_key.to_bytes(), overhead);
    let extensions_bytes = ext_builder.build();

    // Генерация Session ID с Auth Tag
    let mut session_id_bytes = [0u8; 32];
    rand::fill(&mut session_id_bytes[..16]);
    session_id_bytes[16..].copy_from_slice(&keys.generate_auth_tag());

    let client_hello = ClientHello {
        version: profile.versions.get_legacy(), // Всегда 0x0303 для TLS 1.3
        random: tls_random,
        session_id: Bytes::copy_from_slice(&session_id_bytes),
        cipher_suites: profile.cipher_suites.to_vec(),
        extensions: extensions_bytes,
    };

    let record = TlsRecord::new(
        ContentType::Handshake,
        profile.record_layer_version, // 0x0301 для маскировки
        client_hello.serialize(),
    );

    record.serialize()
}
```
