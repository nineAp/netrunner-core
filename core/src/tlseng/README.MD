# Netrunner TLS Engine (tlseng)

Модуль `tlseng` отвечает за генерацию и анализ TLS-хендшейков. Его основная задача — маскировка сетевой активности под легитимный трафик популярных браузеров (Chrome, Edge).

## Возможности

- **Fingerprint Mimicry:** Полная имитация параметров расширений, порядка их следования и наборов шифров.
- **Dynamic Extension Builder:** Потокобезопасная сборка TLS-расширений (SNI, ALPN, KeyShare, PADDING и т.д.).
- **GREASE Support:** Автоматическая генерация случайных идентификаторов для обхода сигнатурных фильтров.
- **TlsRecord Encapsulation:** Упаковка данных в стандартные TLS-записи согласно спецификациям.

## Архитектура

- `profile/`: Описания браузерных конфигураций (JA3/JA4 совместимость).
- `extension/`: Логика построения TLS-расширений (`ExtensionBuilder`).
- `handshake/`: Реализация `ClientHello` и `ServerHello`.
- `tls_record/`: Низкоуровневая упаковка данных в TLS-формат.

## Пример использования

```rust
use crate::tlseng::profile::BrowserProfile;
use crate::tlseng::extension::ExtensionBuilder;

// Создание хендшейка для профиля Chrome 131
let mut builder = ExtensionBuilder::new();
builder.apply_profile(&BrowserProfile::CHROME_131, "google.com", &public_key);
let extensions = builder.build();
```
