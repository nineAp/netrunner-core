# Crypto Module Documentation

## Overview

Данный модуль реализует криптографическую основу протокола:

- согласование ключей (ECDH, X25519)
- derivation ключей (HKDF-SHA256)
- симметричное шифрование (ChaCha20-Poly1305, AEAD)
- аутентификация с плавающим временным окном (HMAC)

Архитектура разделена на независимые компоненты:

- `ecdh` — обмен ключами
- `hkdf` — derivation ключей
- `session` — управление состоянием сессии
- `chacha` — AEAD шифрование
- `aead` — абстракция шифрования

---

## Security Model

Модель безопасности:

- Forward secrecy обеспечивается за счёт `EphemeralSecret`
- Каждая сессия использует уникальные:
  - salt (локальный + удалённый)
  - ephemeral key pair
- Ключи разделены по направлениям:
  - client → server
  - server → client

---

## Key Exchange (ECDH)

### Реализация

Используется:

- X25519 (через `x25519-dalek`)
- Ephemeral ключи

````rust
let secret = EphemeralSecret::random_from_rng(&mut OsRng);
let public = PublicKey::from(&secret);

### Shared Secret

```rust
shared = private.diffie_hellman(remote_public)
````

Особенности:

- приватный ключ используется **один раз** (`take()`)
- после вызова `get_shared()` он уничтожается

Это критично для:

- forward secrecy
- защиты от повторного использования

---

## Salt Mechanism

### SaltPair

Каждая сторона генерирует:

- `local_salt` (32 байта, случайный)
- получает `remote_salt`

Финальный salt:

```
initiator:
    total = local || remote

responder:
    total = remote || local
```

Это гарантирует:

- детерминированность
- отсутствие коллизий ролей

---

## Key Derivation (HKDF)

Используется:

- HKDF-SHA256

### Extract

```
PRK = HKDF(salt, shared_secret)
```

### Expand

Из PRK генерируются:

| Назначение      | Размер |
| --------------- | ------ |
| client_aead key | 32     |
| client_iv       | 12     |
| server_aead key | 32     |
| server_iv       | 12     |
| auth_key        | 32     |

Пример:

```rust
HKDF::expand_key::<32>(&hkdf, b"client_aead")
```

Контекст (`mark`) используется как label.

---

## SessionKeys

Центральная структура управления:

```rust
pub struct SessionKeys {
    salt: SaltPair,
    ecdh: ECDH,
    auth_key: [u8; 32],
    current_aead: Option<(...)>,
}
```

### Основные задачи:

1. Принять remote salt
2. Извлечь публичный ключ из TLS extension
3. Выполнить ECDH
4. Сгенерировать ключи

---

## TLS Integration

Ключ извлекается из `ExtensionStack`:

- extension type: `0x0033` (KeyShare)
- поддерживается X25519 (`0x001d`)

### Client / Server различия

**Server:**

- парсит ClientHello
- ищет key share внутри структуры

**Client:**

- читает фиксированное смещение

---

## AEAD Encryption (ChaCha20-Poly1305)

### Используемый алгоритм

- ChaCha20-Poly1305
- 256-bit key
- 96-bit nonce

---

## Nonce Strategy

### NonceState

```rust
nonce = base_iv XOR counter
```

Где:

- `base_iv` — получен из HKDF
- `counter` — 64-bit

Алгоритм:

```rust
for i in 0..8:
    iv[i+4] ^= counter[i]
```

Особенности:

- гарантированная уникальность nonce
- отсутствие повторов при корректной работе

---

## Cipher Structure

```rust
pub struct ChaChaCipher {
    encrypt_cipher,
    decrypt_cipher,
    encrypt_state,
    decrypt_state,
}
```

Разделение:

- отдельные ключи и nonce для каждого направления

---

## Encryption Flow

```rust
encrypt_in_place(nonce, aad=nonce, data)
```

AAD:

- используется сам nonce

После:

- данные мутируются
- тег добавляется автоматически

---

## Decryption Flow

```rust
decrypt_in_place(nonce, aad=nonce, data)
```

При ошибке:

- ошибка аутентификации
- повреждённые данные
- несинхронный nonce

---

## Authentication Layer

Дополнительный механизм:

### HMAC-SHA256

```rust
tag = HMAC(auth_key, time_step)
```

Где:

```
time_step = unix_time / 60
```

### Проверка

Принимаются значения:

```
[t-2, t-1, t, t+1, t+2]
```

Назначение:

- защита от replay
- tolerance к рассинхрону времени

---

## AeadPacker Trait

Абстракция для шифрования:

```rust
trait AeadPacker {
    fn encrypt(...)
    fn decrypt(...)
}
```

Позволяет:

- заменить алгоритм
- тестировать разные реализации

---

## Error Handling

Ошибки возникают в случаях:

- неизвестный протокол / extension
- повреждённые данные
- неверный AEAD tag
- отсутствие shared secret

Возвращаются:

- `Result<T, String>`
- `aead::Error`

---

## Important Security Notes

1. Ephemeral ключ используется только один раз
2. Nonce никогда не должен повторяться
3. Salt обязателен с обеих сторон
4. AEAD тег обязателен (встроен)
5. Временные теги не заменяют AEAD

---

## Limitations

- Нет re-keying
- Нет защиты от state desync (nonce)
- Нет replay protection на уровне пакетов (только time-based)
- Жёстко задан HKDF context strings

---

## Summary

Модуль реализует:

- безопасный ECDH handshake
- детерминированный key derivation
- AEAD шифрование с разделением направлений
- дополнительную HMAC-аутентификацию

Подходит для:

- пользовательских протоколов
- туннелей
- транспортных шифрованных каналов
