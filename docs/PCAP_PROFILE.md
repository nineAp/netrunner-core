# Снятие браузерного профиля с pcap

🇬🇧 [English version](en/PCAP_PROFILE.md)

Модуль `netrunner_core::pcap` (`core/src/pcap/`, feature `pcap`) читает файл захвата, собирает
TCP-потоки, достаёт `ClientHello` (и первый flight сервера) и вычисляет по ним профиль
[`BrowserProfile`](../core/src/tlseng/profile.rs) — тот «рецепт», по которому наш сборщик строит
свой `ClientHello`. Значения профиля больше не переносятся из дампов руками, а считаются из
самого захвата; всё, что сборщик воспроизвести не умеет, выводится списком `notes`.

## Быстрый старт

```bash
# 1. снять захват начала соединений браузера (откройте 2–3 разных сайта)
sudo tcpdump -i any -w chrome.pcap 'tcp port 443'
#    QUIC лучше отключить (--disable-quic у Chrome), иначе трафик уйдёт по UDP и не будет разобран

# 2. получить профиль
cargo run -p netrunner-core --features pcap --example pcap_profile -- chrome.pcap --name CHROME_149
```

Вывод — готовый ассоциированный `const` для `impl BrowserProfile` в
`core/src/tlseng/profile.rs`, комментарии `ВНИМАНИЕ:` с расхождениями и (если виден ответ
сервера) `CoverFlight { records: vec![…] }`.

| Ключ | Что делает |
|---|---|
| `--name NAME` | имя константы |
| `--list` | только список найденных `ClientHello` с JA4, длиной записи и ECH |
| `--sni SUBSTR` / `--client IP` / `--ja4 HASH` | выбрать нужного клиента, если в захвате их несколько |
| `--json` | профиль в JSON (хранить/сравнивать) |

> Чтобы определить **перемешивание расширений**, нужно не меньше двух соединений: Chromium
> меняет порядок на каждом. С одним `ClientHello` флаг выставляется эвристикой (GREASE + ALPS/ECH),
> и `shuffle_evidence` честно об этом говорит.

## Что извлекается

Из каждого `ClientHello` — без потерь: версия в заголовке записи, `legacy_version`, шифры
(с GREASE), расширения **в порядке на проводе**, SNI, `supported_groups`, `signature_algorithms`,
`delegated_credential`, `supported_versions`, ALPN, ALPS (кодпоинт и протоколы), `key_share`
(группа и длина каждой доли), PSK-режимы, форматы точек, `compress_certificate`, `status_request`,
ECH (`enc`/`payload`), паддинг, длина записи (разбит ли hello на несколько записей).

Из ответа сервера — `ServerHello` (шифр, выбранная версия, группа) и длины записей
`ApplicationData` первого flight'а до первой зашифрованной записи клиента: для TLS 1.3 это
`EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished` — исходные данные для
[`CoverFlight`](../core/src/tlseng/decoy.rs).

Поля профиля → откуда берутся:

| Поле `BrowserProfile` | Источник |
|---|---|
| `cipher_suites`, `groups`, `signatures`, `delegated_signatures`, `versions`, `alpn` | соответствующие поля hello без GREASE |
| `extension_order` | порядок расширений; первое/последнее GREASE заменены маркерами `GREASE_SLOT_FIRST/LAST` |
| `has_grease` | есть ли GREASE в шифрах/расширениях |
| `shuffle_extensions` | порядок «середины» различается между `ClientHello` группы |
| `record_layer_version` | версия в заголовке записи с `ClientHello` |
| `target_padding_len` | длина записи hello, если есть расширение `padding` |
| `alps_protocols` | протоколы ALPS |

Дополнительно считаются **JA3** (строка и MD5) и **JA4**. JA4 не зависит ни от GREASE, ни от
порядка расширений, поэтому служит объективной проверкой: профиль, воссозданный нашим сборщиком,
обязан дать тот же JA4, что и браузер (проверяется тестом).

## Что поддерживается

* Контейнеры: `pcap` (µs/ns, любой порядок байт), `pcapng` (несколько секций и интерфейсов,
  `if_tsresol`, EPB/SPB). Gzip — предварительно `gunzip`.
* Канальные уровни: Ethernet (+VLAN/QinQ), Linux cooked v1/v2 (`-i any`), raw IP, BSD loopback.
* IPv4/IPv6 (расширенные заголовки; не первые фрагменты пропускаются).
* TCP: переупорядочивание, ретрансмиты и перекрытия, перенос номера через 2³²; на первой дыре
  сборка направления останавливается и в `warnings` пишется предупреждение.
* Любые порты (не только 443), несколько клиентов — группируются по JA4.
* `ClientHello`, разбитый на несколько TCP-сегментов и TLS-записей.

Не поддерживается: расшифровка, QUIC (Initial-пакеты только подсчитываются и приводят к
предупреждению), захваты без начала соединения.

## Что стоит знать о результате

`notes` перечисляют то, что наш сборщик не воспроизводит точно: `legacy_version`/`session_id`/
`compression` не по нашему образцу, расширения без собственной сборки (будут пустыми), другая
структура `key_share`, нестандартные `compress_certificate`/`psk_modes`/ALPS-кодпоинт, **ECH-payload
другой длины**. Профиль с непустыми `notes` совпадёт с браузером по JA3/JA4, но не по содержимому
этих расширений.

### Что нашлось на реальном Chrome 148

Проверка на настоящем захвате (Chrome 148, headless, loopback → `openssl s_server`, TLS 1.3;
файл — тестовая фикстура `core/src/pcap/testdata/chrome148_loopback.pcap`):

| Наблюдение | Значение |
|---|---|
| JA4 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` (`8daaf6152771` — известный хеш шифров Chrome) |
| `signature_algorithms` | 8 значений, **без ML-DSA** (`0904`–`0906`); в профиле `CHROME_140` их 11 |
| порядок расширений | перемешивается между соединениями; набор из 18 (с 2 GREASE) совпадает с `CHROME_140` |
| **ECH GREASE payload** | **случайной длины: 144 / 176 / 208 / 240 Б** (в сборщике константа 144) |
| первый flight (RSA-2048 `s_server`) | записи `23, 832, 281, 53` (`Finished = 4+32+17 = 53` — формула `CoverFlight` верна) |

Две практические находки для профиля `CHROME_140`: (1) список подписей с ML-DSA не совпадает с
Chrome 148; (2) постоянный ECH-payload 144 Б — детектор. Профиль следует обновить этим
инструментом под целевую версию Chrome, а длину ECH-payload сделать случайной из наблюдаемого
набора.

## API

```rust
use netrunner_core::pcap::{analyze, ProfileOptions};

let analysis = analyze(&std::fs::read("chrome.pcap")?)?;       // Analysis
for h in &analysis.client_hellos { /* ClientHelloInfo: всё, что было на проводе */ }
let profile = analysis.build_profile(&ProfileOptions {
    name: Some("CHROME_149".into()),
    sni_contains: Some("example".into()),
    ..Default::default()
})?;                                                            // CapturedProfile
println!("{}", profile.to_rust_source());                       // или profile.to_json()
let flight = analysis.flight_for(&analysis.client_hellos[0]);   // ServerFlight → CoverFlight
```

Низкоуровневые части (`read_packets`, `assemble_flows`, `split_records`, `parse_client_hello`,
`ja3_string`, `ja4`) тоже публичны — их можно использовать отдельно.

## Тесты

```bash
cargo test -p netrunner-core --features pcap --lib pcap    # 27 тестов
```

Синтетические захваты собираются из `ClientHello` нашего же сборщика (сквозной круг: сборка →
захват → профиль → пересборка → тот же JA4); `real_chrome_148_capture` — регрессия на реальные
байты браузера. Контейнеры, канальные уровни, сборка TCP и TLS-разбор покрыты отдельными тестами,
включая обрезанные и мусорные входы (паник нет).
