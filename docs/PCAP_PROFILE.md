# Браузерные профили: запись, JSON, загрузка

🇬🇧 [English version](en/PCAP_PROFILE.md)

Движок строит свой `ClientHello` по **профилю браузера** — «рецепту» отпечатка (шифры, группы,
подписи, порядок расширений…). Профиль — это данные: JSON-файл. Его можно **снять с настоящего
браузера одной командой**, отредактировать руками или написать с нуля, а клиент подхватывает его
при запуске. Никакой пересборки.

```text
 браузер ──трафик──▶ netrunner-client profile record ──▶ profile.json ──▶ netrunner-client --browser-profile profile.json
                      (AF_PACKET, без tcpdump)     (разбор pcap, JA3/JA4,        (движок строит ClientHello по JSON)
                                                    сборка профиля, проверка)
```

## Быстрый старт

```bash
# 0. один раз: право на сырой сокет (или запускайте через sudo)
sudo setcap cap_net_raw+ep ./netrunner-client

# 1. ОТКЛЮЧИТЕ VPN, запустите запись и посёрфите в браузере 3–5 разных сайтов
./netrunner-client profile record --out chrome.json
#    остановится само, когда наберётся 12 соединений одного отпечатка (или Ctrl+C / 120 с)

# 2. проверить (необязательно: record уже проверяет)
./netrunner-client profile check chrome.json

# 3. запустить клиент с этим профилем
./netrunner-client --config client.toml --browser-profile chrome.json
```

`browser_profile = "chrome.json"` можно положить и в `client.toml`, либо переменная
`NETRUNNER_BROWSER_PROFILE`. Файл с одним профилем или с **массивом** профилей — тогда каждая сессия
берёт один из них по хешу своего `session_id` (отпечаток стабилен всю сессию). Без флага
используется встроенный профиль.

Готовые профили: [`profiles/chrome_148.json`](../profiles/chrome_148.json) (снят с настоящего Chrome 148)
и [`profiles/minimal_example.json`](../profiles/minimal_example.json) (написан руками — шаблон для своих).

### Команды

| Команда | Что делает |
|---|---|
| `profile record --out F` | записывает трафик, строит профиль, пишет JSON. Ключи: `--iface` (по умолчанию все), `--port` (443; можно повторять), `--seconds` (120), `--stop-after` (12; 0 — только Ctrl+C/таймер), `--save-pcap F` (сохранить сырой захват), `--name`, `--sni`, `--client`, `--ja4` |
| `profile build CAP --out F` | то же из готового `.pcap`/`.pcapng` (Wireshark, `tcpdump`, Windows/macOS) |
| `profile check F` | проверяет JSON (применим ли профиль к нашему протоколу) и печатает предупреждения |

Запись показывает прогресс (соединений, `ClientHello`, различных отпечатков), а в конце — сводку:
JA4, перемешивание расширений и чем оно обосновано, наблюдавшиеся длины ECH, другие отпечатки в
захвате и замечания о том, что движок не воспроизводит.

> Чтобы определить **перемешивание расширений** и разброс длины ECH нужно несколько соединений:
> Chromium меняет порядок на каждом. Поэтому `--stop-after` по умолчанию 12.
> Запись без VPN: иначе в захвате окажется наш же туннель, а не браузер. QUIC лучше отключить
> (`--disable-quic` у Chrome) — иначе трафик пойдёт по UDP.

## Формат JSON (schema 1)

Числа — числом или строкой `"0x1301"`; расширения — числом, `"0x…"` или **именем**. Неизвестные
поля отвергаются (опечатка не пройдёт молча).

| Поле | Обяз. | Смысл |
|---|:-:|---|
| `schema` | — | версия формата, сейчас `1` |
| `name` | да | имя (1–64 символа) |
| `record_layer_version` | да | версия в заголовке TLS-записи с `ClientHello`: `0x0301` (Chrome), `0x0303`, `0x0304` |
| `cipher_suites` | да | шифры **без GREASE**; нужен `0x1301` или `0x1302` (узел по умолчанию выбирает AES-GCM) |
| `groups` | да | `supported_groups` без GREASE; **обязателен `0x001d`** (x25519), `0x11ec` добавляет постквантовый балласт |
| `signatures` | да | `signature_algorithms` |
| `delegated_signatures` | — | для `delegated_credential` |
| `versions` | да | `supported_versions` без GREASE; **обязателен `0x0304`** |
| `alpn`, `alps_protocols` | — | протоколы ALPN / ALPS |
| `alps_codepoint` | — | `0x44cd` (по умолчанию) либо `0x4469` |
| `extension_order` | да | порядок расширений; `grease_first` / `grease_last` — позиции GREASE. Обязательны `key_share`, `supported_groups`, `supported_versions` |
| `has_grease` | — | по умолчанию — есть ли GREASE-слоты в порядке |
| `shuffle_extensions` | — | перемешивать «середину» порядка на каждое соединение (Chromium) |
| `target_padding_len` | — | цель паддинга `ClientHello` (0 — без) |
| `ech_payload_lengths` | — | допустимые длины payload GREASE-ECH; на соединение берётся случайная (пусто = 144) |
| `compress_cert_algs`, `psk_modes`, `ec_point_formats` | — | содержимое одноимённых расширений (по умолчанию brotli, `[1]`, `[0]`) |
| `raw_extensions` | — | тела расширений без собственной сборки: `{"0x1234": "abcd01"}` — выписываются как есть |
| `meta` | — | любые сведения (источник, JA3/JA4, заметки); движком не читается |

Имена расширений: `server_name`, `status_request`, `supported_groups`, `ec_point_formats`,
`signature_algorithms`, `alpn`, `sct`, `padding`, `extended_master_secret`, `compress_certificate`,
`delegated_credential`, `session_ticket`, `supported_versions`, `psk_key_exchange_modes`, `key_share`,
`alps`, `ech`, `renegotiation_info`, `grease_first`, `grease_last`.

Профиль **проверяется при загрузке**: если он ломает протокол (нет x25519, TLS 1.3, `key_share`,
AES-GCM-шифра, дубль расширения…), загрузка отклоняется со списком причин и ничего не меняется — ошибка
видна сразу, а не на первом соединении. Менее серьёзное (расширение без сборщика и без `raw_extensions`
будет пропущено, паддинг без цели…) выводится предупреждением.

## Что извлекается из захвата

Из каждого `ClientHello` — без потерь: версия в заголовке записи, `legacy_version`, шифры (с GREASE),
расширения **в порядке на проводе**, SNI, группы, подписи, ALPN, ALPS (кодпоинт), `key_share`
(группа и длина каждой доли), PSK-режимы, форматы точек, `compress_certificate`, `status_request`, ECH
(`enc`/`payload`), паддинг, фрагментация по записям. Из ответа сервера — `ServerHello` и длины записей
первого flight'а (исходные данные для [`CoverFlight`](../core/src/tlseng/decoy.rs)). Считаются
**JA3** и **JA4**; JA4 не зависит от GREASE и порядка, поэтому профиль, пересобранный движком, обязан
дать тот же JA4, что и браузер — это проверяется тестами.

Если в захвате несколько разных клиентов, берётся самая многочисленная группа по JA4 (остальные
перечисляются); `--sni`, `--client`, `--ja4` выбирают нужную.

## Ограничения: откуда они и что с ними

| Ограничение | Откуда | Состояние |
|---|---|---|
| Профиль был константой в коде | архитектура | **снято**: JSON, загрузка при старте, `--browser-profile` |
| ECH-payload — константа 144 Б (у Chrome случайный 144/176/208/240) | зашито в сборщике | **снято**: `ech_payload_lengths`, случайная на соединение |
| Зашитые brotli / PSK `[1]` / формат точек `[0]` / ALPS `0x44cd` | зашито в сборщике | **снято**: поля профиля |
| Расширения без сборщика **молча пропускались** | сборщик | **снято**: `raw_extensions` (тело из захвата); без тела — предупреждение |
| Нужно `tcpdump` и права | инструмент | **снято**: запись из бинаря (`AF_PACKET`, `CAP_NET_RAW`) |
| Запись только на Linux | `AF_PACKET` | на macOS/Windows: `profile build` по `.pcap` из Wireshark. Нативный захват (libpcap/Npcap) — возможное расширение |
| Не воспроизводится: `legacy_version`≠`0x0303`, `session_id`≠32 Б, `compression`≠`[0]`, нестандартные `key_share`/`status_request`/SCT/EMS/ticket | **протокол**: в `session_id` едут версия, шифр и тег; обмен ключами — только X25519 | остаётся; такие отличия выводятся в `notes` |
| Только TLS поверх TCP; QUIC не разбирается | парсер | **можно доработать**: Initial-пакеты QUIC шифруются ключами из публичной соли и открытого DCID, поэтому `ClientHello` из них извлекается (наш `quiceng` делает то же при сборке). Не сделано; нужно и для профиля QUIC-ноги |
| Профиль влияет только на TCP-ногу | UDP-нога имеет свои профили (`QuicProfile`, `WebrtcProfile`) | возможное расширение — тоже из JSON |
| Мобильное приложение (UniFFI) не принимает JSON-профиль | нет параметра в `SessionParams` | **можно доработать**: добавить параметр; `core::browser_profile::load_json` уже готов |
| Нужно начало соединения | TCP/TLS: `ClientHello` — первый пакет | неустранимо, но запись ловит новые соединения; открывайте новые вкладки |
| Firefox headless не снялся при проверке | окружение (Firefox-snap), не инструмент | снимите профиль на своей машине; парсер Firefox-образной ветки проверен на синтетике |

## API

```rust
use netrunner_core::{browser_profile, pcap};

// движок: подмена встроенного пула своими профилями
let report = browser_profile::load_file("chrome.json")?;      // или load_json(&str)
browser_profile::clear();                                      // вернуть встроенные

// снятие: файл → профиль
let analysis = pcap::analyze(&std::fs::read("chrome.pcap")?)?;
let profile = analysis.build_profile(&pcap::ProfileOptions::default())?;
std::fs::write("chrome.json", profile.to_json())?;

// запись (Linux), фича `pcap`
let rec = pcap::capture::record(&pcap::capture::CaptureConfig::default(), &stop, &mut |p| { /* прогресс */ })?;
let analysis = rec.analyze();
```

Низкоуровневые части (`read_packets`, `assemble_flows`, `split_records`, `parse_client_hello`,
`ja3_string`, `ja4`) публичны. Модуль `pcap` включается фичей `pcap`; чтение JSON
(`browser_profile`) доступно всегда, в том числе в мобильных и wasm-сборках.

## Проверка

```bash
cargo test -p netrunner-core --features pcap --lib      # 283 теста
```

Среди них: синтетические захваты из `ClientHello` нашего же сборщика; **реальный захват Chrome 148**
(фикстура `core/src/pcap/testdata/chrome148_loopback.pcap`) → JSON → профиль → пересборка с тем же JA4
и случайной длиной ECH; поставляемые `profiles/*.json` принимает настоящий серверный разбор; запись из
бинаря проверена вручную на живом Chrome.

### Что нашлось на реальном Chrome 148

| Наблюдение | Значение |
|---|---|
| JA4 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` (`8daaf6152771` — известный хеш шифров Chrome) |
| `signature_algorithms` | 8 значений, **без ML-DSA** (`0904`–`0906`); в встроенном `CHROME_140` их 11 |
| порядок расширений | перемешивается между соединениями; набор из 18 (с 2 GREASE) совпадает с `CHROME_140` |
| ECH GREASE payload | случайный: 144 / 176 / 208 / 240 Б |
| первый flight (RSA-2048 `s_server`) | записи `23, 832, 281, 53` (`Finished = 4+32+17 = 53`) |

Встроенный профиль `CHROME_140` отличается от Chrome 148 списком подписей — используйте
`profiles/chrome_148.json` (или снимите профиль под свою версию браузера).
