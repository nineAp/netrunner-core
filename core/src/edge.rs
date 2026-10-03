//! # Edge-клиент (`edge`) — протокол NRXP без `tokio::net`
//!
//! Тонкая, полностью синхронная и платформо-независимая обвязка над
//! [`crypto`](crate::crypto)/[`nrxp`](crate::nrxp)/[`tlseng`](crate::tlseng),
//! не завязанная ни на какой конкретный ввод-вывод. [`net::connection`](crate::net)
//! жёстко использует `tokio::net::TcpStream` (реального сетевого драйвера
//! `tokio` для цели `wasm32-unknown-unknown` не существует), поэтому он
//! целиком выключен из wasm-сборок — см. `#[cfg]` в `net/mod.rs`. Этот модуль —
//! замена для таких сред: вызывающий код сам решает, как именно доставлять
//! байты (`worker::Socket` в Cloudflare Workers, обычный TCP-сокет где угодно
//! ещё), а сюда просто скармливает то, что пришло, и забирает то, что нужно
//! отправить.
//!
//! Соответствует ровно тому же протоколу и тому же хендшейку, что и
//! [`ClientHandler::perform_handshake`](crate::net::connection::ClientHandler)
//! (см. `core/src/net/connection/connection.rs`): поддельный `ClientHello` +
//! фиктивный `ChangeCipherSpec`, ожидание `ServerHello` + встречного CCS,
//! вывод ключей, первый зашифрованный `Heartbeat` с `session_id:leg_id:auth_token`.
//! Это НЕ полноценный мультиплексор/муксер ([`Muxer`](crate::net::Muxer)) —
//! ролей и отказоустойчивости нескольких "ног" здесь нет; это один логический
//! TCP-канал до ноды, чего достаточно для edge-релея (одно исходящее
//! TCP-соединение из Cloudflare Worker до VPN-ноды).
//!
//! ## Типичный цикл использования
//!
//! ```text
//! let hs = EdgeHandshake::new(decoy_sni, session_seed);
//! write(hs.client_hello_bytes());
//! let mut buf = BytesMut::new();
//! let mut hs = hs;
//! let mut tunnel = loop {
//!     buf.extend_from_slice(&read_some());
//!     match hs.feed(&mut buf)? {
//!         HandshakeOutcome::NeedMore(next) => { hs = next; continue; }
//!         HandshakeOutcome::Done(tunnel) => break tunnel,
//!     }
//! };
//! write(tunnel.encode_auth_heartbeat(&session_id, 0, &auth_token)?);
//! write(tunnel.encode_frame(1, EdgeFrameKind::Connect, b"1.2.3.4:443".as_ref().into())?);
//! for frame in tunnel.feed(&read_some())? { /* маршрутизировать по frame.stream_id */ }
//! ```

use crate::crypto::{ChaChaCipher, SessionKeys};
use crate::nrxp::{Codec, FrameType, RxCodec, TlsBridge, TxCodec};
use crate::tlseng::BrowserProfile;
use bytes::{Bytes, BytesMut};

/// Тип кадра NRXP, видимый снаружи крейта (зеркало `crate::nrxp::FrameType`,
/// которое само `pub(crate)` и наружу течь не может).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EdgeFrameKind {
    Connect,
    Data,
    Close,
    Heartbeat,
    UdpConnect,
    UdpData,
    Diag,
    Credit,
}

impl EdgeFrameKind {
    fn to_internal(self) -> FrameType {
        match self {
            EdgeFrameKind::Connect => FrameType::Connect,
            EdgeFrameKind::Data => FrameType::Data,
            EdgeFrameKind::Close => FrameType::Close,
            EdgeFrameKind::Heartbeat => FrameType::Heartbeat,
            EdgeFrameKind::UdpConnect => FrameType::UdpConnect,
            EdgeFrameKind::UdpData => FrameType::UdpData,
            EdgeFrameKind::Diag => FrameType::Diag,
            EdgeFrameKind::Credit => FrameType::Credit,
        }
    }
}

impl From<FrameType> for EdgeFrameKind {
    fn from(ft: FrameType) -> Self {
        match ft {
            FrameType::Connect => EdgeFrameKind::Connect,
            FrameType::Data => EdgeFrameKind::Data,
            FrameType::Close => EdgeFrameKind::Close,
            FrameType::Heartbeat => EdgeFrameKind::Heartbeat,
            FrameType::UdpConnect => EdgeFrameKind::UdpConnect,
            FrameType::UdpData => EdgeFrameKind::UdpData,
            FrameType::Diag => EdgeFrameKind::Diag,
            FrameType::Credit => EdgeFrameKind::Credit,
            // Cover до сюда не доходит: `EdgeTunnel::feed` отбрасывает такие
            // кадры раньше, чем дело дойдёт до конверсии. Отображаем в
            // Heartbeat как безопасный no-op, чтобы не заводить публичный
            // вариант перечисления под чисто внутреннюю механику маскировки.
            FrameType::Cover => EdgeFrameKind::Heartbeat,
            FrameType::SecureConnect | FrameType::MeshOnionConnect => EdgeFrameKind::Connect,
            FrameType::SecureUdpConnect | FrameType::MeshOnionUdpConnect => {
                EdgeFrameKind::UdpConnect
            }
        }
    }
}

/// Один разобранный и расшифрованный кадр туннеля, отданный вызывающему коду.
pub struct EdgeFrame {
    pub stream_id: u32,
    pub kind: EdgeFrameKind,
    pub payload: Bytes,
}

/// Хендшейк в процессе: ключи уже сгенерированы (эфемерный X25519 + локальная
/// соль), `ClientHello` готов к отправке, но `ServerHello` ещё не пришёл (или
/// пришёл не целиком).
pub struct EdgeHandshake {
    session_keys: SessionKeys,
    decoy_host: String,
    profile: &'static BrowserProfile,
    hello_parsed: bool,
}

/// Результат очередной попытки продвинуть хендшейк.
pub enum HandshakeOutcome {
    /// Данных пока недостаточно — прочитать ещё с сокета и вызвать `feed` снова.
    NeedMore(EdgeHandshake),
    /// Хендшейк завершён, ключи выведены, кодек готов к работе. `EdgeTunnel`
    /// уже содержит любой "хвост" данных, оставшийся в буфере после хендшейка
    /// (например, если сервер прислал первые байты AppData в том же TCP-чтении).
    Done(EdgeTunnel),
}

impl EdgeHandshake {
    /// Начинает клиентский хендшейк. `decoy_sni` — домен-декой для `ClientHello`
    /// (см. [`EngineConfig::decoy_sni`](../../../client/src/net/engine.rs) в
    /// клиенте — то же самое поле). `session_seed` определяет, какой профиль
    /// браузера ([`BrowserProfile::for_session`]) будет использован для этого
    /// TLS-отпечатка; передавайте сюда стабильный идентификатор сессии, а не
    /// что-то, что меняется от попытки к попытке (см. doc на `for_session`
    /// про то, почему смена отпечатка между реконнектами — плохая идея).
    pub fn new(decoy_sni: impl Into<String>, session_seed: &str) -> Self {
        Self::with_identity(decoy_sni, session_seed, None)
    }

    /// То же самое, но с учётными данными ноды (`nrxp_secret` +
    /// `nrxp_public_key` из админки бэкенда): включает аутентифицированный
    /// аутентифицированный хендшейк (v3/ChaCha или v4/ring AES-GCM).
    ///
    /// Edge ходит на ту же ноду тем же протоколом, что и приложение, и без
    /// учётных данных он остаётся ровно так же уязвим к активному посреднику —
    /// с той разницей, что его токен долгоживущий (`edge_...`, выпускается
    /// один раз), поэтому цена перехвата здесь выше, а не ниже.
    pub fn with_identity(
        decoy_sni: impl Into<String>,
        session_seed: &str,
        identity: Option<crate::Identity>,
    ) -> Self {
        Self {
            session_keys: match identity {
                Some(id) => SessionKeys::with_identity(true, id),
                None => SessionKeys::new(true),
            },
            decoy_host: decoy_sni.into(),
            profile: BrowserProfile::for_session(session_seed),
            hello_parsed: false,
        }
    }

    /// Байты для отправки первыми: поддельный `ClientHello` + фиктивный
    /// `ChangeCipherSpec` (см. doc на модуль про middlebox-совместимость).
    pub fn client_hello_bytes(&self) -> Bytes {
        let ch = TlsBridge::wrap_client_hello(self.profile, &self.decoy_host, &self.session_keys);
        let ccs = TlsBridge::build_middlebox_ccs();
        let mut out = BytesMut::with_capacity(ch.len() + ccs.len());
        out.extend_from_slice(&ch);
        out.extend_from_slice(&ccs);
        out.freeze()
    }

    /// Скармливает вновь пришедшие байты. `buf` — накопительный буфер
    /// вызывающего кода (тот же самый между вызовами); функция сама решает,
    /// сколько из него потребить. При `NeedMore` вызывающий код обязан
    /// дочитать сокет и добавить новые байты в тот же `buf` перед повторным
    /// вызовом `feed` на возвращённом состоянии.
    pub fn feed(mut self, buf: &mut BytesMut) -> Result<HandshakeOutcome, String> {
        if !self.hello_parsed {
            match TlsBridge::unpack_handshake(buf).map_err(|e| format!("{:?}", e.stage))? {
                Some(msg) => {
                    if let Some(suite) = msg.cipher_suite() {
                        self.session_keys
                            .set_tls_cipher_suite(suite)
                            .map_err(|e| e.to_string())?;
                    }
                    self.session_keys
                        .update_keys(msg.random(), msg.extensions(), false)
                        .map_err(|e| e.to_string())?;
                    self.hello_parsed = true;
                }
                None => return Ok(HandshakeOutcome::NeedMore(self)),
            }
        }

        // Сервер шлёт свой фиктивный CCS сразу после ServerHello — вычитываем
        // и отбрасываем его до перехода в data-фазу (см. doc на модуль).
        match TlsBridge::unpack_middlebox_ccs(buf).map_err(|e| format!("{:?}", e.stage))? {
            Some(()) => {}
            None => return Ok(HandshakeOutcome::NeedMore(self)),
        }

        let (tx_key, tx_iv, rx_key, rx_iv) = self.session_keys.get_aead_parameters();
        let mut cipher = ChaChaCipher::with_suite_and_legacy_chacha_aad(
            self.session_keys.aead_suite(),
            self.session_keys.uses_legacy_chacha_aad(),
        );
        cipher.set_keys(tx_key, tx_iv, rx_key, rx_iv);
        let codec = Codec::new(cipher, self.session_keys.get_auth_key());
        let (rx_codec, tx_codec) = codec.split();

        Ok(HandshakeOutcome::Done(EdgeTunnel {
            tx: tx_codec,
            rx: rx_codec,
            inbuf: std::mem::take(buf),
        }))
    }
}

/// Готовый туннель: один зашифрованный логический канал до ноды. Кодирует
/// исходящие кадры и разбирает входящие из сырых байт TCP-сокета.
pub struct EdgeTunnel {
    tx: TxCodec,
    rx: RxCodec,
    /// Накопитель непрочитанных сырых (ещё зашифрованных) байт между вызовами
    /// [`feed`](EdgeTunnel::feed) — как правило пуст сразу после парсинга,
    /// хранит только "хвост" TCP-чтения, не образующий целой TLS-записи.
    inbuf: BytesMut,
}

impl EdgeTunnel {
    /// Кодирует один кадр в готовую к отправке TLS-запись `ApplicationData`.
    pub fn encode_frame(
        &mut self,
        stream_id: u32,
        kind: EdgeFrameKind,
        payload: Bytes,
    ) -> Result<Bytes, String> {
        self.tx
            .encode_frame(stream_id, kind.to_internal(), payload)
            .map_err(|e| format!("{:?}", e.stage))
    }

    /// Первый зашифрованный кадр сессии: `Heartbeat` с телом
    /// `"session_id:leg_id:auth_token"` (стрим 0). Сервер ожидает его сразу
    /// после хендшейка — без него нода не свяжет TCP-соединение с сессией.
    pub fn encode_auth_heartbeat(
        &mut self,
        session_id: &str,
        leg_id: u32,
        auth_token: &str,
    ) -> Result<Bytes, String> {
        let payload = Bytes::from(format!("{}:{}:{}", session_id, leg_id, auth_token));
        self.encode_frame(0, EdgeFrameKind::Heartbeat, payload)
    }

    /// Разбирает столько кадров, сколько накопилось в `data` + недоразобранном
    /// хвосте. Порядок кадров в возвращённом `Vec` — порядок их прибытия.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<EdgeFrame>, String> {
        self.inbuf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            match self.rx.decode_inbound(&mut self.inbuf) {
                // Cover-кадры (см. `FrameType::Cover`) — набивка ради формы
                // трафика, данных в них нет. Отбрасываем прямо здесь, а не
                // заводим вариант в `EdgeFrameKind`: иначе каждый потребитель
                // edge-API (Worker, edge-native) обязан был бы знать про
                // маскировочную механику ядра и молча её игнорировать.
                Ok(Some(frame)) if frame.header.frame_type == FrameType::Cover => continue,
                Ok(Some(frame)) => out.push(EdgeFrame {
                    stream_id: frame.header.stream_id,
                    kind: frame.header.frame_type.into(),
                    payload: frame.payload,
                }),
                Ok(None) => break,
                Err(e) => return Err(format!("{:?}", e.stage)),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ChaChaCipher, SessionKeys};
    use crate::nrxp::{Codec, TlsBridge};
    use crate::tlseng::ServerProfile;

    /// Проводит хендшейк [`EdgeHandshake`] против настоящей серверной стороны
    /// протокола (`TlsBridge::wrap_server_hello` + `SessionKeys`, то же самое,
    /// что использует `ServerHandler` в `net::connection`), чтобы убедиться,
    /// что edge-клиент выводит те же ключи и говорит по проводу ровно то, что
    /// ожидает нода — а не просто компилируется как самодостаточный мок.
    #[test]
    fn edge_handshake_interops_with_real_server_side() {
        let client_hs = EdgeHandshake::new("www.debian.org", "edge-test-session");
        let mut wire = BytesMut::from(&client_hs.client_hello_bytes()[..]);

        // --- сервер ---
        let mut server_keys = SessionKeys::new(false);
        let client_msg = TlsBridge::unpack_handshake(&mut wire).unwrap().unwrap();
        let (server_hello, _client_protocol_version) =
            TlsBridge::wrap_server_hello(&client_msg, &mut server_keys, &ServerProfile::MODERN)
                .unwrap();
        // Клиент оставил в буфере свой фиктивный CCS — серверу до него дела нет
        // в этом тесте (сервер не гоняет полный цикл ClientHandler::perform_handshake),
        // достаточно того, что клиент действительно его отправил.
        assert!(TlsBridge::unpack_middlebox_ccs(&mut wire)
            .unwrap()
            .is_some());

        let (s_tx_key, s_tx_iv, s_rx_key, s_rx_iv) = server_keys.get_aead_parameters();
        let mut server_cipher = ChaChaCipher::new();
        server_cipher.set_keys(s_tx_key, s_tx_iv, s_rx_key, s_rx_iv);
        let (mut server_rx, mut server_tx) =
            Codec::new(server_cipher, server_keys.get_auth_key()).split();

        // --- обратно клиенту: ServerHello + фиктивный CCS ---
        let mut server_to_client = BytesMut::from(&server_hello[..]);
        server_to_client.extend_from_slice(&TlsBridge::build_middlebox_ccs());

        let mut tunnel = match client_hs.feed(&mut server_to_client).unwrap() {
            HandshakeOutcome::Done(tunnel) => tunnel,
            HandshakeOutcome::NeedMore(_) => panic!("handshake should complete in one feed here"),
        };

        // Клиент → сервер: auth heartbeat расшифровывается и совпадает по содержимому.
        let auth_wire = tunnel
            .encode_auth_heartbeat("edge-test-session", 0, "token-123")
            .unwrap();
        let mut auth_buf = BytesMut::from(&auth_wire[..]);
        let frame = server_rx.decode_inbound(&mut auth_buf).unwrap().unwrap();
        assert_eq!(frame.header.stream_id, 0);
        assert_eq!(&frame.payload[..], b"edge-test-session:0:token-123");

        // Данные в обе стороны на прикладном stream_id.
        let data_wire = tunnel
            .encode_frame(1, EdgeFrameKind::Data, Bytes::from_static(b"hello backend"))
            .unwrap();
        let mut data_buf = BytesMut::from(&data_wire[..]);
        let frame = server_rx.decode_inbound(&mut data_buf).unwrap().unwrap();
        assert_eq!(frame.header.stream_id, 1);
        assert_eq!(&frame.payload[..], b"hello backend");

        let reply_wire = server_tx
            .encode_frame(1, FrameType::Data, Bytes::from_static(b"hello edge"))
            .unwrap();
        let frames = tunnel.feed(&reply_wire).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].stream_id, 1);
        assert!(matches!(frames[0].kind, EdgeFrameKind::Data));
        assert_eq!(&frames[0].payload[..], b"hello edge");
    }
}
