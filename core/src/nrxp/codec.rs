//! Шифрующий кодек: мост между кадрами [`Frame`] и зашифрованными TLS-записями.
//!
//! Это слой, где встречаются протокол ([`nrxp::frame`](super::frame)),
//! криптография ([`crypto`](crate::crypto)) и TLS-обёртка ([`bridge`](super::bridge)).
//! Кодек разнесён на два независимых направления, чтобы чтение и запись жили в
//! разных задачах tokio без общего мьютекса:
//!
//! - [`TxCodec`] — `Frame` → AEAD-шифр in-place → TLS `ApplicationData`;
//! - [`RxCodec`] — TLS `ApplicationData` → AEAD-дешифр in-place → `Frame`.
//!
//! [`Codec`] — лишь фабрика: создаёт оба направления из одного [`ChaChaCipher`] и
//! `auth_key`, после чего [`split`](Codec::split) раздаёт их reader'у и writer'у.
//!
//! ## Буфер `staging` в [`RxCodec`]
//!
//! Опирается на инвариант «1 TLS-запись = 1 кадр NRXP». TLS-записи
//! расшифровываются по одной в общий буфер `staging`, и сразу делается попытка
//! распарсить кадр. `staging` переживает вызовы `decode_inbound`: если в одном
//! TCP-чтении пришло несколько записей, лишние остаются в нём до следующего
//! вызова. Любой провал AEAD или парсинга после успешной расшифровки трактуется
//! как рассинхрон/tampering → [`ErrorAction::Drop`] (пересоздать ногу с нуля).

use crate::crypto::{AeadPacker, ChaChaCipher, ChaChaStream, SessionAuth};
use crate::nrxp::bridge::TlsBridge;
use crate::nrxp::errors::{ErrorAction, ErrorStage, TlsError};
use crate::nrxp::frame::{Frame, FrameType};
use crate::parser::Parser;
use bytes::{Bytes, BytesMut};

/// Исходящее направление: шифрует кадры для отправки в туннель.
pub struct TxCodec {
    crypto: ChaChaStream,
    auth: SessionAuth,
}

impl TxCodec {
    pub fn new(crypto: ChaChaStream, auth: SessionAuth) -> Self {
        Self { crypto, auth }
    }

    /// Кодирует один кадр в готовую к отправке TLS-запись `ApplicationData`.
    ///
    /// Шаги: сгенерировать time-based тег → собрать байты кадра → зашифровать
    /// in-place (буфер вырастает на 16 байт AEAD-тега) → обернуть в TLS-запись.
    /// Любая ошибка шифрования критична → [`ErrorAction::Drop`].
    pub(crate) fn encode_frame(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
    ) -> Result<Bytes, TlsError> {
        let tag = self.auth.generate_current_tag();
        let frame = Frame::new(stream_id, frame_type, payload);

        // frame_bytes — это BytesMut. Выделяем и формируем заголовок.
        let mut frame_bytes = frame.into_bytes(&tag);

        // Шифруем In-Place. Массив frame_bytes мутирует и вырастает на 16 байт тега AEAD.
        self.crypto.encrypt(&mut frame_bytes).map_err(|e| {
            netrunner_logger::error!("Encryption failed: {:?}", e);
            TlsError::new(
                ErrorStage::Tls("Encryption failed"),
                ErrorAction::Drop,
                Bytes::new(),
            )
        })?;

        // Только в самом конце замораживаем буфер (Zero-Copy операция) для отправки
        Ok(TlsBridge::pack_app_data(frame_bytes.freeze()))
    }
}

/// Входящее направление: расшифровывает TLS-записи и собирает из них кадры.
pub struct RxCodec {
    crypto: ChaChaStream,
    auth: SessionAuth,
    /// Накопитель расшифрованного открытого текста между вызовами `decode_inbound`
    /// (хранит «хвост» кадров, не разобранных в текущем вызове).
    staging: BytesMut,
}

impl RxCodec {
    pub fn new(crypto: ChaChaStream, auth: SessionAuth, staging: BytesMut) -> Self {
        Self {
            crypto,
            auth,
            staging,
        }
    }
    /// Пытается извлечь **один** следующий кадр из накопленных TCP-данных.
    ///
    /// Возвращает `Ok(Some(frame))`, если кадр готов; `Ok(None)`, если данных
    /// пока недостаточно (ждём следующего чтения сокета); `Err(Drop)` при провале
    /// AEAD/парсинга. Сначала дочищает «хвост» из `staging`, затем по одной
    /// расшифровывает новые TLS-записи из `buffer`.
    pub(crate) fn decode_inbound(
        &mut self,
        buffer: &mut BytesMut,
    ) -> Result<Option<Frame>, TlsError> {
        // Drain any complete frame that was left in staging from the previous call.
        // This happens when multiple TLS records arrived in one TCP read and we
        // returned after the first parsed frame, leaving the rest in staging.
        if !self.staging.is_empty() {
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }
        }

        // Encoding invariant: one TLS ApplicationData record = one encrypted NRXP
        // frame.  We decrypt each record independently into the staging buffer and
        // immediately attempt to parse.  split_off + decrypt_in_place + unsplit is
        // used to keep the decrypted bytes in staging's existing allocation (zero
        // extra allocation on the fast path).
        while let Some(app_data) = TlsBridge::unpack_app_data(buffer)? {
            let start_idx = self.staging.len();
            self.staging.extend_from_slice(&app_data.payload);

            // Split off just the new encrypted bytes; staging[..start_idx] holds
            // any prior plaintext that is still waiting for a parse attempt.
            let mut data_to_decrypt = self.staging.split_off(start_idx);

            if let Err(_) = self.crypto.decrypt(&mut data_to_decrypt) {
                // AEAD failure after a successful TCP delivery means key/nonce
                // mismatch or tampering.  Clear staging to avoid feeding garbled
                // plaintext into the parser on the next call, then signal Drop so
                // the caller tears down and reconnects (fresh keys, nonce=0).
                self.staging.clear();
                return Err(TlsError::new(
                    ErrorStage::Tls("AEAD Decrypt Failed"),
                    ErrorAction::Drop,
                    Bytes::new(),
                ));
            }

            // Re-join: staging now contains [prev_plaintext || new_plaintext].
            // decrypt_in_place shrank data_to_decrypt by 16 (stripped AEAD tag);
            // unsplit handles the adjusted length correctly because the underlying
            // allocation is contiguous and data_to_decrypt is still adjacent.
            self.staging.unsplit(data_to_decrypt);

            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }

            // try_parse_frame returned Ok(None) — this should never happen with the
            // 1:1 TLS-record→NRXP-frame invariant, but if it does (e.g. an empty
            // padding-only frame), we continue to the next TLS record rather than
            // looping indefinitely.  The staging bytes will be parsed on the next
            // decode_inbound call.
        }

        Ok(None)
    }

    fn try_parse_frame(&mut self) -> Result<Option<Frame>, TlsError> {
        match Frame::parse(&mut self.staging) {
            Ok(Some(frame)) => Ok(Some(frame)),
            Ok(None) => Ok(None),
            Err(e) => {
                // Frame::parse only returns Err for protocol-level violations
                // (e.g. unknown FrameType byte) that survive AEAD decryption.
                // This is not a partial-data situation — it means the stream is
                // desynchronised. Drop the leg so reconnect generates fresh keys.
                netrunner_logger::error!(
                    "Frame parse error after AEAD success — dropping leg: {}",
                    e
                );
                self.staging.clear();
                Err(TlsError::new(
                    crate::nrxp::errors::ErrorStage::Tls("Frame parse error"),
                    crate::nrxp::errors::ErrorAction::Drop,
                    bytes::Bytes::new(),
                ))
            }
        }
    }
}

/// Фабрика кодеков: владеет обоими направлениями до момента, пока их не раздадут
/// в задачи reader/writer через [`split`](Codec::split).
pub struct Codec {
    tx: Option<TxCodec>,
    rx: Option<RxCodec>,
}

impl Codec {
    /// Создаёт оба направления из шифра сессии и ключа аутентификации.
    /// `auth` (одна `SessionAuth`) общий для tx и rx — тег зависит только от
    /// времени и `auth_key`, а не от направления.
    pub fn new(cipher: ChaChaCipher, auth_key: [u8; 32]) -> Self {
        let (rx_stream, tx_stream) = cipher.split();
        let auth = SessionAuth::new(auth_key);

        Self {
            tx: Some(TxCodec::new(tx_stream, auth)),
            rx: Some(RxCodec::new(rx_stream, auth, BytesMut::with_capacity(4096))),
        }
    }

    pub fn split(mut self) -> (RxCodec, TxCodec) {
        (
            self.rx.take().expect("RxCodec missing"),
            self.tx.take().expect("TxCodec missing"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ChaChaCipher;

    const AUTH_KEY: [u8; 32] = [0x11; 32];
    const KEY_A: [u8; 32] = [0xAA; 32];
    const IV_A: [u8; 12] = [0x01; 12];
    const KEY_B: [u8; 32] = [0xBB; 32];
    const IV_B: [u8; 12] = [0x02; 12];

    /// Пара codec'ов "клиент+сервер" с ключами, зеркальными друг другу — так же,
    /// как их реально назначает `SessionKeys::generate_keys` по ролям (tx одной
    /// стороны == rx другой).
    fn client_server_pair() -> ((RxCodec, TxCodec), (RxCodec, TxCodec)) {
        let mut client_cipher = ChaChaCipher::new();
        client_cipher.set_keys(KEY_A, IV_A, KEY_B, IV_B); // tx=A, rx=B
        let mut server_cipher = ChaChaCipher::new();
        server_cipher.set_keys(KEY_B, IV_B, KEY_A, IV_A); // tx=B, rx=A

        (
            Codec::new(client_cipher, AUTH_KEY).split(),
            Codec::new(server_cipher, AUTH_KEY).split(),
        )
    }

    #[test]
    fn client_to_server_round_trip() {
        let ((_client_rx, mut client_tx), (mut server_rx, _server_tx)) = client_server_pair();

        let wire = client_tx
            .encode_frame(
                5,
                FrameType::Data,
                Bytes::from_static(b"payload from client"),
            )
            .unwrap();

        let mut buf = BytesMut::from(&wire[..]);
        let frame = server_rx.decode_inbound(&mut buf).unwrap().unwrap();

        assert_eq!(frame.header.stream_id, 5);
        assert_eq!(frame.header.frame_type, FrameType::Data);
        assert_eq!(&frame.payload[..], b"payload from client");
    }

    #[test]
    fn server_to_client_round_trip() {
        let ((mut client_rx, _client_tx), (_server_rx, mut server_tx)) = client_server_pair();

        let wire = server_tx
            .encode_frame(6, FrameType::Heartbeat, Bytes::from_static(b"pong"))
            .unwrap();

        let mut buf = BytesMut::from(&wire[..]);
        let frame = client_rx.decode_inbound(&mut buf).unwrap().unwrap();
        assert_eq!(&frame.payload[..], b"pong");
    }

    #[test]
    fn sequential_frames_keep_nonce_counters_in_sync() {
        let ((_client_rx, mut client_tx), (mut server_rx, _server_tx)) = client_server_pair();

        for i in 0..20u32 {
            let payload = format!("frame-{i}");
            let wire = client_tx
                .encode_frame(1, FrameType::Data, Bytes::from(payload.clone()))
                .unwrap();
            let mut buf = BytesMut::from(&wire[..]);
            let frame = server_rx.decode_inbound(&mut buf).unwrap().unwrap();
            assert_eq!(&frame.payload[..], payload.as_bytes());
        }
    }

    #[test]
    fn tampered_ciphertext_fails_aead_and_drops() {
        let ((_client_rx, mut client_tx), (mut server_rx, _server_tx)) = client_server_pair();

        let wire = client_tx
            .encode_frame(1, FrameType::Data, Bytes::from_static(b"secret"))
            .unwrap();

        let mut tampered = BytesMut::from(&wire[..]);
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF; // flip a byte inside the AEAD tag

        let result = server_rx.decode_inbound(&mut tampered);
        assert!(result.is_err(), "tampered ciphertext must not decrypt");
    }

    #[test]
    fn replayed_frame_desyncs_nonce_and_fails() {
        // Кадр расшифровывается один раз успешно; повторная подача ТЕХ ЖЕ байт
        // получателю с уже продвинувшимся счётчиком nonce должна провалиться —
        // это и есть встроенная защита от replay на уровне AEAD-потока.
        let ((_client_rx, mut client_tx), (mut server_rx, _server_tx)) = client_server_pair();

        let wire = client_tx
            .encode_frame(1, FrameType::Data, Bytes::from_static(b"once"))
            .unwrap();

        let mut first = BytesMut::from(&wire[..]);
        assert!(server_rx.decode_inbound(&mut first).unwrap().is_some());

        let mut replay = BytesMut::from(&wire[..]);
        assert!(server_rx.decode_inbound(&mut replay).is_err());
    }
}
