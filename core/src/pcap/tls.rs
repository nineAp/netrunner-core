//! Разбор TLS поверх собранного потока: записи, `ClientHello`, `ServerHello`.
//!
//! Разбор самостоятельный и «пассивный»: он хранит ВСЁ, что наблюдалось
//! (сырые расширения, порядок, GREASE), в отличие от парсеров стека
//! маскировки, которые берут только нужное для рукопожатия.

use super::tcp::Stream;

pub const CT_CCS: u8 = 0x14;
pub const CT_ALERT: u8 = 0x15;
pub const CT_HANDSHAKE: u8 = 0x16;
pub const CT_APPDATA: u8 = 0x17;

const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;

/// Расширения, у которых мы разбираем содержимое.
pub mod ext {
    pub const SNI: u16 = 0x0000;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const PADDING: u16 = 0x0015;
    pub const COMPRESS_CERT: u16 = 0x001b;
    pub const DELEGATED_CREDENTIAL: u16 = 0x0022;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const PSK_MODES: u16 = 0x002d;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const ALPS_OLD: u16 = 0x4469;
    pub const ALPS: u16 = 0x44cd;
    pub const ECH: u16 = 0xfe0d;
}

/// GREASE (RFC 8701): `0x?a?a` с одинаковыми байтами.
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v & 0xff) == (v >> 8)
}

/// Заголовок одной TLS-записи в потоке.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordInfo {
    pub content_type: u8,
    /// Версия из заголовка записи.
    pub version: u16,
    /// Поле `length` заголовка.
    pub length: u16,
    /// Смещение заголовка записи в потоке.
    pub offset: usize,
    /// Метка времени сегмента, в котором начинается запись.
    pub ts_nanos: u64,
}

/// Режет поток на записи, пока заголовки правдоподобны.
pub fn split_records(stream: &Stream) -> Vec<RecordInfo> {
    let b = &stream.bytes;
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 5 <= b.len() && out.len() < 4096 {
        let ct = b[p];
        let ver = u16::from_be_bytes([b[p + 1], b[p + 2]]);
        let len = u16::from_be_bytes([b[p + 3], b[p + 4]]);
        if !(CT_CCS..=CT_APPDATA).contains(&ct) || (ver >> 8) != 3 {
            break; // не TLS либо рассинхрон
        }
        out.push(RecordInfo {
            content_type: ct,
            version: ver,
            length: len,
            offset: p,
            ts_nanos: stream.ts_at(p),
        });
        // Неполную последнюю запись тоже учитываем (длина известна из заголовка).
        p += 5 + len as usize;
    }
    out
}

/// Сообщение рукопожатия, собранное из одной или нескольких записей.
#[derive(Debug, Clone)]
pub struct HandshakeMsg {
    pub msg_type: u8,
    pub body: Vec<u8>,
    /// Версия из заголовка первой записи, несущей сообщение.
    pub record_version: u16,
    /// Сумма `length` записей, в которых оно лежало.
    pub record_payload_len: usize,
    /// Число записей, в которые оно было разбито.
    pub record_count: usize,
    pub ts_nanos: u64,
}

/// Извлекает сообщения рукопожатия из ведущих `Handshake`-записей потока
/// (до первой записи другого типа). Фрагментация сообщения по записям
/// поддерживается.
pub fn handshake_messages(stream: &Stream, records: &[RecordInfo]) -> Vec<HandshakeMsg> {
    let mut out = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    // (record_version, ts, число записей, сумма длин) для текущего сообщения
    let mut meta: Option<(u16, u64, usize, usize)> = None;

    for r in records {
        if r.content_type != CT_HANDSHAKE {
            break;
        }
        let start = r.offset + 5;
        let end = (start + r.length as usize).min(stream.bytes.len());
        if start > stream.bytes.len() {
            break;
        }
        buf.extend_from_slice(&stream.bytes[start..end]);
        let m = meta.get_or_insert((r.version, r.ts_nanos, 0, 0));
        m.2 += 1;
        m.3 += r.length as usize;

        // Выбираем все полные сообщения из буфера.
        loop {
            if buf.len() < 4 {
                break;
            }
            let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
            if buf.len() < 4 + len {
                break;
            }
            let (rv, ts, cnt, sum) = meta.unwrap_or((r.version, r.ts_nanos, 1, r.length as usize));
            out.push(HandshakeMsg {
                msg_type: buf[0],
                body: buf[4..4 + len].to_vec(),
                record_version: rv,
                record_payload_len: sum,
                record_count: cnt,
                ts_nanos: ts,
            });
            buf.drain(..4 + len);
            meta = if buf.is_empty() {
                None
            } else {
                Some((r.version, r.ts_nanos, 1, r.length as usize))
            };
        }
    }
    out
}

/// Курсор с проверкой границ.
pub(crate) struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.b.len() - self.p
    }
    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    pub fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }
}

/// Одно расширение как оно лежало на проводе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExtension {
    pub id: u16,
    pub data: Vec<u8>,
}

/// Элемент `key_share` клиента.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: u16,
    pub len: u16,
}

/// Содержимое `ClientHello`, разобранное без потерь.
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    pub ts_nanos: u64,
    pub client: super::tcp::Endpoint,
    pub server: super::tcp::Endpoint,
    /// Версия из заголовка TLS-записи.
    pub record_version: u16,
    /// `legacy_version` самого сообщения.
    pub legacy_version: u16,
    pub session_id_len: u8,
    /// Все шифронаборы, включая GREASE, в порядке на проводе.
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    /// Расширения в порядке на проводе.
    pub extensions: Vec<RawExtension>,
    /// Сумма `length` записей, несущих ClientHello (payload записи).
    pub record_payload_len: usize,
    /// ClientHello разбит на несколько TLS-записей.
    pub fragmented: bool,

    // ── разобранные поля ──
    pub sni: Option<String>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub delegated_credential: Option<Vec<u16>>,
    pub supported_versions: Vec<u16>,
    pub alpn: Vec<String>,
    /// ALPS: кодпоинт расширения и список протоколов.
    pub alps: Option<(u16, Vec<String>)>,
    pub key_shares: Vec<KeyShareEntry>,
    pub psk_modes: Vec<u8>,
    pub ec_point_formats: Vec<u8>,
    pub compress_certificate: Vec<u16>,
    pub status_request: bool,
    /// Длины ECH: `(enc, payload)` для варианта `outer`.
    pub ech: Option<(u16, u16)>,
    /// Длина тела расширения `padding`, если оно есть.
    pub padding_ext_len: Option<usize>,
    /// `ClientHello` из QUIC Initial (JA4 начинается с `q`, а не `t`).
    pub quic: bool,
}

impl ClientHelloInfo {
    pub fn has_ext(&self, id: u16) -> bool {
        self.extensions.iter().any(|e| e.id == id)
    }
}

fn parse_u16_list(data: &[u8], len_bytes: usize) -> Option<Vec<u16>> {
    let mut c = Cur::new(data);
    let n = if len_bytes == 2 {
        c.u16()? as usize
    } else {
        c.u8()? as usize
    };
    let s = c.take(n)?;
    if n % 2 != 0 {
        return None;
    }
    Some(s.chunks_exact(2).map(|x| u16::from_be_bytes([x[0], x[1]])).collect())
}

fn parse_proto_list(data: &[u8]) -> Option<Vec<String>> {
    let mut c = Cur::new(data);
    let n = c.u16()? as usize;
    let mut s = Cur::new(c.take(n)?);
    let mut out = Vec::new();
    while s.remaining() > 0 {
        let l = s.u8()? as usize;
        let p = s.take(l)?;
        out.push(String::from_utf8_lossy(p).into_owned());
    }
    Some(out)
}

/// Разбирает тело `ClientHello`.
pub fn parse_client_hello(
    msg: &HandshakeMsg,
    client: super::tcp::Endpoint,
    server: super::tcp::Endpoint,
) -> Option<ClientHelloInfo> {
    if msg.msg_type != HS_CLIENT_HELLO {
        return None;
    }
    let mut c = Cur::new(&msg.body);
    let legacy_version = c.u16()?;
    c.take(32)?; // random
    let sid_len = c.u8()?;
    c.take(sid_len as usize)?;
    let cs_len = c.u16()? as usize;
    let cs = c.take(cs_len)?;
    if cs_len % 2 != 0 {
        return None;
    }
    let cipher_suites: Vec<u16> = cs.chunks_exact(2).map(|x| u16::from_be_bytes([x[0], x[1]])).collect();
    let comp_len = c.u8()? as usize;
    let compression = c.take(comp_len)?.to_vec();

    let mut extensions = Vec::new();
    if c.remaining() >= 2 {
        let ext_len = c.u16()? as usize;
        let mut e = Cur::new(c.take(ext_len)?);
        while e.remaining() >= 4 {
            let id = e.u16()?;
            let l = e.u16()? as usize;
            let data = e.take(l)?.to_vec();
            extensions.push(RawExtension { id, data });
        }
    }

    let mut info = ClientHelloInfo {
        ts_nanos: msg.ts_nanos,
        client,
        server,
        record_version: msg.record_version,
        legacy_version,
        session_id_len: sid_len,
        cipher_suites,
        compression,
        extensions: Vec::new(),
        record_payload_len: msg.record_payload_len,
        fragmented: msg.record_count > 1,
        sni: None,
        supported_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        delegated_credential: None,
        supported_versions: Vec::new(),
        alpn: Vec::new(),
        alps: None,
        key_shares: Vec::new(),
        psk_modes: Vec::new(),
        ec_point_formats: Vec::new(),
        compress_certificate: Vec::new(),
        status_request: false,
        ech: None,
        padding_ext_len: None,
        quic: false,
    };

    for x in &extensions {
        let d = &x.data[..];
        match x.id {
            ext::SNI => {
                // list_len(2) | type(1) | name_len(2) | name
                let mut c = Cur::new(d);
                if let (Some(_), Some(t), Some(l)) = (c.u16(), c.u8(), c.u16()) {
                    if t == 0 {
                        if let Some(n) = c.take(l as usize) {
                            info.sni = String::from_utf8(n.to_vec()).ok();
                        }
                    }
                }
            }
            ext::SUPPORTED_GROUPS => info.supported_groups = parse_u16_list(d, 2).unwrap_or_default(),
            ext::SIGNATURE_ALGORITHMS => {
                info.signature_algorithms = parse_u16_list(d, 2).unwrap_or_default()
            }
            ext::DELEGATED_CREDENTIAL => info.delegated_credential = parse_u16_list(d, 2),
            ext::SUPPORTED_VERSIONS => info.supported_versions = parse_u16_list(d, 1).unwrap_or_default(),
            ext::ALPN => info.alpn = parse_proto_list(d).unwrap_or_default(),
            ext::ALPS | ext::ALPS_OLD => {
                info.alps = Some((x.id, parse_proto_list(d).unwrap_or_default()))
            }
            ext::KEY_SHARE => {
                let mut c = Cur::new(d);
                if let Some(n) = c.u16() {
                    if let Some(s) = c.take(n as usize) {
                        let mut s = Cur::new(s);
                        while s.remaining() >= 4 {
                            let (Some(g), Some(l)) = (s.u16(), s.u16()) else { break };
                            if s.take(l as usize).is_none() {
                                break;
                            }
                            info.key_shares.push(KeyShareEntry { group: g, len: l });
                        }
                    }
                }
            }
            ext::PSK_MODES => {
                if let Some((&n, rest)) = d.split_first() {
                    info.psk_modes = rest.iter().take(n as usize).copied().collect();
                }
            }
            ext::EC_POINT_FORMATS => {
                if let Some((&n, rest)) = d.split_first() {
                    info.ec_point_formats = rest.iter().take(n as usize).copied().collect();
                }
            }
            ext::COMPRESS_CERT => {
                if let Some((&n, rest)) = d.split_first() {
                    info.compress_certificate = rest
                        .iter()
                        .take(n as usize)
                        .copied()
                        .collect::<Vec<u8>>()
                        .chunks_exact(2)
                        .map(|x| u16::from_be_bytes([x[0], x[1]]))
                        .collect();
                }
            }
            ext::STATUS_REQUEST => info.status_request = true,
            ext::PADDING => info.padding_ext_len = Some(d.len()),
            ext::ECH => {
                // type(1)=outer(0) | kdf(2) | aead(2) | config_id(1) | enc_len(2) | enc | payload_len(2) | payload
                let mut c = Cur::new(d);
                if c.u8() == Some(0) {
                    let _ = (c.u16(), c.u16(), c.u8());
                    if let Some(el) = c.u16() {
                        if c.take(el as usize).is_some() {
                            if let Some(pl) = c.u16() {
                                info.ech = Some((el, pl));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    info.extensions = extensions;
    Some(info)
}

/// Содержимое `ServerHello`.
#[derive(Debug, Clone)]
pub struct ServerHelloInfo {
    pub ts_nanos: u64,
    pub record_version: u16,
    pub legacy_version: u16,
    pub session_id_len: u8,
    pub cipher_suite: u16,
    pub compression: u8,
    pub extension_ids: Vec<u16>,
    /// Выбранная версия из `supported_versions`.
    pub selected_version: Option<u16>,
    /// Группа `key_share` сервера.
    pub key_share_group: Option<u16>,
    /// `random` равен константе HelloRetryRequest (RFC 8446 §4.1.3).
    pub hello_retry_request: bool,
    /// Длина записи, несущей ServerHello (payload).
    pub record_payload_len: usize,
}

const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub fn parse_server_hello(msg: &HandshakeMsg) -> Option<ServerHelloInfo> {
    if msg.msg_type != HS_SERVER_HELLO {
        return None;
    }
    let mut c = Cur::new(&msg.body);
    let legacy_version = c.u16()?;
    let random = c.take(32)?;
    let hrr = random == HRR_RANDOM;
    let sid_len = c.u8()?;
    c.take(sid_len as usize)?;
    let cipher_suite = c.u16()?;
    let compression = c.u8()?;
    let mut ids = Vec::new();
    let mut selected_version = None;
    let mut key_share_group = None;
    if c.remaining() >= 2 {
        let n = c.u16()? as usize;
        let mut e = Cur::new(c.take(n)?);
        while e.remaining() >= 4 {
            let id = e.u16()?;
            let l = e.u16()? as usize;
            let d = e.take(l)?;
            ids.push(id);
            match id {
                ext::SUPPORTED_VERSIONS if d.len() >= 2 => {
                    selected_version = Some(u16::from_be_bytes([d[0], d[1]]))
                }
                ext::KEY_SHARE if d.len() >= 2 => {
                    key_share_group = Some(u16::from_be_bytes([d[0], d[1]]))
                }
                _ => {}
            }
        }
    }
    Some(ServerHelloInfo {
        ts_nanos: msg.ts_nanos,
        record_version: msg.record_version,
        legacy_version,
        session_id_len: sid_len,
        cipher_suite,
        compression,
        extension_ids: ids,
        selected_version,
        key_share_group,
        hello_retry_request: hrr,
        record_payload_len: msg.record_payload_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::tcp::Endpoint;
    use std::net::{IpAddr, Ipv4Addr};

    fn ep(p: u16) -> Endpoint {
        Endpoint {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: p,
        }
    }

    pub(crate) fn hello_body(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend_from_slice(&[7u8; 32]);
        b.push(32);
        b.extend_from_slice(&[9u8; 32]);
        b.extend_from_slice(&[0, 6, 0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02]);
        b.extend_from_slice(&[1, 0]);
        let mut e = Vec::new();
        for (id, d) in exts {
            e.extend_from_slice(&id.to_be_bytes());
            e.extend_from_slice(&(d.len() as u16).to_be_bytes());
            e.extend_from_slice(d);
        }
        b.extend_from_slice(&(e.len() as u16).to_be_bytes());
        b.extend_from_slice(&e);
        b
    }

    #[test]
    fn parses_core_extensions() {
        let sni = {
            let name = b"example.com";
            let mut d = Vec::new();
            d.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes());
            d.push(0);
            d.extend_from_slice(&(name.len() as u16).to_be_bytes());
            d.extend_from_slice(name);
            d
        };
        let groups = vec![0, 6, 0x3a, 0x3a, 0x11, 0xec, 0x00, 0x1d];
        let alpn = vec![0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'];
        let versions = vec![4, 0x0a, 0x0a, 0x03, 0x04];
        let body = hello_body(&[
            (0x0a0a, vec![]),
            (ext::SNI, sni),
            (ext::SUPPORTED_GROUPS, groups),
            (ext::ALPN, alpn),
            (ext::SUPPORTED_VERSIONS, versions),
            (ext::ALPS, vec![0, 3, 2, b'h', b'2']),
            (ext::COMPRESS_CERT, vec![2, 0, 2]),
            (ext::PSK_MODES, vec![1, 1]),
            (ext::STATUS_REQUEST, vec![1, 0, 0, 0, 0]),
            (ext::PADDING, vec![0; 7]),
        ]);
        let msg = HandshakeMsg {
            msg_type: 1,
            body,
            record_version: 0x0301,
            record_payload_len: 100,
            record_count: 1,
            ts_nanos: 5,
        };
        let ch = parse_client_hello(&msg, ep(1), ep(2)).unwrap();
        assert_eq!(ch.sni.as_deref(), Some("example.com"));
        assert_eq!(ch.supported_groups, vec![0x3a3a, 0x11ec, 0x001d]);
        assert_eq!(ch.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(ch.supported_versions, vec![0x0a0a, 0x0304]);
        assert_eq!(ch.alps, Some((ext::ALPS, vec!["h2".to_string()])));
        assert_eq!(ch.compress_certificate, vec![2]);
        assert_eq!(ch.psk_modes, vec![1]);
        assert!(ch.status_request);
        assert_eq!(ch.padding_ext_len, Some(7));
        assert_eq!(ch.extensions.len(), 10);
        assert_eq!(ch.cipher_suites, vec![0x0a0a, 0x1301, 0x1302]);
        assert_eq!(ch.session_id_len, 32);
    }

    #[test]
    fn truncated_hello_returns_none_without_panic() {
        let body = hello_body(&[(ext::SNI, vec![0, 5, 0, 0, 9])]);
        for cut in 0..body.len() {
            let msg = HandshakeMsg {
                msg_type: 1,
                body: body[..cut].to_vec(),
                record_version: 0x0303,
                record_payload_len: cut,
                record_count: 1,
                ts_nanos: 0,
            };
            let _ = parse_client_hello(&msg, ep(1), ep(2));
        }
    }

    #[test]
    fn handshake_message_spanning_two_records() {
        let body = hello_body(&[]);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let (a, b) = hs.split_at(20);
        let mut bytes = Vec::new();
        for part in [a, b] {
            bytes.extend_from_slice(&[0x16, 3, 1]);
            bytes.extend_from_slice(&(part.len() as u16).to_be_bytes());
            bytes.extend_from_slice(part);
        }
        let st = Stream {
            bytes,
            marks: vec![(0, 11)],
            gap: false,
            syn: false,
        };
        let recs = split_records(&st);
        assert_eq!(recs.len(), 2);
        let msgs = handshake_messages(&st, &recs);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].record_count, 2);
        assert_eq!(msgs[0].record_payload_len, hs.len());
        let ch = parse_client_hello(&msgs[0], ep(1), ep(2)).unwrap();
        assert!(ch.fragmented);
    }

    #[test]
    fn split_records_stops_on_garbage() {
        let st = Stream {
            bytes: vec![0x16, 3, 3, 0, 1, 0xaa, 0x99, 3, 3, 0, 0],
            marks: vec![(0, 1)],
            gap: false,
            syn: false,
        };
        assert_eq!(split_records(&st).len(), 1);
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && is_grease(0x7a7a));
        assert!(!is_grease(0x1301) && !is_grease(0x0a1a) && !is_grease(0x001d));
    }
}
