//! Разбор клиентских QUIC Initial-пакетов: `ClientHello` и форма пакета.
//!
//! Ключи Initial выводятся из **публичной** соли и открытого Destination
//! Connection ID (RFC 9001 §5.2), поэтому `ClientHello` из захвата достаётся без
//! чьих-либо секретов — ровно так делает любой DPI и наш `quiceng` при сборке
//! декоративного Initial. Поддерживается QUIC версии 1 (RFC 9000/9001); версия 2
//! и черновики пропускаются с замечанием.
//!
//! Chrome с постквантовым `key_share` не умещает `ClientHello` в один пакет:
//! CRYPTO-поток режется на несколько Initial'ов в разных датаграммах. Поэтому
//! потоки собираются по `(клиент, сервер, DCID)` и склеиваются по смещениям.

use std::collections::BTreeMap;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes128Gcm};
use hkdf::Hkdf;
use sha2::Sha256;

use super::tcp::Endpoint;
use super::tls::{parse_client_hello, ClientHelloInfo, HandshakeMsg};

/// Версия QUIC 1.
pub const QUIC_V1: u32 = 1;
/// Тип расширения `quic_transport_parameters` (RFC 9001 §8.2).
pub const EXT_QUIC_TP: u16 = 0x0039;

/// RFC 9001 §5.2.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Ключи Initial одного направления.
#[derive(Debug, PartialEq, Eq)]
pub struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

fn expand_label<const N: usize>(prk: &Hkdf<Sha256>, label: &[u8]) -> [u8; N] {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&(N as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let mut out = [0u8; N];
    // Длины фиксированы и малы — ошибка невозможна.
    let _ = prk.expand(&info, &mut out);
    out
}

/// Ключи Initial для `dcid` (клиентского направления, если `client`).
pub fn initial_keys(dcid: &[u8], client: bool) -> InitialKeys {
    let initial = Hkdf::<Sha256>::new(Some(&INITIAL_SALT_V1), dcid);
    let secret: [u8; 32] = expand_label(&initial, if client { b"client in" } else { b"server in" });
    let prk = Hkdf::<Sha256>::from_prk(&secret).expect("32-byte PRK");
    InitialKeys {
        key: expand_label(&prk, b"quic key"),
        iv: expand_label(&prk, b"quic iv"),
        hp: expand_label(&prk, b"quic hp"),
    }
}

/// Читает QUIC varint, возвращает `(значение, длина)`.
pub(crate) fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for x in &b[1..len] {
        v = (v << 8) | *x as u64;
    }
    Some((v, len))
}

/// Кадр Initial-пакета в порядке следования (содержимое CRYPTO отдельно).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameKind {
    Padding(usize),
    Ping,
    Ack,
    Crypto { offset: u64, len: usize },
    /// Любой другой тип кадра (останавливает разбор оставшейся части).
    Other(u64),
}

/// Один расшифрованный клиентский Initial-пакет.
#[derive(Debug, Clone)]
pub struct InitialPacket {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token_len: usize,
    /// Первый байт пакета после снятия защиты заголовка.
    pub first_byte: u8,
    pub pn: u64,
    pub pn_len: usize,
    /// Длина этого пакета целиком (заголовок + нагрузка + тег).
    pub packet_len: usize,
    /// Длина UDP-нагрузки датаграммы, в которой он пришёл.
    pub datagram_len: usize,
    pub frames: Vec<FrameKind>,
    /// Куски CRYPTO-потока: `(смещение, данные)`.
    pub crypto: Vec<(u64, Vec<u8>)>,
}

/// Почему пакет не разобран (для замечаний по захвату).
#[derive(Debug, PartialEq, Eq)]
pub enum Skip {
    NotLongHeader,
    /// Не Initial (Handshake/0-RTT/Retry) — в датаграмме может идти вслед за Initial.
    OtherLongType,
    UnsupportedVersion(u32),
    Malformed,
    DecryptFailed,
}

/// Разбирает один пакет с начала `buf`. Возвращает пакет и сколько байт он занял
/// (датаграмма может содержать несколько склеенных пакетов).
pub fn parse_initial(buf: &[u8], datagram_len: usize) -> Result<(InitialPacket, usize), Skip> {
    let first = *buf.first().ok_or(Skip::Malformed)?;
    if first & 0x80 == 0 {
        return Err(Skip::NotLongHeader);
    }
    let version = u32::from_be_bytes(buf.get(1..5).ok_or(Skip::Malformed)?.try_into().unwrap());
    let mut p = 5usize;
    let dcid_len = *buf.get(p).ok_or(Skip::Malformed)? as usize;
    p += 1;
    if dcid_len > 20 {
        return Err(Skip::Malformed);
    }
    let dcid = buf.get(p..p + dcid_len).ok_or(Skip::Malformed)?.to_vec();
    p += dcid_len;
    let scid_len = *buf.get(p).ok_or(Skip::Malformed)? as usize;
    p += 1;
    if scid_len > 20 {
        return Err(Skip::Malformed);
    }
    let scid = buf.get(p..p + scid_len).ok_or(Skip::Malformed)?.to_vec();
    p += scid_len;

    if version != QUIC_V1 {
        return Err(Skip::UnsupportedVersion(version));
    }
    if (first >> 4) & 0x03 != 0 {
        return Err(Skip::OtherLongType);
    }
    let (token_len, n) = varint(buf.get(p..).ok_or(Skip::Malformed)?).ok_or(Skip::Malformed)?;
    p += n;
    p = p.checked_add(token_len as usize).ok_or(Skip::Malformed)?;
    let (length, n) = varint(buf.get(p..).ok_or(Skip::Malformed)?).ok_or(Skip::Malformed)?;
    p += n;
    let pn_offset = p;
    let packet_end = pn_offset.checked_add(length as usize).ok_or(Skip::Malformed)?;
    if packet_end > buf.len() || length < 4 + 16 + 1 {
        return Err(Skip::Malformed);
    }

    // Снятие защиты заголовка (RFC 9001 §5.4): sample берётся на 4 байта позже
    // начала поля номера пакета.
    let keys = initial_keys(&dcid, true);
    let sample: [u8; 16] = buf
        .get(pn_offset + 4..pn_offset + 20)
        .ok_or(Skip::Malformed)?
        .try_into()
        .unwrap();
    let mut block = *GenericArray::from_slice(&sample);
    Aes128::new(GenericArray::from_slice(&keys.hp)).encrypt_block(&mut block);
    let first_plain = first ^ (block[0] & 0x0f);
    let pn_len = (first_plain & 0x03) as usize + 1;
    let mut pn = 0u64;
    let mut header = buf[..pn_offset + pn_len].to_vec();
    header[0] = first_plain;
    for i in 0..pn_len {
        header[pn_offset + i] ^= block[1 + i];
        pn = (pn << 8) | header[pn_offset + i] as u64;
    }

    // AEAD (RFC 9001 §5.3): nonce = iv XOR pn.
    let mut nonce = keys.iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= *b;
    }
    let mut body = buf[pn_offset + pn_len..packet_end].to_vec();
    Aes128Gcm::new(GenericArray::from_slice(&keys.key))
        .decrypt_in_place(GenericArray::from_slice(&nonce), &header, &mut body)
        .map_err(|_| Skip::DecryptFailed)?;

    let (frames, crypto) = parse_frames(&body);
    Ok((
        InitialPacket {
            version,
            dcid,
            scid,
            token_len: token_len as usize,
            first_byte: first_plain,
            pn,
            pn_len,
            packet_len: packet_end,
            datagram_len,
            frames,
            crypto,
        },
        packet_end,
    ))
}

fn parse_frames(mut b: &[u8]) -> (Vec<FrameKind>, Vec<(u64, Vec<u8>)>) {
    let mut frames = Vec::new();
    let mut crypto = Vec::new();
    while let Some(&t) = b.first() {
        match t {
            0x00 => {
                let n = b.iter().take_while(|x| **x == 0).count();
                frames.push(FrameKind::Padding(n));
                b = &b[n..];
            }
            0x01 => {
                frames.push(FrameKind::Ping);
                b = &b[1..];
            }
            0x02 | 0x03 => {
                // largest, delay, range_count, first_range, [gap, len]*, [ecn×3]
                let mut p = 1;
                let get = |p: &mut usize| -> Option<u64> {
                    let (v, n) = varint(b.get(*p..)?)?;
                    *p += n;
                    Some(v)
                };
                let ok = (|| {
                    get(&mut p)?;
                    get(&mut p)?;
                    let ranges = get(&mut p)?;
                    get(&mut p)?;
                    for _ in 0..ranges {
                        get(&mut p)?;
                        get(&mut p)?;
                    }
                    if t == 0x03 {
                        for _ in 0..3 {
                            get(&mut p)?;
                        }
                    }
                    Some(())
                })();
                if ok.is_none() {
                    frames.push(FrameKind::Other(t as u64));
                    break;
                }
                frames.push(FrameKind::Ack);
                b = &b[p..];
            }
            0x06 => {
                let Some((off, n1)) = varint(&b[1..]) else { break };
                let Some((len, n2)) = varint(&b[1 + n1..]) else { break };
                let start = 1 + n1 + n2;
                let Some(data) = b.get(start..start + len as usize) else { break };
                frames.push(FrameKind::Crypto { offset: off, len: len as usize });
                crypto.push((off, data.to_vec()));
                b = &b[start + len as usize..];
            }
            other => {
                frames.push(FrameKind::Other(other as u64));
                break;
            }
        }
    }
    (frames, crypto)
}

/// Транспортные параметры в порядке на проводе: `(id, значение)`.
pub fn parse_transport_params(b: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < b.len() {
        let (id, n) = varint(&b[p..])?;
        p += n;
        let (len, n) = varint(b.get(p..)?)?;
        p += n;
        out.push((id, b.get(p..p + len as usize)?.to_vec()));
        p += len as usize;
    }
    Some(out)
}

/// Зарезервированные («GREASE») идентификаторы параметров: `31·N + 27`.
pub fn is_grease_param(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

/// Один QUIC-поток соединения клиента: все его Initial'ы и собранный `ClientHello`.
#[derive(Debug, Clone)]
pub struct QuicFlow {
    pub client: Endpoint,
    pub server: Endpoint,
    pub ts_nanos: u64,
    pub packets: Vec<InitialPacket>,
    /// Разобранный `ClientHello` (если CRYPTO-поток собрался целиком).
    pub hello: Option<ClientHelloInfo>,
    /// Транспортные параметры из `ClientHello`.
    pub transport_params: Vec<(u64, Vec<u8>)>,
}

struct Pending {
    client: Endpoint,
    server: Endpoint,
    dcid: Vec<u8>,
    ts: u64,
    packets: Vec<InitialPacket>,
}

/// Накопитель датаграмм: подаются в порядке захвата.
#[derive(Default)]
pub struct QuicCollector {
    flows: Vec<Pending>,
    pub skipped_versions: Vec<u32>,
    pub undecryptable: usize,
}

impl QuicCollector {
    /// Добавляет UDP-датаграмму от `client` к `server`.
    pub fn push(&mut self, ts: u64, client: Endpoint, server: Endpoint, payload: &[u8]) {
        let mut rest = payload;
        while !rest.is_empty() {
            match parse_initial(rest, payload.len()) {
                Ok((pkt, used)) => {
                    self.add(ts, client, server, pkt);
                    rest = &rest[used..];
                }
                Err(Skip::UnsupportedVersion(v)) => {
                    if !self.skipped_versions.contains(&v) {
                        self.skipped_versions.push(v);
                    }
                    return;
                }
                Err(Skip::DecryptFailed) => {
                    self.undecryptable += 1;
                    return;
                }
                // Handshake/0-RTT и прочее после Initial нас не интересует.
                Err(_) => return,
            }
        }
    }

    fn add(&mut self, ts: u64, client: Endpoint, server: Endpoint, pkt: InitialPacket) {
        match self
            .flows
            .iter_mut()
            .find(|f| f.client == client && f.server == server && f.dcid == pkt.dcid)
        {
            // Тот же пакет дважды: на loopback AF_PACKET отдаёт исходящий и входящий
            // экземпляр, либо датаграмму дублировала сеть — одним пакетом считаем один номер.
            Some(f) if f.packets.iter().any(|p| p.pn == pkt.pn) => {}
            Some(f) => f.packets.push(pkt),
            None => self.flows.push(Pending { client, server, dcid: pkt.dcid.clone(), ts, packets: vec![pkt] }),
        }
    }

    /// Собирает потоки: склеивает CRYPTO и разбирает `ClientHello`.
    pub fn finish(self) -> (Vec<QuicFlow>, Vec<u32>, usize) {
        let flows = self
            .flows
            .into_iter()
            .map(|f| {
                let hello = assemble_hello(&f.packets, f.client, f.server, f.ts);
                let transport_params = hello
                    .as_ref()
                    .and_then(|h| h.extensions.iter().find(|e| e.id == EXT_QUIC_TP))
                    .and_then(|e| parse_transport_params(&e.data))
                    .unwrap_or_default();
                QuicFlow {
                    client: f.client,
                    server: f.server,
                    ts_nanos: f.ts,
                    packets: f.packets,
                    hello,
                    transport_params,
                }
            })
            .collect();
        (flows, self.skipped_versions, self.undecryptable)
    }
}

/// Склеивает CRYPTO-куски по смещениям и разбирает `ClientHello`.
fn assemble_hello(packets: &[InitialPacket], client: Endpoint, server: Endpoint, ts: u64) -> Option<ClientHelloInfo> {
    let mut chunks: BTreeMap<u64, &[u8]> = BTreeMap::new();
    for p in packets {
        for (off, data) in &p.crypto {
            chunks.entry(*off).or_insert(data.as_slice());
        }
    }
    let mut stream: Vec<u8> = Vec::new();
    for (off, data) in chunks {
        let have = stream.len() as u64;
        if off > have {
            break; // дыра: потерянный пакет
        }
        let skip = (have - off) as usize;
        if skip < data.len() {
            stream.extend_from_slice(&data[skip..]);
        }
    }
    if stream.len() < 4 || stream[0] != 0x01 {
        return None;
    }
    let len = ((stream[1] as usize) << 16) | ((stream[2] as usize) << 8) | stream[3] as usize;
    let body = stream.get(4..4 + len)?.to_vec();
    let msg = HandshakeMsg {
        msg_type: 0x01,
        body,
        record_version: 0x0303,
        record_payload_len: 4 + len,
        record_count: 1,
        ts_nanos: ts,
    };
    let mut h = parse_client_hello(&msg, client, server)?;
    h.quic = true;
    Some(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// RFC 9001 Appendix A.1: ключи Initial для DCID 0x8394c8f03e515708.
    #[test]
    fn initial_keys_match_rfc9001_appendix_a() {
        let dcid = hex("8394c8f03e515708");
        let c = initial_keys(&dcid, true);
        assert_eq!(c.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(c.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(c.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
        let s = initial_keys(&dcid, false);
        assert_eq!(s.key.to_vec(), hex("cf3a5331653c364c88f0f379b6067e37"));
        assert_eq!(s.iv.to_vec(), hex("0ac1493ca1905853b0bba03e"));
        assert_eq!(s.hp.to_vec(), hex("c206b8d9b9f0f37644430b490eeaa314"));
    }

    #[test]
    fn varints_follow_rfc9000() {
        assert_eq!(varint(&[0x25]), Some((37, 1)));
        assert_eq!(varint(&[0x7b, 0xbd]), Some((15293, 2)));
        assert_eq!(varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
        assert_eq!(varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]), Some((151_288_809_941_952_652, 8)));
        assert_eq!(varint(&[0x40]), None);
    }

    #[test]
    fn grease_parameter_ids() {
        assert!(is_grease_param(27) && is_grease_param(58) && is_grease_param(31 * 100 + 27));
        assert!(!is_grease_param(0x0f) && !is_grease_param(0x4752));
    }

    #[test]
    fn transport_params_round_trip() {
        let tp = [0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x0f, 0x00, 0x1b, 0x02, 0xaa, 0xbb];
        let p = parse_transport_params(&tp).unwrap();
        assert_eq!(p, vec![(1, vec![0x80, 0, 0x75, 0x30]), (0x0f, vec![]), (27, vec![0xaa, 0xbb])]);
        assert!(parse_transport_params(&[0x01, 0x05, 0x00]).is_none());
    }
}
