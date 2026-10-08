//! Чтение контейнеров захвата: классический `pcap` и `pcapng`.
//!
//! Разбирается из байтового среза целиком (захваты для снятия профиля невелики),
//! без аллокаций на пакет: [`Packet::data`] ссылается прямо в исходный буфер.
//! Любое повреждение — [`PcapError`], паники исключены: все смещения
//! проверяются по границам.

use super::PcapError;

/// Один захваченный кадр канального уровня.
#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    /// Метка времени, наносекунды от эпохи (0, если в контейнере её нет).
    pub ts_nanos: u64,
    /// Тип канального уровня (`LINKTYPE_*`).
    pub link_type: u32,
    /// Длина кадра на проводе (может быть больше `data.len()` при `snaplen`).
    pub orig_len: u32,
    /// Захваченные байты.
    pub data: &'a [u8],
}

/// Верхняя граница размера одного кадра: защита от мусорных заголовков.
const MAX_FRAME: usize = 1 << 24;

/// Определяет формат по магическому числу и возвращает все пакеты.
pub fn read_packets(bytes: &[u8]) -> Result<Vec<Packet<'_>>, PcapError> {
    if bytes.len() < 4 {
        return Err(PcapError::Truncated("file shorter than a magic number"));
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Err(PcapError::Unsupported(
            "gzip-compressed capture: decompress it first (gunzip)".into(),
        ));
    }
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match magic {
        [0x0a, 0x0d, 0x0d, 0x0a] => read_pcapng(bytes),
        [0xa1, 0xb2, 0xc3, 0xd4]
        | [0xd4, 0xc3, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0x3c, 0x4d]
        | [0x4d, 0x3c, 0xb2, 0xa1] => read_classic(bytes),
        _ => Err(PcapError::BadMagic(magic)),
    }
}

#[derive(Clone, Copy)]
struct Endian {
    big: bool,
}

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.big {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    }

    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.big {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }
}

// ─────────────────────────────── classic pcap ───────────────────────────────

fn read_classic(bytes: &[u8]) -> Result<Vec<Packet<'_>>, PcapError> {
    if bytes.len() < 24 {
        return Err(PcapError::Truncated("pcap global header"));
    }
    let (big, nanos) = match [bytes[0], bytes[1], bytes[2], bytes[3]] {
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        _ => (false, true),
    };
    let e = Endian { big };
    let link_type = e.u32(&bytes[20..24]) & 0x0fff_ffff;

    let mut out = Vec::new();
    let mut p = 24usize;
    while p + 16 <= bytes.len() {
        let ts_sec = e.u32(&bytes[p..p + 4]) as u64;
        let ts_frac = e.u32(&bytes[p + 4..p + 8]) as u64;
        let incl = e.u32(&bytes[p + 8..p + 12]) as usize;
        let orig = e.u32(&bytes[p + 12..p + 16]);
        p += 16;
        if incl > MAX_FRAME || p + incl > bytes.len() {
            // Обрезанный хвост (захват прервали) — отдаём то, что успели прочитать.
            break;
        }
        let frac_nanos = if nanos { ts_frac } else { ts_frac * 1_000 };
        out.push(Packet {
            ts_nanos: ts_sec * 1_000_000_000 + frac_nanos,
            link_type,
            orig_len: orig,
            data: &bytes[p..p + incl],
        });
        p += incl;
    }
    Ok(out)
}

// ──────────────────────────────── pcapng ────────────────────────────────────

#[derive(Clone, Copy)]
struct Interface {
    link_type: u32,
    /// Единица времени в наносекундах (для степени 10) либо None при степени 2.
    nanos_per_tick: f64,
}

fn tsresol_to_nanos(v: u8) -> f64 {
    if v & 0x80 == 0 {
        // 10^-v секунды
        1e9 / 10f64.powi(v as i32)
    } else {
        // 2^-(v & 0x7f) секунды
        1e9 / 2f64.powi((v & 0x7f) as i32)
    }
}

fn read_pcapng(bytes: &[u8]) -> Result<Vec<Packet<'_>>, PcapError> {
    let mut out = Vec::new();
    let mut e = Endian { big: false };
    let mut ifaces: Vec<Interface> = Vec::new();
    let mut p = 0usize;

    while p + 12 <= bytes.len() {
        // Тип блока SHB симметричен (0a0d0d0a), порядок байт определяется внутри.
        let is_shb = bytes[p..p + 4] == [0x0a, 0x0d, 0x0d, 0x0a];
        if is_shb {
            if p + 12 > bytes.len() {
                break;
            }
            let bom = &bytes[p + 8..p + 12];
            e = if bom == [0x1a, 0x2b, 0x3c, 0x4d] {
                Endian { big: true }
            } else if bom == [0x4d, 0x3c, 0x2b, 0x1a] {
                Endian { big: false }
            } else {
                return Err(PcapError::Malformed("pcapng: bad byte-order magic"));
            };
            ifaces.clear();
        }
        let btype = e.u32(&bytes[p..p + 4]);
        let total = e.u32(&bytes[p + 4..p + 8]) as usize;
        if total < 12 || !total.is_multiple_of(4) || p + total > bytes.len() {
            // Обрезанный/повреждённый хвост.
            break;
        }
        let body = &bytes[p + 8..p + total - 4];
        match btype {
            // Interface Description Block
            1 => {
                if body.len() >= 8 {
                    let link_type = e.u16(&body[0..2]) as u32;
                    let mut nanos_per_tick = 1_000.0; // по умолчанию микросекунды
                    let mut o = 8usize;
                    while o + 4 <= body.len() {
                        let code = e.u16(&body[o..o + 2]);
                        let len = e.u16(&body[o + 2..o + 4]) as usize;
                        o += 4;
                        if code == 0 {
                            break;
                        }
                        if o + len > body.len() {
                            break;
                        }
                        if code == 9 && len >= 1 {
                            nanos_per_tick = tsresol_to_nanos(body[o]);
                        }
                        o += (len + 3) & !3;
                    }
                    ifaces.push(Interface {
                        link_type,
                        nanos_per_tick,
                    });
                }
            }
            // Enhanced Packet Block
            6 => {
                if body.len() >= 20 {
                    let id = e.u32(&body[0..4]) as usize;
                    let hi = e.u32(&body[4..8]) as u64;
                    let lo = e.u32(&body[8..12]) as u64;
                    let cap = e.u32(&body[12..16]) as usize;
                    let orig = e.u32(&body[16..20]);
                    if cap <= MAX_FRAME && 20 + cap <= body.len() {
                        if let Some(ifc) = ifaces.get(id) {
                            let ticks = (hi << 32) | lo;
                            out.push(Packet {
                                ts_nanos: (ticks as f64 * ifc.nanos_per_tick) as u64,
                                link_type: ifc.link_type,
                                orig_len: orig,
                                data: &body[20..20 + cap],
                            });
                        }
                    }
                }
            }
            // Simple Packet Block (интерфейс 0, без метки времени)
            3 => {
                if body.len() >= 4 {
                    if let Some(ifc) = ifaces.first() {
                        let orig = e.u32(&body[0..4]);
                        let cap = (orig as usize).min(body.len() - 4);
                        out.push(Packet {
                            ts_nanos: 0,
                            link_type: ifc.link_type,
                            orig_len: orig,
                            data: &body[4..4 + cap],
                        });
                    }
                }
            }
            _ => {}
        }
        p += total;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classic(link: u32, big: bool, nanos: bool, frames: &[(&[u8], u32, u32)]) -> Vec<u8> {
        let w32 = |v: u32| if big { v.to_be_bytes() } else { v.to_le_bytes() };
        let w16 = |v: u16| if big { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut f = Vec::new();
        let magic: u32 = if nanos { 0xa1b23c4d } else { 0xa1b2c3d4 };
        f.extend_from_slice(&w32(magic));
        f.extend_from_slice(&w16(2));
        f.extend_from_slice(&w16(4));
        f.extend_from_slice(&w32(0));
        f.extend_from_slice(&w32(0));
        f.extend_from_slice(&w32(65535));
        f.extend_from_slice(&w32(link));
        for (d, s, frac) in frames {
            f.extend_from_slice(&w32(*s));
            f.extend_from_slice(&w32(*frac));
            f.extend_from_slice(&w32(d.len() as u32));
            f.extend_from_slice(&w32(d.len() as u32));
            f.extend_from_slice(d);
        }
        f
    }

    #[test]
    fn classic_both_endiannesses_and_resolutions() {
        for big in [false, true] {
            for nanos in [false, true] {
                let f = classic(1, big, nanos, &[(b"abc", 5, 7), (b"defg", 6, 0)]);
                // Магическое число пишется в порядке записи: little-endian файл
                // начинается с d4c3b2a1 — оба случая должны читаться.
                let pk = read_packets(&f).unwrap();
                assert_eq!(pk.len(), 2);
                assert_eq!(pk[0].data, b"abc");
                assert_eq!(pk[0].link_type, 1);
                let frac = if nanos { 7 } else { 7_000 };
                assert_eq!(pk[0].ts_nanos, 5_000_000_000 + frac);
                assert_eq!(pk[1].data, b"defg");
            }
        }
    }

    #[test]
    fn truncated_tail_is_tolerated() {
        let mut f = classic(1, false, false, &[(b"abcdef", 1, 0)]);
        f.truncate(f.len() - 2);
        assert!(read_packets(&f).unwrap().is_empty());
    }

    #[test]
    fn rejects_garbage_and_gzip() {
        assert!(matches!(
            read_packets(b"\x00\x01\x02\x03rest"),
            Err(PcapError::BadMagic(_))
        ));
        assert!(matches!(
            read_packets(&[0x1f, 0x8b, 8, 0, 0]),
            Err(PcapError::Unsupported(_))
        ));
        assert!(read_packets(&[1, 2]).is_err());
    }

    fn block(btype: u32, body: &[u8]) -> Vec<u8> {
        let pad = (4 - body.len() % 4) % 4;
        let total = (12 + body.len() + pad) as u32;
        let mut b = Vec::new();
        b.extend_from_slice(&btype.to_le_bytes());
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(body);
        b.extend(std::iter::repeat(0).take(pad));
        b.extend_from_slice(&total.to_le_bytes());
        b
    }

    #[test]
    fn pcapng_enhanced_packets_with_tsresol() {
        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        let mut idb = Vec::new();
        idb.extend_from_slice(&1u16.to_le_bytes()); // ethernet
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&65535u32.to_le_bytes());
        // if_tsresol = 9 (наносекунды)
        idb.extend_from_slice(&9u16.to_le_bytes());
        idb.extend_from_slice(&1u16.to_le_bytes());
        idb.extend_from_slice(&[9, 0, 0, 0]);
        idb.extend_from_slice(&[0, 0, 0, 0]);
        let mut epb = Vec::new();
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&1500u32.to_le_bytes());
        epb.extend_from_slice(&5u32.to_le_bytes());
        epb.extend_from_slice(&5u32.to_le_bytes());
        epb.extend_from_slice(b"hello");

        let mut f = block(0x0a0d0d0a, &shb);
        f.extend(block(1, &idb));
        f.extend(block(6, &epb));
        let pk = read_packets(&f).unwrap();
        assert_eq!(pk.len(), 1);
        assert_eq!(pk[0].data, b"hello");
        assert_eq!(pk[0].ts_nanos, 1500);
        assert_eq!(pk[0].link_type, 1);
    }
}
