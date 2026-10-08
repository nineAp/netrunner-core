//! Сборка TCP-потоков из пакетов.
//!
//! Задача узкая: получить для каждого соединения два потока байт (клиент →
//! сервер и сервер → клиент) с метками времени, чтобы выше читать TLS-записи.
//! Поддерживается переупорядочивание и ретрансмиты (перекрытия обрезаются);
//! на первой дыре сборка направления останавливается — дальше данные
//! недостоверны. Объём ограничен: интересует рукопожатие, а не весь поток.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use super::net::{Transport, TCP_ACK, TCP_SYN};
use super::reader::Packet;

/// Сколько байт каждого направления собирать (хватает на рукопожатие с запасом).
pub const MAX_STREAM_BYTES: usize = 256 * 1024;
/// Предел числа одновременно отслеживаемых соединений.
const MAX_FLOWS: usize = 100_000;

/// Конечная точка соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

/// Собранное направление соединения.
#[derive(Debug, Clone, Default)]
pub struct Stream {
    /// Непрерывный префикс потока.
    pub bytes: Vec<u8>,
    /// Метки времени: `(смещение в bytes, ts_nanos)` для начала каждого сегмента.
    pub marks: Vec<(usize, u64)>,
    /// Сборка оборвалась на дыре (потерян сегмент).
    pub gap: bool,
    /// Видели SYN этого направления.
    pub syn: bool,
}

impl Stream {
    /// Метка времени сегмента, в котором лежит байт `offset`.
    pub fn ts_at(&self, offset: usize) -> u64 {
        match self.marks.binary_search_by(|(o, _)| o.cmp(&offset)) {
            Ok(i) => self.marks[i].1,
            Err(0) => self.marks.first().map_or(0, |m| m.1),
            Err(i) => self.marks[i - 1].1,
        }
    }
}

/// TCP-соединение.
#[derive(Debug, Clone)]
pub struct Flow {
    /// Инициатор соединения (отправитель SYN либо отправитель ClientHello).
    pub client: Endpoint,
    pub server: Endpoint,
    pub c2s: Stream,
    pub s2c: Stream,
    /// Метка времени первого пакета соединения.
    pub first_ts: u64,
    /// Порядковый номер появления (стабильная сортировка).
    pub index: usize,
}

struct RawSeg {
    seq: u32,
    ts: u64,
    flags: u8,
    data: Vec<u8>,
}

#[derive(Default)]
struct RawDir {
    segs: Vec<RawSeg>,
    collected: usize,
}

struct RawFlow {
    a: Endpoint,
    b: Endpoint,
    /// Направление a → b и b → a.
    ab: RawDir,
    ba: RawDir,
    first_ts: u64,
    index: usize,
}

/// Собирает соединения из пакетов (только TCP; остальное игнорируется).
pub fn assemble_flows(packets: &[Packet<'_>]) -> Vec<Flow> {
    let mut map: HashMap<(Endpoint, Endpoint), usize> = HashMap::new();
    let mut raws: Vec<RawFlow> = Vec::new();

    for pk in packets {
        let Some(Transport::Tcp(seg)) = super::net::decode(pk.link_type, pk.data) else {
            continue;
        };
        let src = Endpoint {
            ip: seg.src,
            port: seg.sport,
        };
        let dst = Endpoint {
            ip: seg.dst,
            port: seg.dport,
        };
        if seg.payload.is_empty() && seg.flags & TCP_SYN == 0 {
            continue;
        }
        let key = if src <= dst { (src, dst) } else { (dst, src) };
        let idx = match map.get(&key) {
            Some(i) => *i,
            None => {
                if raws.len() >= MAX_FLOWS {
                    continue;
                }
                let i = raws.len();
                raws.push(RawFlow {
                    a: key.0,
                    b: key.1,
                    ab: RawDir::default(),
                    ba: RawDir::default(),
                    first_ts: pk.ts_nanos,
                    index: i,
                });
                map.insert(key, i);
                i
            }
        };
        let rf = &mut raws[idx];
        let dir = if src == rf.a { &mut rf.ab } else { &mut rf.ba };
        if dir.collected >= MAX_STREAM_BYTES * 2 && seg.flags & TCP_SYN == 0 {
            continue;
        }
        dir.collected += seg.payload.len();
        dir.segs.push(RawSeg {
            seq: seg.seq,
            ts: pk.ts_nanos,
            flags: seg.flags,
            data: seg.payload.to_vec(),
        });
    }

    raws.into_iter().filter_map(finish_flow).collect()
}

fn finish_flow(rf: RawFlow) -> Option<Flow> {
    let ab = build_stream(&rf.ab);
    let ba = build_stream(&rf.ba);
    if ab.bytes.is_empty() && ba.bytes.is_empty() {
        return None;
    }
    // Клиент: тот, кто прислал «чистый» SYN (без ACK); иначе — кто первым
    // прислал запись рукопожатия TLS ClientHello; иначе a.
    let ab_syn = rf.ab.segs.iter().any(|s| s.flags & TCP_SYN != 0 && s.flags & TCP_ACK == 0);
    let ba_syn = rf.ba.segs.iter().any(|s| s.flags & TCP_SYN != 0 && s.flags & TCP_ACK == 0);
    let a_is_client = if ab_syn != ba_syn {
        ab_syn
    } else if looks_like_client_hello(&ab.bytes) != looks_like_client_hello(&ba.bytes) {
        looks_like_client_hello(&ab.bytes)
    } else {
        true
    };
    let (client, server, c2s, s2c) = if a_is_client {
        (rf.a, rf.b, ab, ba)
    } else {
        (rf.b, rf.a, ba, ab)
    };
    Some(Flow {
        client,
        server,
        c2s,
        s2c,
        first_ts: rf.first_ts,
        index: rf.index,
    })
}

fn looks_like_client_hello(b: &[u8]) -> bool {
    b.len() >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

/// Собирает непрерывный префикс направления.
fn build_stream(dir: &RawDir) -> Stream {
    let mut st = Stream::default();
    if dir.segs.is_empty() {
        return st;
    }
    st.syn = dir.segs.iter().any(|s| s.flags & TCP_SYN != 0);

    // Базовый номер: ISN+1, если видели SYN; иначе первый по времени сегмент
    // с данными (относительные смещения считаем знаковой разностью — это
    // переживает перенос через 2^32).
    let reference = dir
        .segs
        .iter()
        .find(|s| s.flags & TCP_SYN != 0)
        .map(|s| s.seq.wrapping_add(1))
        .or_else(|| dir.segs.iter().find(|s| !s.data.is_empty()).map(|s| s.seq))
        .unwrap_or(0);

    // Смещение относительно reference; для данных до reference (ретрансмит
    // раньше первого виденного) сдвигаем базу на минимум.
    let mut by_off: BTreeMap<i64, (&RawSeg, usize)> = BTreeMap::new();
    for s in dir.segs.iter().filter(|s| !s.data.is_empty()) {
        let off = s.seq.wrapping_sub(reference) as i32 as i64;
        // При равных смещениях оставляем более длинный сегмент.
        match by_off.get(&off) {
            Some((prev, _)) if prev.data.len() >= s.data.len() => {}
            _ => {
                by_off.insert(off, (s, s.data.len()));
            }
        }
    }
    let Some((&first_off, _)) = by_off.iter().next() else {
        return st;
    };
    let base = if st.syn { 0.min(first_off) } else { first_off };
    let mut next = base;

    for (off, (seg, _)) in by_off {
        if st.bytes.len() >= MAX_STREAM_BYTES {
            break;
        }
        let end = off + seg.data.len() as i64;
        if end <= next {
            continue; // полностью дубликат
        }
        if off > next {
            st.gap = true; // дыра — дальше данные недостоверны
            break;
        }
        let skip = (next - off) as usize;
        let chunk = &seg.data[skip..];
        st.marks.push((st.bytes.len(), seg.ts));
        st.bytes.extend_from_slice(chunk);
        next = end;
    }
    st.bytes.truncate(MAX_STREAM_BYTES);
    st
}

#[cfg(test)]
mod tests {
    use super::super::net::build::*;
    use super::super::net::{TCP_ACK, TCP_SYN};
    use super::*;

    fn pk(data: &[u8], ts: u64) -> Packet<'_> {
        Packet {
            ts_nanos: ts,
            link_type: 1,
            orig_len: data.len() as u32,
            data,
        }
    }

    const C: [u8; 4] = [10, 0, 0, 1];
    const S: [u8; 4] = [10, 0, 0, 2];

    #[test]
    fn reorders_dedups_and_picks_client_by_syn() {
        let syn = ethernet(&tcp_v4(C, S, 40000, 443, 99, TCP_SYN, b""));
        let synack = ethernet(&tcp_v4(S, C, 443, 40000, 500, TCP_SYN | TCP_ACK, b""));
        // 3 сегмента клиента: порядок 2,1,3 + дубликат первого
        let p1 = ethernet(&tcp_v4(C, S, 40000, 443, 100, TCP_ACK, b"AAAA"));
        let p2 = ethernet(&tcp_v4(C, S, 40000, 443, 104, TCP_ACK, b"BBBB"));
        let p3 = ethernet(&tcp_v4(C, S, 40000, 443, 108, TCP_ACK, b"CC"));
        let r1 = ethernet(&tcp_v4(S, C, 443, 40000, 501, TCP_ACK, b"zz"));
        let packets = [
            pk(&syn, 1),
            pk(&synack, 2),
            pk(&p2, 4),
            pk(&p1, 3),
            pk(&p1, 5),
            pk(&p3, 6),
            pk(&r1, 7),
        ];
        let flows = assemble_flows(&packets);
        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!(f.client.port, 40000);
        assert_eq!(f.c2s.bytes, b"AAAABBBBCC");
        assert_eq!(f.s2c.bytes, b"zz");
        assert!(!f.c2s.gap);
        assert_eq!(f.c2s.ts_at(0), 3);
        assert_eq!(f.c2s.ts_at(5), 4);
    }

    #[test]
    fn gap_stops_assembly_and_overlap_is_trimmed() {
        let p1 = ethernet(&tcp_v4(C, S, 1, 2, 1000, TCP_ACK, b"1234"));
        let p2 = ethernet(&tcp_v4(C, S, 1, 2, 1002, TCP_ACK, b"34567")); // перекрытие
        let p4 = ethernet(&tcp_v4(C, S, 1, 2, 1020, TCP_ACK, b"zzz")); // дыра
        let packets = [pk(&p1, 1), pk(&p2, 2), pk(&p4, 3)];
        let flows = assemble_flows(&packets);
        assert_eq!(flows[0].c2s.bytes, b"1234567");
        assert!(flows[0].c2s.gap);
    }

    #[test]
    fn client_detected_by_client_hello_without_syn() {
        let ch = [0x16, 3, 1, 0, 4, 1, 0, 0, 0];
        let a = ethernet(&tcp_v4(S, C, 443, 5000, 1, TCP_ACK, b"srv"));
        let b = ethernet(&tcp_v4(C, S, 5000, 443, 1, TCP_ACK, &ch));
        let flows = assemble_flows(&[pk(&a, 1), pk(&b, 2)]);
        assert_eq!(flows[0].client.port, 5000);
    }

    #[test]
    fn sequence_number_wraparound() {
        let p1 = ethernet(&tcp_v4(C, S, 1, 2, u32::MAX - 1, TCP_ACK, b"abcd"));
        let p2 = ethernet(&tcp_v4(C, S, 1, 2, 2, TCP_ACK, b"efg"));
        let flows = assemble_flows(&[pk(&p1, 1), pk(&p2, 2)]);
        assert_eq!(flows[0].c2s.bytes, b"abcdefg");
    }
}
