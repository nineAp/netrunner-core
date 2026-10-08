//! Декодирование кадра: канальный уровень → IPv4/IPv6 → TCP/UDP.
//!
//! Нужно ровно столько, чтобы достать полезную нагрузку транспорта и признаки
//! потока; фрагментированный IP (кроме первого фрагмента) и экзотика
//! канального уровня молча пропускаются.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// TCP-сегмент.
#[derive(Debug, Clone, Copy)]
pub struct TcpSegment<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// UDP-датаграмма.
#[derive(Debug, Clone, Copy)]
pub struct UdpDatagram<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub enum Transport<'a> {
    Tcp(TcpSegment<'a>),
    Udp(UdpDatagram<'a>),
}

// LINKTYPE_* (https://www.tcpdump.org/linktypes.html)
const LT_NULL: u32 = 0;
const LT_ETHERNET: u32 = 1;
const LT_RAW: u32 = 101;
const LT_LOOP: u32 = 108;
const LT_LINUX_SLL: u32 = 113;
const LT_IPV4: u32 = 228;
const LT_IPV6: u32 = 229;
const LT_LINUX_SLL2: u32 = 276;
const LT_RAW_OPENBSD: u32 = 12;

const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86dd;
const ETH_VLAN: u16 = 0x8100;
const ETH_QINQ: u16 = 0x88a8;

/// Декодирует кадр. `None` — не TCP/UDP поверх IP либо кадр непригоден
/// (фрагмент, обрезан, неизвестный канальный уровень).
pub fn decode(link_type: u32, data: &[u8]) -> Option<Transport<'_>> {
    let ip = strip_link(link_type, data)?;
    decode_ip(ip)
}

fn strip_link(link_type: u32, data: &[u8]) -> Option<&[u8]> {
    match link_type {
        LT_ETHERNET => {
            if data.len() < 14 {
                return None;
            }
            let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
            let mut off = 14usize;
            // Теги VLAN (в том числе вложенные 802.1ad).
            while ethertype == ETH_VLAN || ethertype == ETH_QINQ {
                if data.len() < off + 4 {
                    return None;
                }
                ethertype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
                off += 4;
            }
            match ethertype {
                ETH_IPV4 | ETH_IPV6 => data.get(off..),
                _ => None,
            }
        }
        LT_LINUX_SLL => {
            if data.len() < 16 {
                return None;
            }
            match u16::from_be_bytes([data[14], data[15]]) {
                ETH_IPV4 | ETH_IPV6 => data.get(16..),
                _ => None,
            }
        }
        LT_LINUX_SLL2 => {
            if data.len() < 20 {
                return None;
            }
            match u16::from_be_bytes([data[0], data[1]]) {
                ETH_IPV4 | ETH_IPV6 => data.get(20..),
                _ => None,
            }
        }
        LT_NULL | LT_LOOP => data.get(4..),
        LT_RAW | LT_IPV4 | LT_IPV6 | LT_RAW_OPENBSD => Some(data),
        _ => None,
    }
}

fn decode_ip(ip: &[u8]) -> Option<Transport<'_>> {
    match ip.first()? >> 4 {
        4 => decode_ipv4(ip),
        6 => decode_ipv6(ip),
        _ => None,
    }
}

fn decode_ipv4(ip: &[u8]) -> Option<Transport<'_>> {
    if ip.len() < 20 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    // Не первый фрагмент: транспортного заголовка в нём нет.
    if frag & 0x1fff != 0 {
        return None;
    }
    let proto = ip[9];
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    // Отрезаем канальный паддинг (Ethernet добивает короткие кадры до 60 Б).
    let end = if total >= ihl && total <= ip.len() {
        total
    } else {
        ip.len()
    };
    decode_l4(proto, src, dst, &ip[ihl..end])
}

fn decode_ipv6(ip: &[u8]) -> Option<Transport<'_>> {
    if ip.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    let mut next = ip[6];
    let mut a = [0u8; 16];
    a.copy_from_slice(&ip[8..24]);
    let src = IpAddr::V6(Ipv6Addr::from(a));
    a.copy_from_slice(&ip[24..40]);
    let dst = IpAddr::V6(Ipv6Addr::from(a));
    let end = if payload_len != 0 && 40 + payload_len <= ip.len() {
        40 + payload_len
    } else {
        ip.len()
    };
    let mut off = 40usize;
    // Цепочка расширенных заголовков.
    loop {
        match next {
            0 | 43 | 60 => {
                // hop-by-hop / routing / destination options: len в 8-байтных единицах (+1)
                if off + 2 > end {
                    return None;
                }
                let n = ip[off];
                let len = (ip[off + 1] as usize + 1) * 8;
                next = n;
                off += len;
            }
            44 => {
                // fragment header
                if off + 8 > end {
                    return None;
                }
                let frag = u16::from_be_bytes([ip[off + 2], ip[off + 3]]);
                if frag & 0xfff8 != 0 {
                    return None;
                }
                next = ip[off];
                off += 8;
            }
            51 => {
                // AH: len в 4-байтных единицах (+2)
                if off + 2 > end {
                    return None;
                }
                let n = ip[off];
                let len = (ip[off + 1] as usize + 2) * 4;
                next = n;
                off += len;
            }
            _ => break,
        }
        if off > end {
            return None;
        }
    }
    decode_l4(next, src, dst, ip.get(off..end)?)
}

fn decode_l4(proto: u8, src: IpAddr, dst: IpAddr, l4: &[u8]) -> Option<Transport<'_>> {
    match proto {
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let doff = ((l4[12] >> 4) as usize) * 4;
            if doff < 20 || l4.len() < doff {
                return None;
            }
            Some(Transport::Tcp(TcpSegment {
                src,
                dst,
                sport: u16::from_be_bytes([l4[0], l4[1]]),
                dport: u16::from_be_bytes([l4[2], l4[3]]),
                seq: u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]),
                flags: l4[13],
                payload: &l4[doff..],
            }))
        }
        17 => {
            if l4.len() < 8 {
                return None;
            }
            let len = u16::from_be_bytes([l4[4], l4[5]]) as usize;
            let end = if len >= 8 && len <= l4.len() {
                len
            } else {
                l4.len()
            };
            Some(Transport::Udp(UdpDatagram {
                src,
                dst,
                sport: u16::from_be_bytes([l4[0], l4[1]]),
                dport: u16::from_be_bytes([l4[2], l4[3]]),
                payload: &l4[8..end],
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod build {
    //! Сборка кадров для тестов (Ethernet/IPv4/TCP и т. п.).

    pub fn tcp_v4(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(flags);
        tcp.extend_from_slice(&65535u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(payload);
        ipv4(src, dst, 6, &tcp)
    }

    pub fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(l4);
        ip
    }

    pub fn ethernet(ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(ip);
        // Ethernet обязан быть не короче 60 байт: паддинг не должен попасть в payload.
        while f.len() < 60 {
            f.push(0);
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    #[test]
    fn ethernet_ipv4_tcp_strips_padding() {
        let ip = tcp_v4([10, 0, 0, 1], [10, 0, 0, 2], 1234, 443, 77, TCP_SYN | TCP_ACK, b"hi");
        let f = ethernet(&ip);
        let Some(Transport::Tcp(s)) = decode(LT_ETHERNET, &f) else {
            panic!("expected tcp")
        };
        assert_eq!((s.sport, s.dport, s.seq), (1234, 443, 77));
        assert_eq!(s.payload, b"hi");
        assert_eq!(s.flags, TCP_SYN | TCP_ACK);
    }

    #[test]
    fn vlan_sll_and_raw_variants() {
        let ip = tcp_v4([1, 1, 1, 1], [2, 2, 2, 2], 5, 6, 1, 0, b"x");
        // VLAN
        let mut v = vec![0u8; 12];
        v.extend_from_slice(&ETH_VLAN.to_be_bytes());
        v.extend_from_slice(&[0, 5]);
        v.extend_from_slice(&0x0800u16.to_be_bytes());
        v.extend_from_slice(&ip);
        assert!(matches!(decode(LT_ETHERNET, &v), Some(Transport::Tcp(_))));
        // SLL
        let mut s = vec![0u8; 14];
        s.extend_from_slice(&0x0800u16.to_be_bytes());
        s.extend_from_slice(&ip);
        assert!(matches!(decode(LT_LINUX_SLL, &s), Some(Transport::Tcp(_))));
        // SLL2
        let mut s2 = vec![0x08, 0x00];
        s2.extend_from_slice(&[0u8; 18]);
        s2.extend_from_slice(&ip);
        assert!(matches!(decode(LT_LINUX_SLL2, &s2), Some(Transport::Tcp(_))));
        // RAW и NULL
        assert!(matches!(decode(LT_RAW, &ip), Some(Transport::Tcp(_))));
        let mut n = vec![2, 0, 0, 0];
        n.extend_from_slice(&ip);
        assert!(matches!(decode(LT_NULL, &n), Some(Transport::Tcp(_))));
    }

    #[test]
    fn garbage_and_fragments_do_not_panic() {
        for len in 0..64 {
            let data = vec![0x45u8; len];
            let _ = decode(LT_RAW, &data);
            let _ = decode(LT_ETHERNET, &data);
        }
        let mut ip = ipv4([1, 1, 1, 1], [2, 2, 2, 2], 6, &[0u8; 30]);
        ip[6] = 0x00;
        ip[7] = 0x10; // fragment offset != 0
        assert!(decode(LT_RAW, &ip).is_none());
        assert!(decode(9999, &ip).is_none());
    }

    #[test]
    fn ipv6_udp_with_extension_header() {
        let mut udp = Vec::new();
        udp.extend_from_slice(&1000u16.to_be_bytes());
        udp.extend_from_slice(&443u16.to_be_bytes());
        udp.extend_from_slice(&11u16.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(b"abc");
        let mut ip = vec![0x60, 0, 0, 0];
        let hbh = [17u8, 0, 1, 4, 0, 0, 0, 0]; // hop-by-hop → UDP
        ip.extend_from_slice(&((hbh.len() + udp.len()) as u16).to_be_bytes());
        ip.push(0); // next = hop-by-hop
        ip.push(64);
        ip.extend_from_slice(&[0u8; 32]);
        ip.extend_from_slice(&hbh);
        ip.extend_from_slice(&udp);
        let Some(Transport::Udp(u)) = decode(LT_RAW, &ip) else {
            panic!("expected udp")
        };
        assert_eq!((u.sport, u.dport, u.payload), (1000, 443, &b"abc"[..]));
    }
}
