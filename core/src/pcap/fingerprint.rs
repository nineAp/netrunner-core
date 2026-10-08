//! Отпечатки `ClientHello`: JA3 (строка и MD5) и JA4.
//!
//! Нужны не ради самих отпечатков, а как **объективная проверка** снятого
//! профиля: JA4 не зависит ни от порядка расширений, ни от значений GREASE,
//! поэтому профиль, воссозданный нашим сборщиком `ClientHello`, обязан
//! давать тот же JA4, что и захваченный браузер.

use sha2::{Digest, Sha256};

use super::tls::{ext, is_grease, ClientHelloInfo};

/// Строка JA3: `версия,шифры,расширения,группы,форматы_точек` (без GREASE).
pub fn ja3_string(ch: &ClientHelloInfo) -> String {
    let join = |v: Vec<String>| v.join("-");
    let ciphers = join(
        ch.cipher_suites
            .iter()
            .filter(|c| !is_grease(**c))
            .map(|c| c.to_string())
            .collect(),
    );
    let exts = join(
        ch.extensions
            .iter()
            .filter(|e| !is_grease(e.id))
            .map(|e| e.id.to_string())
            .collect(),
    );
    let groups = join(
        ch.supported_groups
            .iter()
            .filter(|g| !is_grease(**g))
            .map(|g| g.to_string())
            .collect(),
    );
    let points = join(ch.ec_point_formats.iter().map(|p| p.to_string()).collect());
    format!("{},{},{},{},{}", ch.legacy_version, ciphers, exts, groups, points)
}

/// JA3 как MD5-хеш строки (hex).
pub fn ja3_hash(ch: &ClientHelloInfo) -> String {
    md5_hex(ja3_string(ch).as_bytes())
}

fn sha12(s: &str) -> String {
    let h = Sha256::digest(s.as_bytes());
    h.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// JA4 (FoxIO) для TLS поверх TCP: `t13d1516h2_<sha12 шифров>_<sha12 расширений+sigalgs>`.
pub fn ja4(ch: &ClientHelloInfo) -> String {
    // Версия: максимум из supported_versions без GREASE, иначе legacy_version.
    let version = ch
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(ch.legacy_version);
    let ver = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let sni = if ch.sni.is_some() { 'd' } else { 'i' };
    let ciphers: Vec<u16> = ch
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let exts: Vec<u16> = ch
        .extensions
        .iter()
        .map(|e| e.id)
        .filter(|e| !is_grease(*e))
        .collect();

    let alpn = match ch.alpn.first() {
        Some(p) if !p.is_empty() => alpn_pair(p.as_bytes()),
        _ => "00".to_string(),
    };

    let a = format!(
        "t{ver}{sni}{:02}{:02}{alpn}",
        ciphers.len().min(99),
        exts.len().min(99)
    );

    let mut sorted_ciphers = ciphers;
    sorted_ciphers.sort_unstable();
    let b = if sorted_ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        sha12(
            &sorted_ciphers
                .iter()
                .map(|c| format!("{c:04x}"))
                .collect::<Vec<_>>()
                .join(","),
        )
    };

    let mut sorted_exts: Vec<u16> = exts
        .into_iter()
        .filter(|e| *e != ext::SNI && *e != ext::ALPN)
        .collect();
    sorted_exts.sort_unstable();
    let mut c_in = sorted_exts
        .iter()
        .map(|e| format!("{e:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    if !ch.signature_algorithms.is_empty() {
        c_in.push('_');
        c_in.push_str(
            &ch.signature_algorithms
                .iter()
                .map(|s| format!("{s:04x}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    let c = if sorted_exts.is_empty() && ch.signature_algorithms.is_empty() {
        "000000000000".to_string()
    } else {
        sha12(&c_in)
    };
    format!("{a}_{b}_{c}")
}

/// Первый и последний символ первого ALPN-значения (для не-ASCII-буквенно-цифровых
/// — первый и последний hex-символ его шестнадцатеричной записи).
fn alpn_pair(p: &[u8]) -> String {
    let (f, l) = (p[0], p[p.len() - 1]);
    if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
        format!("{}{}", f as char, l as char)
    } else {
        let hex: String = p.iter().map(|b| format!("{b:02x}")).collect();
        let hb = hex.as_bytes();
        format!("{}{}", hb[0] as char, hb[hb.len() - 1] as char)
    }
}

// ───────────────────────────────── MD5 ──────────────────────────────────────
// JA3 определён через MD5; отдельную зависимость ради ~50 строк не тащим.

pub fn md5_hex(data: &[u8]) -> String {
    md5(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32)
        .collect();
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);

    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let m: Vec<u32> = chunk
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f2 = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_known_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        // граница блока: 55/56/64 байта
        assert_eq!(md5_hex(&[b'a'; 56]), "3b0c8ac703f828b04c6c197006d17218");
        assert_eq!(md5_hex(&[b'a'; 64]), "014842d480b571495a4a0363793f7367");
    }

    #[test]
    fn alpn_pairs() {
        assert_eq!(alpn_pair(b"h2"), "h2");
        assert_eq!(alpn_pair(b"http/1.1"), "h1");
        assert_eq!(alpn_pair(&[0xab, 0xcd]), "ad");
    }
}
