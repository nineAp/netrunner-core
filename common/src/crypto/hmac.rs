use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn generate_auth_tag(secret: &[u8]) -> [u8; 16] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let minute_step = (now / 60).to_be_bytes();

    // Создаем HMAC-Sha256 с твоим секретным ключом
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");

    // Подмешиваем туда текущую минуту
    mac.update(&minute_step);

    let result = mac.finalize().into_bytes();

    // Берем первые 16 байт от 32-байтного хеша SHA256
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&result[..16]);
    tag
}
