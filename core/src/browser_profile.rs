//! # Пользовательские браузерные профили
//!
//! Движок строит `ClientHello` по профилю. Встроенные профили — константы в
//! коде, но любой можно заменить **JSON-файлом**: снять с реального браузера
//! (см. [`pcap`](crate::pcap), `docs/PCAP_PROFILE.md`), поправить руками или
//! написать с нуля. Формат — [`ProfileSpec`].
//!
//! ```no_run
//! use netrunner_core::browser_profile;
//!
//! // До запуска туннеля (один профиль либо массив профилей):
//! let report = browser_profile::load_file("my_chrome.json")?;
//! for w in &report.warnings { eprintln!("warning: {w}"); }
//! # Ok::<(), browser_profile::ProfileError>(())
//! ```
//!
//! Загруженные профили **заменяют** встроенный пул: каждая сессия берёт один из
//! них по хешу своего `session_id` (как и раньше — отпечаток стабилен всю
//! сессию). [`clear`] возвращает встроенный пул. Профиль проверяется при
//! загрузке: если он ломает протокол (нет x25519, TLS 1.3, `key_share`, AES-GCM
//! шифра…), загрузка отклоняется с перечнем причин, а не падает на соединении.

pub use crate::quiceng::{Hex64, PacketSpec, QuicSpec, TpKind, TpSpec};
pub use crate::tlseng::spec::{
    parse_specs, ExtId, Hex16, ProfileError, ProfileSpec, ShapeSpec, SCHEMA_VERSION,
};

/// Итог загрузки.
#[derive(Debug, Clone, Default)]
pub struct LoadReport {
    /// Имена загруженных профилей.
    pub names: Vec<String>,
    /// Предупреждения (профиль применим, но не идеален).
    pub warnings: Vec<String>,
    /// Сколько значений формы трафика загружено (клиент → сервер, обратно).
    /// `(0, 0)` — в файле нет блока `shape`, длины записей остаются синтетическими.
    pub shape_samples: (usize, usize),
    /// Сколько QUIC-профилей (блоков `quic`) загружено. 0 — UDP-нога шлёт
    /// встроенный Initial.
    pub quic_profiles: usize,
}

/// Объединяет блоки `shape` всех профилей файла.
fn merged_shape(specs: &[ProfileSpec]) -> Option<crate::nrxp::shape::ShapeLengths> {
    let (mut up, mut down) = (Vec::new(), Vec::new());
    for sh in specs.iter().filter_map(|s| s.shape.as_ref()) {
        up.extend_from_slice(&sh.up);
        down.extend_from_slice(&sh.down);
    }
    let shape = crate::nrxp::shape::ShapeLengths {
        up: crate::nrxp::shape::compress(up),
        down: crate::nrxp::shape::compress(down),
    };
    (!shape.is_empty()).then_some(shape)
}

/// Загружает профили из JSON-строки (один объект либо массив) и делает их
/// активными. При любой ошибке ничего не меняется.
pub fn load_json(json: &str) -> Result<LoadReport, ProfileError> {
    let specs = parse_specs(json)?;
    if specs.is_empty() {
        return Err(ProfileError::Invalid(vec!["the profile list is empty".into()]));
    }
    let mut report = LoadReport::default();
    let mut built = Vec::with_capacity(specs.len());
    let mut quic = Vec::new();
    for s in &specs {
        let warnings = s.validate()?;
        for w in warnings {
            report.warnings.push(format!("{}: {w}", s.name));
        }
        built.push(s.into_profile()?);
        if let Some(q) = &s.quic {
            quic.push(q.build_runtime()?);
        }
        report.names.push(s.name.clone());
    }
    report.quic_profiles = quic.len();
    let shape = merged_shape(&specs);
    report.shape_samples = shape.as_ref().map_or((0, 0), |s| (s.up.len(), s.down.len()));
    crate::tlseng::set_custom_profiles(built);
    crate::nrxp::shape::set_shape(shape);
    crate::quiceng::set_custom(quic);
    Ok(report)
}

/// Загружает **только** форму трафика (блок `shape`) из файла профилей. Для
/// процессов, которым браузерный профиль не нужен, а длины записей нужны, —
/// например узла (`netrunner-server --shape-profile`). Возвращает число значений
/// (клиент → сервер, обратно).
pub fn load_shape_json(json: &str) -> Result<(usize, usize), ProfileError> {
    let specs = parse_specs(json)?;
    for s in &specs {
        s.validate()?;
    }
    let shape = merged_shape(&specs)
        .ok_or_else(|| ProfileError::Invalid(vec!["в файле нет блока shape".into()]))?;
    let n = (shape.up.len(), shape.down.len());
    crate::nrxp::shape::set_shape(Some(shape));
    Ok(n)
}

/// То же из файла.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_shape_file(path: impl AsRef<std::path::Path>) -> Result<(usize, usize), ProfileError> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .map_err(|e| ProfileError::Io(format!("{}: {e}", path.display())))?;
    load_shape_json(&text)
}

/// Загружает профили из файла.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_file(path: impl AsRef<std::path::Path>) -> Result<LoadReport, ProfileError> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .map_err(|e| ProfileError::Io(format!("{}: {e}", path.display())))?;
    load_json(&text)
}

/// Только проверка, без активации. Возвращает предупреждения.
pub fn validate_json(json: &str) -> Result<Vec<String>, ProfileError> {
    let mut warnings = Vec::new();
    for s in parse_specs(json)? {
        for w in s.validate()? {
            warnings.push(format!("{}: {w}", s.name));
        }
    }
    Ok(warnings)
}

/// Вернуться к встроенным профилям.
pub fn clear() {
    crate::tlseng::set_custom_profiles(Vec::new());
    crate::nrxp::shape::set_shape(None);
    crate::quiceng::set_custom(Vec::new());
}

/// Сколько пользовательских профилей активно (0 — используется встроенный пул).
pub fn active_count() -> usize {
    crate::tlseng::custom_profiles().len()
}

/// Сколько QUIC-профилей активно (0 — UDP-нога шлёт встроенный Initial).
pub fn active_quic_count() -> usize {
    crate::quiceng::custom_count()
}
