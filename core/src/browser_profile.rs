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

pub use crate::tlseng::spec::{parse_specs, ExtId, Hex16, ProfileError, ProfileSpec, SCHEMA_VERSION};

/// Итог загрузки.
#[derive(Debug, Clone, Default)]
pub struct LoadReport {
    /// Имена загруженных профилей.
    pub names: Vec<String>,
    /// Предупреждения (профиль применим, но не идеален).
    pub warnings: Vec<String>,
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
    for s in &specs {
        let warnings = s.validate()?;
        for w in warnings {
            report.warnings.push(format!("{}: {w}", s.name));
        }
        built.push(s.into_profile()?);
        report.names.push(s.name.clone());
    }
    crate::tlseng::set_custom_profiles(built);
    Ok(report)
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
}

/// Сколько пользовательских профилей активно (0 — используется встроенный пул).
pub fn active_count() -> usize {
    crate::tlseng::custom_profiles().len()
}
