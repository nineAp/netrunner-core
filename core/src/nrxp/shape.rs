//! Форма трафика: распределение длин TLS-записей, снятое с настоящего браузера.
//!
//! Длина TLS-записи едет в открытом виде, и по ней строится
//! website-fingerprinting. [`PadShaper`](super::codec) выравнивает длины по
//! границам квантования, свои у каждого соединения. Раньше границы брались из
//! чисто синтетического распределения; теперь, если в профиле есть блок
//! `shape`, **точки границ выбираются из наблюдавшихся у браузера длин** — то
//! есть набор длин на проводе состоит из значений, которые браузер действительно
//! отправляет.
//!
//! ## Чего это не делает (честно)
//!
//! * Это не воспроизведение временно́й картины и не имитация конкретного сайта:
//!   учитываются только длины записей, по направлениям.
//! * Эффективность канала не страдает: между соседними границами по-прежнему
//!   не больше `GAP_CAP`, наблюдаемые длины лишь определяют, *где* стоят границы.
//! * Данные снимаются с реального сёрфинга: чем больше сайтов, тем лучше.
//!
//! Направление: клиент отправляет `up`, узел — `down`
//! ([`set_server_role`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

/// Меньше этого образцов — распределение слишком грубое, форма не применяется.
pub const MIN_SAMPLES: usize = 8;
/// Больше образцов в профиле не хранится (квантили).
pub const MAX_SAMPLES: usize = 256;
/// Наименьшая длина записи, которую мы вообще можем отправить: заголовок
/// кадра (25) + AEAD-тег (16).
pub const MIN_RECORD: u16 = 41;
/// Наибольшая длина записи (16384 + 16 + 1).
pub const MAX_RECORD: u16 = 16401;

/// Наблюдавшиеся длины записей `ApplicationData` после рукопожатия.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShapeLengths {
    /// Клиент → сервер.
    pub up: Vec<u16>,
    /// Сервер → клиент.
    pub down: Vec<u16>,
}

impl ShapeLengths {
    pub fn is_empty(&self) -> bool {
        self.up.is_empty() && self.down.is_empty()
    }
}

static SHAPE: RwLock<Option<Arc<ShapeLengths>>> = RwLock::new(None);
static SERVER_ROLE: AtomicBool = AtomicBool::new(false);

/// Устанавливает (или снимает, `None`) форму трафика. Процесс узла
/// дополнительно вызывает [`set_server_role`].
pub fn set_shape(shape: Option<ShapeLengths>) {
    if let Ok(mut g) = SHAPE.write() {
        *g = shape.filter(|s| !s.is_empty()).map(Arc::new);
    }
}

/// Текущая форма трафика.
pub fn shape() -> Option<Arc<ShapeLengths>> {
    SHAPE.read().ok().and_then(|g| g.clone())
}

/// Отметить, что этот процесс — узел: его исходящее направление — `down`.
pub fn set_server_role(is_server: bool) {
    SERVER_ROLE.store(is_server, Ordering::Relaxed);
}

/// Образцы исходящего направления текущего процесса, если их достаточно.
pub(crate) fn outbound_samples() -> Option<Vec<u16>> {
    let s = shape()?;
    let v = if SERVER_ROLE.load(Ordering::Relaxed) { &s.down } else { &s.up };
    (v.len() >= MIN_SAMPLES).then(|| v.clone())
}

/// Приводит наблюдения к хранимому виду: обрезает по допустимым длинам и сжимает
/// до `MAX_SAMPLES` квантилей (распределение сохраняется).
pub fn compress(mut lens: Vec<u16>) -> Vec<u16> {
    lens.retain(|l| *l >= 17);
    for l in &mut lens {
        *l = (*l).clamp(MIN_RECORD, MAX_RECORD);
    }
    lens.sort_unstable();
    if lens.len() <= MAX_SAMPLES {
        return lens;
    }
    let n = lens.len();
    (0..MAX_SAMPLES).map(|i| lens[i * (n - 1) / (MAX_SAMPLES - 1)]).collect()
}

/// Проверка блока `shape` из профиля. Возвращает предупреждения.
pub fn validate(s: &ShapeLengths) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    for (name, v) in [("up", &s.up), ("down", &s.down)] {
        if v.len() > MAX_SAMPLES {
            return Err(format!("shape.{name}: {} значений, не больше {MAX_SAMPLES}", v.len()));
        }
        if let Some(bad) = v.iter().find(|l| **l > MAX_RECORD) {
            return Err(format!("shape.{name}: длина {bad} больше предела TLS-записи ({MAX_RECORD})"));
        }
        if !v.is_empty() && v.len() < MIN_SAMPLES {
            warnings.push(format!(
                "shape.{name}: {} значений меньше {MIN_SAMPLES} — для этого направления форма не применяется",
                v.len()
            ));
        }
        if v.iter().any(|l| *l < MIN_RECORD) {
            warnings.push(format!(
                "shape.{name}: есть длины короче {MIN_RECORD} Б (минимальная запись туннеля) — они поднимутся до минимума"
            ));
        }
    }
    Ok(warnings)
}

/// Тесты, меняющие глобальную форму трафика, берут этот замок: иначе параллельные
/// тесты видят чужие `set_shape`/`clear`.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
