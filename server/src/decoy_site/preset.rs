//! Готовые витрины: JSON-пресеты «вайбкод-SaaS», вкомпилированные в бинарь.
//!
//! Каждый пресет — обычный SaaS-лендинг сервиса, через который **оправданно
//! ходит много трафика**: запись и хостинг видео, передача больших файлов,
//! приём логов и метрик. Это и есть смысл выбора: узел с большим egress должен
//! выглядеть как сервис, у которого большой egress нормален. Лендинг мебельного
//! магазина такой трафик не объясняет — а хостинг видео объясняет.
//!
//! Пресеты намеренно выглядят как наспех собранный «вайбкод»-продукт (щедрые
//! градиенты, эмодзи, бодрая маркетинговая копирайтерская вода) — таких сайтов
//! в интернете тысячи, и ещё один не привлекает внимания. Это витрина по
//! умолчанию; дальше её текст правится через админку (см. [`super::catalog`]),
//! не трогая код.
//!
//! Разбор идёт через [`serde_json::Value`], без `derive`-структур: пресет —
//! это данные для наполнения формы, а не типизированный конфиг, и лишняя схема
//! только рассинхронизировалась бы с блоками.

use std::collections::HashMap;

use netrunner_core::decoy::{Decoy, DecoyCatalog, DecoyError};
use serde_json::Value;

use super::{assemble, SiteContent, SiteError};

/// Пресеты, вкомпилированные в бинарь.
pub const PRESETS: &[(&str, &str)] = &[
    ("clipforge", include_str!("presets/clipforge.json")),
    ("hauler", include_str!("presets/hauler.json")),
    ("logdrain", include_str!("presets/logdrain.json")),
];

/// Разобранный пресет: конфиг витрины плюс её тексты.
pub struct Preset {
    pub sni: String,
    pub elements: Vec<String>,
    pub content: SiteContent,
}

/// Ошибки загрузки пресета.
#[derive(Debug)]
pub enum PresetError {
    NotFound(String),
    Json(String),
    Shape(&'static str),
    Site(SiteError),
    /// SNI пресета не входит в каталог доменов узла: витрину собрать можно, но
    /// поднимать узел под доменом, которым он не владеет, нельзя — под него не
    /// выпустить сертификат. Ровно та проверка, что закрывает «любой SNI».
    SniNotOwned(DecoyError),
}

impl std::fmt::Display for PresetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(n) => write!(f, "пресет '{n}' не найден"),
            Self::Json(e) => write!(f, "пресет: битый JSON: {e}"),
            Self::Shape(e) => write!(f, "пресет: неверная структура: {e}"),
            Self::Site(e) => write!(f, "пресет: {e}"),
            Self::SniNotOwned(e) => write!(f, "пресет: {e}"),
        }
    }
}
impl std::error::Error for PresetError {}

fn obj_to_map(v: &Value) -> HashMap<String, String> {
    v.as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

impl Preset {
    /// Разбирает пресет из строки JSON.
    pub fn parse(raw: &str) -> Result<Self, PresetError> {
        let v: Value = serde_json::from_str(raw).map_err(|e| PresetError::Json(e.to_string()))?;

        let sni = v
            .get("sni")
            .and_then(Value::as_str)
            .ok_or(PresetError::Shape("нет поля sni"))?
            .to_string();

        let elements = v
            .get("elements")
            .and_then(Value::as_array)
            .ok_or(PresetError::Shape("нет массива elements"))?
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect();

        let theme = v.get("theme").cloned().unwrap_or(Value::Null);
        let mut page = HashMap::new();
        for (key, slot) in [
            ("page_title", "page_title"),
            ("page_description", "page_description"),
        ] {
            if let Some(s) = v.get(key).and_then(Value::as_str) {
                page.insert(slot.to_string(), s.to_string());
            }
        }
        for slot in ["accent", "accent2"] {
            if let Some(s) = theme.get(slot).and_then(Value::as_str) {
                page.insert(slot.to_string(), s.to_string());
            }
        }

        let blocks = v
            .get("content")
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .map(|(name, block_val)| (name.clone(), obj_to_map(block_val)))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            sni,
            elements,
            content: SiteContent { page, blocks },
        })
    }

    /// Находит пресет по имени среди вкомпилированных.
    pub fn load(name: &str) -> Result<Self, PresetError> {
        let (_, raw) = PRESETS
            .iter()
            .find(|(n, _)| *n == name)
            .ok_or_else(|| PresetError::NotFound(name.to_string()))?;
        Self::parse(raw)
    }

    /// Собирает готовую HTML-страницу.
    pub fn render(&self) -> Result<String, PresetError> {
        assemble(&self.elements, &self.content).map_err(PresetError::Site)
    }

    /// Превращает пресет в проверенный [`Decoy`], сверив его SNI с каталогом
    /// доменов узла. Единственный путь получить `Decoy` из пресета — тем самым
    /// «любой SNI в пресете» отсекается ровно так же, как «любой SNI в админке».
    pub fn into_decoy(&self, catalog: &DecoyCatalog) -> Result<Decoy, PresetError> {
        let sni = catalog
            .validate(&self.sni)
            .map_err(PresetError::SniNotOwned)?;
        Ok(Decoy {
            sni,
            elements: self.elements.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shipped_preset_parses_and_renders_to_complete_html() {
        for (name, _) in PRESETS {
            let p = Preset::load(name).expect(name);
            let html = p.render().unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(html.starts_with("<!doctype html>"), "{name}: не HTML");
            assert!(
                !html.contains("{{"),
                "{name}: в собранной странице остался незаполненный слот"
            );
            assert!(html.contains("</html>"), "{name}: страница оборвана");
        }
    }

    #[test]
    fn preset_sni_must_be_in_the_node_domain_catalog() {
        let p = Preset::load("clipforge").unwrap();

        // Каталог без нашего домена — пресет собрать можно, а поднять нельзя.
        let foreign = DecoyCatalog::from_list("someone-else.com");
        assert!(matches!(
            p.into_decoy(&foreign),
            Err(PresetError::SniNotOwned(_))
        ));

        // Каталог с нашим доменом — Decoy выпускается.
        let owned = DecoyCatalog::from_list("clipforge.app");
        let decoy = p.into_decoy(&owned).unwrap();
        assert_eq!(decoy.sni.as_str(), "clipforge.app");
        assert!(decoy.elements.iter().any(|e| e == "hero"));
    }

    #[test]
    fn presets_cover_only_high_egress_services() {
        // Санити-проверка замысла: дефолтные витрины — сервисы, оправдывающие
        // большой трафик. Если кто-то добавит «магазин диванов», пусть тест
        // хотя бы заставит задуматься (домены заведомо не про товары).
        let snis: Vec<_> = PRESETS
            .iter()
            .map(|(n, _)| Preset::load(n).unwrap().sni)
            .collect();
        assert!(snis.iter().any(|s| s.contains("clip"))); // видео
        assert!(snis.iter().any(|s| s.contains("haul"))); // файлы
        assert!(snis.iter().any(|s| s.contains("log"))); // телеметрия
    }
}

#[cfg(test)]
mod page_size {
    use super::*;
    /// Собранная витрина должна быть похожа на настоящий SaaS-лендинг по
    /// размеру: не заглушка в пару строк и не гигабайт. Заодно — что все блоки
    /// пресета реально попали в страницу.
    #[test]
    fn assembled_pages_are_realistic_landing_sized() {
        for (name, _) in PRESETS {
            let p = Preset::load(name).unwrap();
            let html = p.render().unwrap();
            assert!(
                (3_000..=64_000).contains(&html.len()),
                "{name}: страница {} B — не похоже на лендинг",
                html.len()
            );
        }
    }
}
