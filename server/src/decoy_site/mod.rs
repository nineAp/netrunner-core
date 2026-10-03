//! Конструктор витрины узла: сборка статической страницы из именованных блоков.
//!
//! ## Роль
//!
//! Узел теперь не проксирует «не наши» соединения на чужой сайт, а обслуживает
//! **свой** — обычный SaaS-лендинг под доменом, которым узел владеет (см.
//! [`netrunner_core::decoy`]). Эта страница и есть то, чем узел является для
//! сканера, случайного браузера и активного зонда DPI. Никакой мимикрии:
//! отпечаток совпадает с настоящим сайтом, потому что это и есть настоящий сайт.
//!
//! ## Конструктор из блоков
//!
//! Страница описывается списком имён блоков ([`netrunner_core::decoy::Decoy::elements`]):
//! `["header", "hero", "pricing", "footer"]`. Каждое имя резолвится в шаблон
//! `blocks/<имя>.html` с плейсхолдерами `{{slot}}`, вкомпилированный в бинарь
//! ([`include_str!`]). [`assemble`] подставляет тексты и оборачивает результат
//! в общий каркас `shell.html`.
//!
//! Сборка выполняется **один раз при деплое** ([`assemble`] вызывается на
//! старте узла), а не на каждый запрос: динамический рендеринг на «обычном
//! лендинге» создал бы нагрузочный и временной профиль, которого у статической
//! страницы не бывает, — и это само по себе отличало бы узел от настоящего
//! сайта. Готовый HTML держится в памяти и отдаётся как есть.
//!
//! ## Что знает админка
//!
//! Каждый блок «знает, куда вставлять текст»: его слоты — это множество
//! `{{...}}` в шаблоне, которое [`block_slots`] извлекает автоматически. Админ-
//! панель строит форму по [`catalog`], не зная разметки, а [`assemble`]
//! принимает её ответы как `content`. Связь «блок → редактируемые поля»
//! выводится из самого шаблона, а не дублируется отдельной схемой, которая
//! разошлась бы с разметкой при первой же правке.

use std::collections::{BTreeSet, HashMap};

/// Общий каркас страницы. Слоты: `page_title`, `page_description`, `accent`,
/// `accent2`, `body`.
const SHELL: &str = include_str!("shell.html");

/// Один блок витрины: имя (оно же имя файла) и его HTML-шаблон.
pub struct Block {
    pub name: &'static str,
    pub template: &'static str,
}

/// Все известные блоки. Добавить блок = положить `blocks/<имя>.html` и одну
/// строку сюда; больше нигде регистрировать не нужно.
pub const BLOCKS: &[Block] = &[
    Block {
        name: "header",
        template: include_str!("blocks/header.html"),
    },
    Block {
        name: "hero",
        template: include_str!("blocks/hero.html"),
    },
    Block {
        name: "logos",
        template: include_str!("blocks/logos.html"),
    },
    Block {
        name: "features",
        template: include_str!("blocks/features.html"),
    },
    Block {
        name: "stats",
        template: include_str!("blocks/stats.html"),
    },
    Block {
        name: "pricing",
        template: include_str!("blocks/pricing.html"),
    },
    Block {
        name: "cta",
        template: include_str!("blocks/cta.html"),
    },
    Block {
        name: "footer",
        template: include_str!("blocks/footer.html"),
    },
];

/// Почему витрину не удалось собрать.
#[derive(Debug, PartialEq, Eq)]
pub enum SiteError {
    /// В `elements` указан блок, которого нет среди [`BLOCKS`].
    UnknownBlock(String),
    /// Шаблон после подстановки всё ещё содержит `{{slot}}` — админка не
    /// заполнила поле. Падаем на сборке (деплой), а не отдаём пользователю
    /// страницу с сырым `{{headline}}` посреди заголовка.
    UnfilledSlot { block: String, slot: String },
}

impl std::fmt::Display for SiteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownBlock(b) => write!(f, "неизвестный блок витрины: {b}"),
            Self::UnfilledSlot { block, slot } => {
                write!(f, "блок '{block}': не заполнен слот '{{{{{slot}}}}}'")
            }
        }
    }
}
impl std::error::Error for SiteError {}

fn find_block(name: &str) -> Option<&'static Block> {
    BLOCKS.iter().find(|b| b.name == name)
}

/// Извлекает имена слотов `{{...}}` из шаблона в порядке появления, без
/// повторов. На этом строится форма редактирования: набор полей блока — это
/// ровно его слоты, выведенные из самой разметки.
pub fn block_slots(template: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(end) = template[i + 2..].find("}}") {
                let slot = template[i + 2..i + 2 + end].trim().to_string();
                if seen.insert(slot.clone()) {
                    out.push(slot);
                }
                i += 4 + end;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Каталог блоков для админки: имя → его редактируемые слоты. Панель строит
/// форму по этому каталогу, ничего не зная о разметке.
pub fn catalog() -> Vec<(&'static str, Vec<String>)> {
    BLOCKS
        .iter()
        .map(|b| (b.name, block_slots(b.template)))
        .collect()
}

/// Подставляет `{{slot}}` из карты `values`; незаполненные слоты остаются как
/// есть (их ловит проверка в [`assemble`]).
fn fill(template: &str, values: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(end) = template[i + 2..].find("}}") {
                let slot = template[i + 2..i + 2 + end].trim();
                match values.get(slot) {
                    Some(v) => out.push_str(v),
                    None => out.push_str(&template[i..i + 4 + end]),
                }
                i += 4 + end;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Проверяет, что в собранном фрагменте не осталось `{{...}}`.
fn assert_filled(block: &str, rendered: &str) -> Result<(), SiteError> {
    if let Some(pos) = rendered.find("{{") {
        if let Some(end) = rendered[pos + 2..].find("}}") {
            return Err(SiteError::UnfilledSlot {
                block: block.to_string(),
                slot: rendered[pos + 2..pos + 2 + end].trim().to_string(),
            });
        }
    }
    Ok(())
}

/// Тексты одной страницы: `content[имя_блока][слот] = значение`, плюс
/// страничные поля (`page_title`, `accent`…).
pub struct SiteContent {
    /// Слоты каркаса: `page_title`, `page_description`, `accent`, `accent2`.
    pub page: HashMap<String, String>,
    /// Слоты по блокам.
    pub blocks: HashMap<String, HashMap<String, String>>,
}

/// Собирает итоговую страницу из блоков и текстов. Вызывается **один раз** при
/// старте узла; результат кэшируется вызывающим.
pub fn assemble(elements: &[String], content: &SiteContent) -> Result<String, SiteError> {
    let mut body = String::new();
    for name in elements {
        let block = find_block(name).ok_or_else(|| SiteError::UnknownBlock(name.clone()))?;
        let values = content.blocks.get(name.as_str());
        let empty = HashMap::new();
        let rendered = fill(block.template, values.unwrap_or(&empty));
        assert_filled(name, &rendered)?;
        body.push_str(&rendered);
        body.push('\n');
    }

    let mut page = content.page.clone();
    page.insert("body".to_string(), body);
    let full = fill(SHELL, &page);
    assert_filled("shell", &full)?;
    Ok(full)
}

pub mod preset;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_extracted_in_order_without_duplicates() {
        let slots = block_slots("<a>{{one}}</a><b>{{two}}</b><c>{{one}}</c>");
        assert_eq!(slots, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn every_shipped_block_exposes_at_least_one_slot() {
        for (name, slots) in catalog() {
            assert!(!slots.is_empty(), "блок {name} без слотов бессмысленен");
        }
    }

    #[test]
    fn unknown_block_is_an_error_not_a_silent_skip() {
        let content = SiteContent {
            page: HashMap::new(),
            blocks: HashMap::new(),
        };
        let err = assemble(&["nope".to_string()], &content).unwrap_err();
        assert_eq!(err, SiteError::UnknownBlock("nope".to_string()));
    }

    #[test]
    fn unfilled_slot_fails_the_build_rather_than_leaking_to_the_page() {
        let content = SiteContent {
            page: HashMap::new(),
            blocks: HashMap::new(),
        };
        // hero не заполнен — сборка обязана упасть, а не отдать {{headline}}.
        let err = assemble(&["hero".to_string()], &content).unwrap_err();
        assert!(matches!(err, SiteError::UnfilledSlot { .. }), "{err:?}");
    }
}
