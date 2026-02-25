use crate::{tlseng::types::HelloType, utils::u24::U24};

pub struct HelloHeader {
    pub header_type: HelloType,
    pub len: U24,
}
