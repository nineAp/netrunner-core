use bytes::{Buf, Bytes, BytesMut};

use crate::{
    protocol::{
        interceptors::error_interceptor::{ErrorAction, ErrorType, InterceptorError},
        parser::parser::FrameParser,
    },
    tlseng::extension::{Extension, ExtensionStack},
};

impl FrameParser for ExtensionStack {
    type Error = InterceptorError;

    fn can_parse(bytes: &BytesMut) -> bool {
        // Минимальное расширение: тип(2) + длина(2) = 4 байта
        bytes.len() >= 4
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        let mut extensions = Vec::new();

        while bytes.remaining() >= 4 {
            let etype = bytes.get_u16();
            let elen = bytes.get_u16() as usize;

            if bytes.remaining() < elen {
                // Если данных меньше, чем обещала длина расширения — это ошибка протокола
                return Err(InterceptorError::new(
                    ErrorType::Tls("Invalid extension payload"),
                    ErrorAction::Drop,
                    Bytes::new(),
                ));
            }

            let data = bytes.split_to(elen).freeze();
            extensions.push(Extension::new(etype, data));
        }
        Ok(Some(Self { extensions }))
    }
}

impl ExtensionStack {
    /// Возвращает данные расширения по его типу
    pub fn find_by_type(&self, etype: u16) -> Option<Bytes> {
        self.extensions
            .iter()
            .find(|e| e.etype == etype)
            .map(|e| e.data.clone()) // Клонирование Bytes дешево (increment refcount)
    }

    /// Проверяет наличие расширения
    pub fn has_extension(&self, etype: u16) -> bool {
        self.extensions.iter().any(|e| e.etype == etype)
    }
}
