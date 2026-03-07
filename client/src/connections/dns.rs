use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record};

use crate::connections::ip_store::FakeIpStore;

pub fn handle_dns_query(data: &[u8], store: &mut FakeIpStore) -> Option<Vec<u8>> {
    // 1. Парсим входящий запрос
    let request = Message::from_vec(data).ok()?;

    // 2. Берем первый вопрос (обычно запрос только один)
    let query = request.queries().first()?;
    let name = query.name().to_string().trim_end_matches('.').to_string();

    // 3. Получаем Fake IP
    let fake_ip = store.get_or_assign(&name);

    // 4. Формируем ответ
    let mut response = Message::new();
    response
        .set_recursion_available(true)
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_response_code(ResponseCode::NoError)
        .add_query(query.clone());

    // Создаем запись A (IPv4)
    let record = Record::from_rdata(
        query.name().clone(),
        1, // TTL = 1 сек
        RData::A(fake_ip.into()),
    );
    response.add_answer(record);

    // 5. Сериализуем обратно в байты
    response.to_vec().ok()
}
