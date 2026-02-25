use crate::{
    protocol::codec::codec::Codec,
    proxy::connection::{
        buf_pair::BufPair,
        handler::{handler::ProxyHandler, utils::relay_data},
        state::ConnectionState,
    },
};
use async_trait::async_trait;
use bytes::{BufMut, Bytes};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

use bytes::BytesMut;

enum SocksMsg {
    Hello,           // Hello (0x05, 0x00)
    AuthFailed,      // Error (0x05, 0xFF)
    ConnectOk,       // Connection is OK
    Custom(Vec<u8>), // If needed raw bytes
}

impl SocksMsg {
    pub fn write_to(self, buf: &mut BytesMut) {
        buf.clear(); // Чистим перед записью ВСЕГДА
        match self {
            SocksMsg::Hello => {
                buf.put_slice(&[0x05, 0x00]);
            }
            SocksMsg::AuthFailed => {
                buf.put_slice(&[0x05, 0xFF]);
            }
            SocksMsg::ConnectOk => {
                // SOCKS5 требует 10 байт в ответ на CONNECT:
                // VER, REP(0), RSV, ATYP(1), ADDR(0,0,0,0), PORT(0,0)
                buf.put_slice(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            }
            SocksMsg::Custom(data) => {
                buf.put_slice(&data);
            }
        }
    }
}

pub struct Tcp2Netr {
    socks5: bool,
    proxy_address: String,
}

impl Tcp2Netr {
    pub fn new(socks5: bool, address: String) -> Self {
        Self {
            socks5,
            proxy_address: address,
        }
    }

    fn get_addr_raw(data: &mut BytesMut) -> Result<Bytes, String> {
        if data.len() < 4 {
            return Err("Too short".into());
        }

        let atyp = data[3];
        let total_len = match atyp {
            0x01 => 10, // 4 (header) + 4 (ip) + 2 (port)
            0x03 => {
                let domain_len = data[4] as usize;
                4 + 1 + domain_len + 2 // 4 (header) + 1 (len) + N (domain) + 2 (port)
            }
            _ => return Err("Unsupported address type".to_string()),
        };

        if data.len() < total_len {
            return Err("Incomplete SOCKS packet".into());
        }

        // ВАЖНО: split_to удаляет эти байты из data и возвращает их нам
        // Теперь в data останется только TLS ClientHello!
        let socks_packet = data.split_to(total_len);

        // Формируем твой кастомный адрес (длина + данные + порт)
        let mut result = BytesMut::new();
        if atyp == 0x01 {
            result.put_u8(4);
            result.put_slice(&socks_packet[4..10]);
        } else {
            let len = socks_packet[4];
            result.put_u8(len);
            result.put_slice(&socks_packet[5..total_len]);
        }

        Ok(result.freeze())
    }
}

#[async_trait]
impl ProxyHandler for Tcp2Netr {
    // 1. Инициализация: отвечаем SOCKS5 Hello (0x05, 0x00)
    async fn init_session(
        &self,
        client_reader: &mut OwnedReadHalf,
        client_writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        buffers.read_from(client_reader).await?;

        SocksMsg::Hello.write_to(&mut buffers.write_buf);
        buffers.write_to(client_writer).await?;

        Ok(ConnectionState::Handshake)
    }

    // 2. Авторизация/Парсинг: достаем адрес из SOCKS5 Connect и подключаемся к Netr
    async fn authorize_request(
        &self,
        client_reader: &mut OwnedReadHalf,
        client_writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        _codec: &mut Codec,
    ) -> Result<ConnectionState, String> {
        buffers.read_from(client_reader).await?;

        // Извлекаем адрес и удаляем SOCKS-заголовок из буфера
        let address_to_connect = Tcp2Netr::get_addr_raw(&mut buffers.read_buf)?;

        // Коннектимся к твоему Netr серверу (proxy_address)
        let mut target_stream = TcpStream::connect(&self.proxy_address)
            .await
            .map_err(|e| e.to_string())?;

        // Шлем кастомный заголовок адреса в сторону Netr
        target_stream
            .write_all(&address_to_connect)
            .await
            .map_err(|e| e.to_string())?;

        // Если в буфере остался TLS ClientHello (после split_to в get_addr_raw),
        // проталкиваем его немедленно, чтобы сервер не ждал
        if !buffers.read_buf.is_empty() {
            target_stream
                .write_all(&buffers.read_buf)
                .await
                .map_err(|e| e.to_string())?;
            buffers.read_buf.clear();
        }

        // Отвечаем клиенту (браузеру), что SOCKS-соединение установлено
        SocksMsg::ConnectOk.write_to(&mut buffers.write_buf);
        buffers.write_to(client_writer).await?;

        // Переходим в режим туннеля, передавая сокет до Netr-сервера
        Ok(ConnectionState::Tunnel(target_stream))
    }

    // 3. Обмен данными: гоняем байты между клиентом и Netr-сервером
    async fn exchange_data(
        &self,
        client_reader: &mut OwnedReadHalf,
        client_writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        _codec: &mut Codec,
        target: &mut TcpStream,
    ) -> Result<ConnectionState, String> {
        buffers.reset();
        let (mut target_reader, mut target_writer) = target.split();

        println!("Socks2Netr Стартанул в тонель");

        loop {
            tokio::select! {
                // Из браузера -> в сторону Netr
                res = client_reader.read_buf(&mut buffers.read_buf) => {
                    let should_break =
                    relay_data(res, &mut target_writer, &mut buffers.read_buf).await?;
                    if should_break { break;}
                }

                // Из Netr -> обратно в браузер
                res = target_reader.read_buf(&mut buffers.write_buf) => {
                    let should_break =
                    relay_data(res, client_writer, &mut buffers.write_buf).await?;
                    if should_break { break;}
                }
            }
        }

        client_writer.shutdown().await.map_err(|e| e.to_string())?;
        target_writer.shutdown().await.map_err(|e| e.to_string())?;

        Ok(ConnectionState::Close)
    }

    // 4. Финализация: логируем закрытие
    async fn finalize_session(
        &self,
        _client_reader: &mut OwnedReadHalf,
        _client_writer: &mut OwnedWriteHalf,
        _buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        println!("SOCKS5 CONNECTION CLOSED");
        Ok(ConnectionState::Disconnected)
    }
}
