use crate::{
    protocol::codec::codec::Codec,
    proxy::connection::{
        buf_pair::BufPair,
        handler::{handler::ProxyHandler, utils::relay_data},
        state::ConnectionState,
    },
};
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

pub struct Netr2Tcp;

impl Netr2Tcp {
    pub fn raw_addr_to_string(raw: &mut BytesMut) -> Result<String, String> {
        println!("len is {:?}", raw.len());
        if raw.is_empty() {
            return Err("Buffer is empty".into());
        }

        let len = raw[0] as usize;

        if raw.len() < 1 + len + 2 {
            return Err(format!(
                "Buffer too short: expected {}, got {}",
                1 + len + 2,
                raw.len()
            )
            .into());
        }

        let address = String::from_utf8_lossy(&raw[1..1 + len]);
        let port_start = 1 + len;
        let port = u16::from_be_bytes([raw[port_start], raw[port_start + 1]]);

        Ok(format!("{}:{}", address, port))
    }
}

#[async_trait]
impl ProxyHandler for Netr2Tcp {
    async fn init_session(
        &self,
        _client_reader: &mut OwnedReadHalf,
        _client_writer: &mut OwnedWriteHalf,
        _buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        Ok(ConnectionState::Handshake)
    }

    async fn authorize_request(
        &self,
        client_reader: &mut OwnedReadHalf,
        _client_writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        _codec: &mut Codec,
    ) -> Result<ConnectionState, String> {
        buffers.read_from(client_reader).await?;

        let header_len = if !buffers.read_buf.is_empty() {
            1 + (buffers.read_buf[0] as usize) + 2
        } else {
            return Err("Buffer is empty".into());
        };

        let address_to_connect = Netr2Tcp::raw_addr_to_string(&mut buffers.read_buf)?;
        println!("Address is: {:?}", address_to_connect);

        // Отрезаем заголовок, оставляя только данные приложения (TLS и т.д.)
        let _header = buffers.read_buf.split_to(header_len);

        let target_stream = TcpStream::connect(address_to_connect)
            .await
            .map_err(|e| e.to_string())?;

        Ok(ConnectionState::Tunnel(target_stream))
    }

    async fn exchange_data(
        &self,
        client_reader: &mut OwnedReadHalf,
        client_writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        _codec: &mut Codec,
        target: &mut TcpStream,
    ) -> Result<ConnectionState, String> {
        let (mut target_reader, mut target_writer) = target.split();
        println!("Netr2Tcp Стартанул в тонель");

        loop {
            tokio::select! {
                // 1. От клиента к целевому серверу
                res = client_reader.read_buf(&mut buffers.read_buf) => {
                    let should_break =
                    relay_data(res, &mut target_writer, &mut buffers.read_buf).await?;
                    if should_break { break; }
                }

                // 2. От целевого сервера к клиенту
                res = target_reader.read_buf(&mut buffers.write_buf) => {
                    let should_break =
                    relay_data(res, client_writer, &mut buffers.write_buf).await?;
                    if should_break { break;}
                }
            }
        }

        println!("Cycles breaked");
        client_writer.shutdown().await.map_err(|e| e.to_string())?;
        target_writer.shutdown().await.map_err(|e| e.to_string())?;

        Ok(ConnectionState::Close)
    }

    async fn finalize_session(
        &self,
        _client_reader: &mut OwnedReadHalf,
        _client_writer: &mut OwnedWriteHalf,
        _buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        Ok(ConnectionState::Disconnected)
    }
}
