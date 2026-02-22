use std::io::Error;

use crate::{
    protocol::codec::codec::Codec,
    proxy::connection::{
        buf_pair::BufPair,
        handler::{handler::ProxyHandler, utils::relay_data},
        state::ConnectionState,
    },
};
use async_trait::async_trait;
use bytes::BufMut;
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

pub struct Socks2Netr;

impl Socks2Netr {
    fn get_addr(data: &BytesMut) -> Result<String, String> {
        let target_addr = match data[3] {
            0x01 => {
                // IPv4 (4 байта IP + 2 байта порт)
                let ip = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
                let port = u16::from_be_bytes([data[8], data[9]]);
                format!("{}:{}", ip, port)
            }
            0x03 => {
                // Domain Name
                let len = data[4] as usize;
                let domain = String::from_utf8_lossy(&data[5..5 + len]);
                let port = u16::from_be_bytes([data[5 + len], data[5 + len + 1]]);
                format!("{}:{}", domain, port)
            }
            _ => return Err("Unsupported address type".to_string()),
        };
        Ok(target_addr)
    }
}

#[async_trait]
impl ProxyHandler for Socks2Netr {
    //get tcp from socks connection. give answer to it
    async fn do_new(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        buffers.read_from(reader).await?;
        SocksMsg::Hello.write_to(&mut buffers.write_buf);
        buffers.write_to(writer).await?;

        let codec = Codec::new();

        Ok(ConnectionState::Handshake)
    }

    async fn do_handshake(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
    ) -> Result<ConnectionState, String> {
        buffers.read_from(reader).await?;
        let data = &buffers.read_buf;

        if data.len() < 7 {
            return Err("SOCKS5 request too short".to_string());
        }

        //CODEC HERE SHOULD CREATE CUSTOM FRAME
        //AND MAKE MOCK TLS HANDSHAKE WITH MY SERVER
        //AFTER THIS SEND THE REAL HANDSHAKE BUT IN APPLICATION DATA

        let target_addr = Socks2Netr::get_addr(data)?;
        println!("Connecting to target: {}", target_addr);
        //todo dynamic address of proxy server
        let endpoint_stream = TcpStream::connect("127.0.0.1:4443")
            .await
            .map_err(|e| format!("Could not connect to {}: {}", target_addr, e))?;

        SocksMsg::ConnectOk.write_to(&mut buffers.write_buf);
        buffers.write_to(writer).await?;
        Ok(ConnectionState::Tunnel(endpoint_stream))
    }

    //their tunnel. there is encrypt tcp to netr
    async fn do_tunnel(
        &self,
        reader: &mut OwnedReadHalf,
        mut writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
        target: &mut TcpStream,
    ) -> Result<ConnectionState, String> {
        buffers.reset();
        let (mut target_reader, mut target_writer) = target.split();

        loop {
            tokio::select! {
                // 1. from client to target
                res = reader.read_buf(&mut buffers.read_buf) => {
                    let should_break =
                    relay_data(res, &mut target_writer, &mut buffers.read_buf).await?;
                    if should_break { break;}
                }

                // 2. From target to client
                res = target_reader.read_buf(&mut buffers.write_buf) => {
                    let should_break =
                    relay_data(res, &mut writer, &mut buffers.write_buf).await?;
                    if should_break { break;}
                }

            }
        }
        writer.shutdown().await.map_err(|e| e.to_string())?;
        target_writer.shutdown().await.map_err(|e| e.to_string())?;

        Ok(ConnectionState::Close)
    }

    //close tunnel between mobile (tun2socks) and server
    async fn do_close(
        &self,
        _reader: &mut OwnedReadHalf,
        _writer: &mut OwnedWriteHalf,
        _buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        println!("SOCKS5 CONNECTUON CLOSED");
        Ok(ConnectionState::Disconnected)
    }
}
