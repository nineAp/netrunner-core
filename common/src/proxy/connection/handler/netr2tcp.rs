use crate::{
    protocol::codec::codec::Codec,
    proxy::connection::{
        buf_pair::BufPair,
        handler::{handler::ProxyHandler, utils::relay_data},
        state::ConnectionState,
    },
};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

enum NetrMessages {}

pub struct Netr2Tcp;

#[async_trait]
impl ProxyHandler for Netr2Tcp {
    //TODO MAKE ANSWER TO CONNECT
    //CLOSE CONNECT HERE IF IT IS NOT MY PROXY
    async fn do_new(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        //buffers.read_from(reader).await?;
        let codec = Codec::new();
        Ok(ConnectionState::Handshake)
    }

    //TODO MAKE HANDSHAKE WITH TARGET
    //GET TARGET FROM CUSTOM FRAME
    async fn do_handshake(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
    ) -> Result<ConnectionState, String> {
        buffers.read_from(reader).await?;

        let mut target_stream = TcpStream::connect("google.com:443")
            .await
            .map_err(|e| e.to_string())?;
        target_stream.write_buf(&mut buffers.read_buf).await;
        target_stream.read_buf(&mut buffers.write_buf).await;
        writer.write_buf(&mut buffers.write_buf);
        buffers.write_to(writer).await?;
        Ok(ConnectionState::Tunnel(target_stream))
    }

    //TODO TUNNEL TO TARGET
    async fn do_tunnel(
        &self,
        reader: &mut OwnedReadHalf,
        mut writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
        target: &mut TcpStream,
    ) -> Result<ConnectionState, String> {
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

    //CLOSE CONNECT WITH TARGET
    async fn do_close(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        Ok(ConnectionState::Disconnected)
    }
}
