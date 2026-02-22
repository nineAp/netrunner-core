use async_trait::async_trait;
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};

use crate::{
    protocol::codec::codec::Codec,
    proxy::connection::{buf_pair::BufPair, state::ConnectionState},
};
#[async_trait]
pub trait ProxyHandler {
    async fn do_new(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String>;
    async fn do_handshake(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
    ) -> Result<ConnectionState, String>;
    async fn do_tunnel(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
        target: &mut TcpStream,
    ) -> Result<ConnectionState, String>;
    async fn do_close(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String>;
}
