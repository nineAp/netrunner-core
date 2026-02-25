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
    async fn init_session(
        &self,
        client_reader: &mut OwnedReadHalf,
        client_writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String>;
    async fn authorize_request(
        &self,
        client_reader: &mut OwnedReadHalf,
        client_writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
    ) -> Result<ConnectionState, String>;
    async fn exchange_data(
        &self,
        client_reader: &mut OwnedReadHalf,
        client_writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
        target: &mut TcpStream,
    ) -> Result<ConnectionState, String>;
    async fn finalize_session(
        &self,
        client_reader: &mut OwnedReadHalf,
        client_writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String>;
}
