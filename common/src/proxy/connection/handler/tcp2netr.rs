use crate::{
    protocol::codec::codec::Codec,
    proxy::connection::{
        buf_pair::BufPair, handler::handler::ProxyHandler, state::ConnectionState,
    },
};
use async_trait::async_trait;
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};

pub struct Tcp2Netr;

#[async_trait]
impl ProxyHandler for Tcp2Netr {
    //for new tunnel between site.ru and proxy
    async fn do_new(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        todo!()
        //Ok(ConnectionState::Handshake)
    }

    //their handshake. need to encrypt this in netr protocol
    async fn do_handshake(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
    ) -> Result<ConnectionState, String> {
        Ok(ConnectionState::Close)
    }

    //data flow like application data in netr protocol
    async fn do_tunnel(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
        codec: &mut Codec,
        target: &mut TcpStream,
    ) -> Result<ConnectionState, String> {
        Ok(ConnectionState::Close)
    }

    //close of connection
    async fn do_close(
        &self,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        buffers: &mut BufPair,
    ) -> Result<ConnectionState, String> {
        Ok(ConnectionState::Close)
    }
}
