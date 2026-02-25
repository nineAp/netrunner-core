use std::{net::SocketAddr, sync::Arc};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};

use crate::{
    protocol::codec::codec::Codec,
    proxy::connection::{
        buf_pair::BufPair, handler::handler::ProxyHandler, state::ConnectionState,
    },
};

pub struct Connection {
    pub addr: SocketAddr,
    inbound: OwnedReadHalf,
    outbound: OwnedWriteHalf,
    state: ConnectionState,
    buffers: BufPair,
    codec: Codec,
}

impl Connection {
    pub fn new(stream: TcpStream, addr: SocketAddr, init: bool) -> Self {
        let (inbound, outbound) = stream.into_split();
        Self {
            addr,
            inbound,
            outbound,
            state: ConnectionState::New,
            buffers: BufPair::new(),
            codec: Codec::new(init),
        }
    }
    pub async fn handle(
        &mut self,
        handler: Arc<dyn ProxyHandler + Send + Sync>,
    ) -> Result<ConnectionState, String> {
        loop {
            match &mut self.state {
                ConnectionState::New => {
                    self.state = handler
                        .init_session(&mut self.inbound, &mut self.outbound, &mut self.buffers)
                        .await?
                }
                ConnectionState::Handshake => {
                    self.state = handler
                        .authorize_request(
                            &mut self.inbound,
                            &mut self.outbound,
                            &mut self.buffers,
                            &mut self.codec,
                        )
                        .await?;
                }
                ConnectionState::Tunnel(ref mut stream) => {
                    self.state = handler
                        .exchange_data(
                            &mut self.inbound,
                            &mut self.outbound,
                            &mut self.buffers,
                            &mut self.codec,
                            stream,
                        )
                        .await?;
                }

                ConnectionState::Close => {
                    self.state = handler
                        .finalize_session(&mut self.inbound, &mut self.outbound, &mut self.buffers)
                        .await?;
                }
                ConnectionState::Disconnected => {
                    println!("Disconnected");
                    return Ok(ConnectionState::Disconnected);
                }
            }
        }
    }
}
