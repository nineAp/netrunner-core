use std::{net::SocketAddr, sync::Arc, vec};
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
    pub fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        let (inbound, outbound) = stream.into_split();
        Self {
            addr,
            inbound,
            outbound,
            state: ConnectionState::New,
            buffers: BufPair::new(),
            codec: Codec::new(),
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
                        .do_new(&mut self.inbound, &mut self.outbound, &mut self.buffers)
                        .await?
                }
                ConnectionState::Handshake => {
                    self.state = handler
                        .do_handshake(
                            &mut self.inbound,
                            &mut self.outbound,
                            &mut self.buffers,
                            &mut self.codec,
                        )
                        .await?;
                }
                ConnectionState::Tunnel(ref mut stream) => {
                    self.state = handler
                        .do_tunnel(
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
                        .do_close(&mut self.inbound, &mut self.outbound, &mut self.buffers)
                        .await?;
                }
                ConnectionState::Disconnected => {
                    println!("Disconnected");
                    return Ok(ConnectionState::Disconnected);
                }
                _ => return Err("Invalid transition".to_string()),
            }
        }
    }
}
