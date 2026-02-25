use tokio::net::TcpStream;

//todo split to codec that uses my frame and tls codec that remove camouflage
pub enum ConnectionState {
    New,
    Handshake,
    Tunnel(TcpStream),
    Close,
    Disconnected,
}
