pub mod dns;
pub mod ip_store;
pub mod tcp_connection;
pub mod udp_connection;

pub const CHANNEL_CAPACITY: usize = 2048 * 4;
