pub mod bridge;
pub mod connection;
pub mod engine;
pub mod handler;
pub mod muxer;

pub const TCP_BUF_SIZE: usize = 1024 * 512;
pub const UDP_BUF_SIZE: usize = 1024 * 64;
pub const MESSAGE_CHANNEL_SIZE: usize = 1024 * 16;
