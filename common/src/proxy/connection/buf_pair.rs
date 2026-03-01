use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf}; // <--- ОБЯЗАТЕЛЬНО ТУТ

pub struct BufPair {
    pub write_buf: BytesMut,
    pub read_buf: BytesMut,
}
const BUF_SIZE: usize = 4096;

impl BufPair {
    pub fn new() -> Self {
        let write_buf = BytesMut::with_capacity(BUF_SIZE);
        let read_buf = BytesMut::with_capacity(BUF_SIZE);
        Self {
            write_buf,
            read_buf,
        }
    }
    pub async fn read_from(&mut self, reader: &mut OwnedReadHalf) -> Result<usize, String> {
        let n = reader
            .read_buf(&mut self.read_buf)
            .await
            .map_err(|e| e.to_string())?;

        if n == 0 {
            return Err("Connection closed by peer".to_string());
        }
        Ok(n)
    }

    pub async fn write_from(&mut self, writer: &mut OwnedWriteHalf) -> Result<(), String> {
        writer
            .write_all_buf(&mut self.write_buf)
            .await
            .map_err(|e| e.to_string())
    }

    pub fn reset(&mut self) {
        self.read_buf.clear();
        self.write_buf.clear();
    }
}
