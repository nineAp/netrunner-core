use std::io::Error;

use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

pub async fn relay_data<W>(
    res: Result<usize, Error>,
    writer: &mut W,
    buffer: &mut BytesMut,
) -> Result<bool, String>
where
    W: AsyncWriteExt + Unpin,
{
    match res {
        Ok(0) => {
            println!("Read 0 bytes - closing half of connection");
            return Ok(true); // Это закроет туннель
        }
        Ok(n) => println!("Relayed {} bytes", n),
        Err(e) => println!("Relay error: {}", e),
    }

    println!("What is here {:?}", &buffer);
    writer.write_buf(buffer).await.map_err(|e| e.to_string())?;
    Ok(false)
}
