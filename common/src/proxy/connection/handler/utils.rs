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
    let n = res.map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(true);
    }

    println!(">>> Client sent {} bytes", n);

    writer.write_all(&buffer).await.map_err(|e| e.to_string())?;
    Ok(false)
}
