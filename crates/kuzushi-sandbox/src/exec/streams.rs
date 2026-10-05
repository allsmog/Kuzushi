use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::ChildStdin;

use super::MAX_OUTPUT_BYTES;

/// Keep at most the limit plus one overflow sentinel, including before EOF.
pub(super) async fn read_bounded(
    mut stream: impl AsyncRead + Unpin,
    retained: &mut Vec<u8>,
) -> io::Result<()> {
    let mut chunk = [0_u8; 8192];
    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Ok(());
        }
        let remaining = (MAX_OUTPUT_BYTES + 1).saturating_sub(retained.len());
        retained.extend_from_slice(&chunk[..count.min(remaining)]);
        if retained.len() > MAX_OUTPUT_BYTES {
            return Err(io::Error::other("sandbox output budget exceeded"));
        }
    }
}

pub(super) async fn deliver_stdin(
    input: Option<&str>,
    stream: Option<ChildStdin>,
) -> io::Result<()> {
    let Some(mut stream) = stream else {
        return Ok(());
    };
    if let Some(input) = input {
        stream.write_all(input.as_bytes()).await.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("sandbox stdin delivery failed: {error}"),
            )
        })?;
    }
    stream.shutdown().await
}
