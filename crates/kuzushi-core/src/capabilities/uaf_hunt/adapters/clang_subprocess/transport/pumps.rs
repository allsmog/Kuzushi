use super::*;
use std::io::{BufRead, BufReader, Read, Write};

pub(super) fn reader(stdout: ChildStdout, events: SyncSender<Result<Vec<u8>>>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let result = read_frame(&mut reader);
            let failed = result.is_err();
            if events.send(result).is_err() || failed {
                break;
            }
        }
    })
}

pub(super) fn writer(
    mut stdin: ChildStdin,
    input: Receiver<Vec<u8>>,
    events: SyncSender<Result<Vec<u8>>>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while let Ok(bytes) = input.recv() {
            if let Err(error) = write_frame(&mut stdin, &bytes) {
                let _ = events.send(Err(error));
                break;
            }
        }
    })
}

fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    writer
        .write_all(bytes)
        .context("uaf-hunt: MCP stdin write failed")?;
    writer.flush().context("uaf-hunt: MCP stdin flush failed")?;
    Ok(())
}

fn read_frame(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    reader
        .take((MAX_FRAME_BYTES + 1) as u64)
        .read_until(b'\n', &mut frame)
        .context("uaf-hunt: MCP stdout read failed")?;
    anyhow::ensure!(
        !frame.is_empty(),
        "uaf-hunt: mcp-clang closed stdout unexpectedly"
    );
    anyhow::ensure!(
        frame.len() <= MAX_FRAME_BYTES,
        "uaf-hunt: MCP frame byte limit exceeded"
    );
    anyhow::ensure!(
        frame.last() == Some(&b'\n'),
        "uaf-hunt: MCP frame ended without a newline"
    );
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_preserve_exact_bytes_and_reject_truncation_or_excess() {
        assert_eq!(read_frame(&mut Cursor::new(b"{}\n")).unwrap(), b"{}\n");
        assert!(read_frame(&mut Cursor::new(b"{}")).is_err());
        assert!(read_frame(&mut Cursor::new(b"")).is_err());
        let error = read_frame(&mut Cursor::new(vec![b'x'; MAX_FRAME_BYTES + 1])).unwrap_err();
        assert!(error.to_string().contains("byte limit"));
    }
}
