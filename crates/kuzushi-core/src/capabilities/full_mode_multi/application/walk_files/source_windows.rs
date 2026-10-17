use super::*;
use crate::capabilities::full_mode_multi::domain::MAX_FILE_BYTES;
use std::io::{BufRead, BufReader, Read};

pub(super) fn buckets(
    file: std::fs::File,
    path: &str,
    bytes: usize,
    canceled: &dyn Fn() -> bool,
) -> (Result<Vec<FileBucket>>, usize) {
    let mut windows = Windows::default();
    let result = read_windows(file, path, bytes, canceled, &mut windows);
    (result, windows.read_bytes)
}

fn read_windows(
    file: std::fs::File,
    path: &str,
    bytes: usize,
    canceled: &dyn Fn() -> bool,
    windows: &mut Windows,
) -> Result<Vec<FileBucket>> {
    let mut reader = BufReader::with_capacity(16 * 1024, file.take(bytes as u64));
    loop {
        anyhow::ensure!(!canceled(), "source window planning canceled");
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take((MAX_FILE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)?;
        windows.read_bytes += read;
        if read == 0 {
            break;
        }
        anyhow::ensure!(
            read <= MAX_FILE_BYTES,
            "source line exceeds the bounded window size of {MAX_FILE_BYTES} bytes"
        );
        std::str::from_utf8(&line)?;
        windows.push_line(path, read);
    }
    anyhow::ensure!(
        windows.read_bytes == bytes && reader.get_ref().get_ref().metadata()?.len() == bytes as u64,
        "source size changed during planning; replan the current source"
    );
    windows.flush(path);
    Ok(std::mem::take(&mut windows.buckets))
}

#[derive(Default)]
struct Windows {
    buckets: Vec<FileBucket>,
    read_bytes: usize,
    start_byte: usize,
    lines: usize,
    start_line: usize,
    current_bytes: usize,
    current_lines: usize,
}

impl Windows {
    fn push_line(&mut self, path: &str, bytes: usize) {
        if self.current_bytes > 0 && self.current_bytes + bytes > MAX_FILE_BYTES {
            self.flush(path);
        }
        self.current_bytes += bytes;
        self.current_lines += 1;
    }

    fn flush(&mut self, path: &str) {
        if self.current_bytes == 0 {
            return;
        }
        self.buckets.push(FileBucket {
            path: path.into(),
            bytes: self.current_bytes,
            est_tokens: est_tokens_for_bytes(self.current_bytes),
            start_byte: self.start_byte,
            start_line: self.start_line + 1,
        });
        self.start_byte += self.current_bytes;
        self.lines += self.current_lines;
        self.start_line = self.lines;
        self.current_bytes = 0;
        self.current_lines = 0;
    }
}
