use crate::run_lifecycle::{
    RunItemEnvelopeV1, MAX_RUN_ITEM_STREAM_BYTES, MAX_SERIALIZED_RUN_ITEM_BYTES,
    RUN_ITEM_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_RUN_ITEM_STREAM_ITEMS: usize = 1_000_000;

#[derive(Debug, Clone, Copy)]
struct StreamLimits {
    bytes: u64,
    record_bytes: usize,
    items: usize,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            bytes: MAX_RUN_ITEM_STREAM_BYTES,
            record_bytes: MAX_SERIALIZED_RUN_ITEM_BYTES,
            items: MAX_RUN_ITEM_STREAM_ITEMS,
        }
    }
}

#[derive(Debug)]
pub(super) struct StreamRecord {
    pub(super) line_number: usize,
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone)]
pub(super) struct StreamCursorCheckpoint {
    bytes_read: u64,
    items_read: usize,
    prefix_digest: Sha256,
}

pub(super) struct RunItemStreamReader {
    root: Option<PathBuf>,
    path: PathBuf,
    reader: BufReader<File>,
    identity: FileIdentity,
    limits: StreamLimits,
    bytes_read: u64,
    items_read: usize,
    prefix_digest: Sha256,
}

impl RunItemStreamReader {
    #[cfg(test)]
    pub(super) fn open(path: &Path) -> io::Result<Option<Self>> {
        Self::open_with_limits(path, StreamLimits::default())
    }

    pub(super) fn open_within(root: &Path, path: &Path) -> io::Result<Option<Self>> {
        let file = match crate::bounded_file::open_regular_file_within(root, path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        Self::from_open_file_with_limits(Some(root), path, file, StreamLimits::default()).map(Some)
    }

    #[cfg(test)]
    fn open_with_limits(path: &Path, limits: StreamLimits) -> io::Result<Option<Self>> {
        let file = match crate::bounded_file::open_regular_file(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        Self::from_open_file_with_limits(None, path, file, limits).map(Some)
    }

    pub(super) fn from_open_file_within(root: &Path, path: &Path, file: File) -> io::Result<Self> {
        Self::from_open_file_with_limits(Some(root), path, file, StreamLimits::default())
    }

    fn from_open_file_with_limits(
        root: Option<&Path>,
        path: &Path,
        file: File,
        limits: StreamLimits,
    ) -> io::Result<Self> {
        reject_oversized_stream(path, &file.metadata()?, limits.bytes)?;
        let identity = FileIdentity::from_file(&file)?;
        Ok(Self {
            root: root.map(Path::to_path_buf),
            path: path.to_path_buf(),
            reader: BufReader::new(file),
            identity,
            limits,
            bytes_read: 0,
            items_read: 0,
            prefix_digest: Sha256::new(),
        })
    }

    pub(super) fn next_record(&mut self) -> io::Result<Option<StreamRecord>> {
        if self.items_read >= self.limits.items {
            return self.reject_additional_item();
        }
        let Some(raw) = read_raw_record(&mut self.reader, self.limits.record_bytes)? else {
            return Ok(None);
        };
        self.record_consumed(&raw)?;
        Ok(Some(StreamRecord {
            line_number: self.items_read,
            bytes: record_body(raw),
        }))
    }

    pub(super) fn verify_path_unchanged(&self) -> io::Result<()> {
        let mut current = self.reopen_current_path()?;
        let metadata = current.metadata()?;
        reject_oversized_stream(&self.path, &metadata, self.limits.bytes)?;
        reject_replaced_file(&self.identity, &current)?;
        reject_truncated_file(self.bytes_read, metadata.len())?;
        verify_consumed_prefix(&mut current, self.bytes_read, &self.prefix_digest)?;
        Ok(())
    }

    fn reopen_current_path(&self) -> io::Result<File> {
        match self.root.as_deref() {
            Some(root) => crate::bounded_file::open_regular_file_within(root, &self.path),
            None => crate::bounded_file::open_regular_file(&self.path),
        }
    }

    pub(super) fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    pub(super) fn checkpoint(&self) -> StreamCursorCheckpoint {
        StreamCursorCheckpoint {
            bytes_read: self.bytes_read,
            items_read: self.items_read,
            prefix_digest: self.prefix_digest.clone(),
        }
    }

    pub(super) fn restore(&mut self, checkpoint: StreamCursorCheckpoint) -> io::Result<()> {
        self.reader.seek(SeekFrom::Start(checkpoint.bytes_read))?;
        self.bytes_read = checkpoint.bytes_read;
        self.items_read = checkpoint.items_read;
        self.prefix_digest = checkpoint.prefix_digest;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn records_read(&self) -> usize {
        self.items_read
    }

    fn reject_additional_item(&mut self) -> io::Result<Option<StreamRecord>> {
        if self.reader.fill_buf()?.is_empty() {
            return Ok(None);
        }
        Err(invalid_data(format!(
            "run-item stream exceeds the {}-item limit",
            self.limits.items
        )))
    }

    fn record_consumed(&mut self, raw: &[u8]) -> io::Result<()> {
        let consumed = u64::try_from(raw.len()).map_err(|_| invalid_data("record is too large"))?;
        self.bytes_read = self
            .bytes_read
            .checked_add(consumed)
            .ok_or_else(|| invalid_data("run-item stream byte count overflow"))?;
        if self.bytes_read > self.limits.bytes {
            return Err(invalid_data(format!(
                "run-item stream exceeds the {}-byte limit",
                self.limits.bytes
            )));
        }
        self.items_read += 1;
        self.prefix_digest.update(raw);
        Ok(())
    }
}

pub(super) fn parse_record(record: StreamRecord) -> Result<RunItemEnvelopeV1, String> {
    let value = serde_json::from_slice::<serde_json::Value>(&record.bytes)
        .map_err(|error| format!("line {}: {error}", record.line_number))?;
    let version = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64);
    if version != Some(u64::from(RUN_ITEM_SCHEMA_VERSION)) {
        return Err(format!(
            "line {}: unknown schema version {version:?}",
            record.line_number
        ));
    }
    serde_json::from_value(value).map_err(|error| format!("line {}: {error}", record.line_number))
}

fn read_raw_record(reader: &mut BufReader<File>, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
    let read_limit = max_bytes
        .checked_add(2)
        .ok_or_else(|| invalid_data("run-item record limit overflow"))?;
    let mut raw = Vec::with_capacity(read_limit.min(8 * 1024));
    let read = reader
        .by_ref()
        .take(read_limit as u64)
        .read_until(b'\n', &mut raw)?;
    if read == 0 {
        return Ok(None);
    }
    let body_len = raw.len() - usize::from(raw.ends_with(b"\n"));
    let body_len = body_len - usize::from(raw[..body_len].ends_with(b"\r"));
    if body_len > max_bytes {
        return Err(invalid_data(format!(
            "run-item record exceeds the {max_bytes}-byte limit"
        )));
    }
    Ok(Some(raw))
}

fn record_body(mut raw: Vec<u8>) -> Vec<u8> {
    if raw.last() == Some(&b'\n') {
        raw.pop();
    }
    if raw.last() == Some(&b'\r') {
        raw.pop();
    }
    raw
}

fn verify_consumed_prefix(file: &mut File, bytes_read: u64, expected: &Sha256) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let actual = digest_prefix(file, bytes_read)?;
    if actual != <[u8; 32]>::from(expected.clone().finalize()) {
        return Err(invalid_data("run-item stream committed prefix changed"));
    }
    Ok(())
}

fn digest_prefix(file: &mut File, mut remaining: u64) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let length = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| invalid_data("committed prefix is too large"))?;
        file.read_exact(&mut buffer[..length])?;
        digest.update(&buffer[..length]);
        remaining -= length as u64;
    }
    Ok(digest.finalize().into())
}

fn reject_oversized_stream(path: &Path, metadata: &Metadata, max_bytes: u64) -> io::Result<()> {
    if metadata.len() > max_bytes {
        return Err(invalid_data(format!(
            "{} exceeds the {max_bytes}-byte run-item stream limit",
            path.display()
        )));
    }
    Ok(())
}

fn reject_truncated_file(bytes_read: u64, current_length: u64) -> io::Result<()> {
    if current_length < bytes_read {
        return Err(invalid_data(
            "run-item stream was truncated during delivery",
        ));
    }
    Ok(())
}

fn reject_replaced_file(expected: &FileIdentity, current: &File) -> io::Result<()> {
    if &FileIdentity::from_file(current)? != expected {
        return Err(invalid_data("run-item stream was replaced during delivery"));
    }
    Ok(())
}

fn invalid_data(detail: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
}

impl FileIdentity {
    #[cfg(unix)]
    fn from_file(file: &File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    fn from_file(file: &File) -> io::Result<Self> {
        let identity = crate::file_lock::windows_file_identity(file)?;
        Ok(Self {
            volume_serial_number: identity.volume_serial_number,
            file_index: identity.file_index,
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn from_file(_file: &File) -> io::Result<Self> {
        Ok(Self {})
    }
}

#[cfg(test)]
mod tests;
