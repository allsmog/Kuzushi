use super::{
    ensure_file_size, ensure_regular_path, ensure_same_file, read_error, JsonlLimits, KwpError,
};
use crate::worker_protocol::open_fs_read_no_follow;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

#[derive(Clone, Copy)]
pub(in crate::worker_protocol) enum MissingFile {
    Empty,
    Error,
}

pub(in crate::worker_protocol) fn read_bounded_jsonl<T>(
    path: &Path,
    limits: JsonlLimits,
    missing: MissingFile,
) -> Result<Vec<T>, KwpError>
where
    T: DeserializeOwned + Serialize,
{
    let Some(file) = open_bounded_jsonl(path, limits, missing)? else {
        return Ok(Vec::new());
    };
    decode_jsonl(file, path, limits)
}

pub(in crate::worker_protocol) fn decode_bounded_jsonl_bytes<T>(
    bytes: &[u8],
    path: &Path,
    limits: JsonlLimits,
) -> Result<Vec<T>, KwpError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > limits.max_file_bytes as usize {
        return Err(limits.quota("bytes"));
    }
    decode_jsonl(std::io::Cursor::new(bytes), path, limits)
}

fn open_bounded_jsonl(
    path: &Path,
    limits: JsonlLimits,
    missing: MissingFile,
) -> Result<Option<File>, KwpError> {
    let path_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match missing {
                MissingFile::Empty => Ok(None),
                MissingFile::Error => Err(read_error(path, error)),
            };
        }
        Err(error) => return Err(read_error(path, error)),
    };
    ensure_regular_path(path, &path_metadata, limits)?;
    ensure_file_size(path_metadata.len(), limits)?;
    let file = open_fs_read_no_follow(path).map_err(|error| read_error(path, error))?;
    let handle_metadata = file.metadata().map_err(|error| read_error(path, error))?;
    ensure_same_file(path, &path_metadata, &file, &handle_metadata, limits)?;
    ensure_file_size(handle_metadata.len(), limits)?;
    Ok(Some(file))
}

fn decode_jsonl<T>(reader: impl Read, path: &Path, limits: JsonlLimits) -> Result<Vec<T>, KwpError>
where
    T: DeserializeOwned + Serialize,
{
    let mut reader = BufReader::new(reader.take(limits.max_file_bytes.saturating_add(1)));
    let mut records = Vec::new();
    let mut state = DecodeState::default();
    while let Some((line, consumed)) = read_bounded_line(&mut reader, limits)? {
        decode_jsonl_line(&mut records, &mut state, line, consumed, path, limits)?;
    }
    Ok(records)
}

#[derive(Default)]
struct DecodeState {
    file_bytes: u64,
    decoded_bytes: u64,
}

fn decode_jsonl_line<T>(
    records: &mut Vec<T>,
    state: &mut DecodeState,
    line: Vec<u8>,
    consumed: u64,
    path: &Path,
    limits: JsonlLimits,
) -> Result<(), KwpError>
where
    T: DeserializeOwned + Serialize,
{
    state.file_bytes = add_file_bytes(state.file_bytes, consumed, limits)?;
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    ensure_record_capacity(records.len(), limits)?;
    let record = parse_jsonl_record(&line, path, limits)?;
    state.decoded_bytes = add_decoded_size(state.decoded_bytes, &record, limits)?;
    records.push(record);
    Ok(())
}

fn add_file_bytes(current: u64, consumed: u64, limits: JsonlLimits) -> Result<u64, KwpError> {
    let next = current
        .checked_add(consumed)
        .ok_or_else(|| limits.quota("bytes"))?;
    if next > limits.max_file_bytes {
        Err(limits.quota("bytes"))
    } else {
        Ok(next)
    }
}

fn ensure_record_capacity(count: usize, limits: JsonlLimits) -> Result<(), KwpError> {
    if count >= limits.max_records {
        Err(limits.quota("records"))
    } else {
        Ok(())
    }
}

fn parse_jsonl_record<T: DeserializeOwned>(
    line: &[u8],
    path: &Path,
    limits: JsonlLimits,
) -> Result<T, KwpError> {
    serde_json::from_slice(line).map_err(|error| {
        KwpError::Internal(format!(
            "could not parse {} {}: {error}",
            limits.label,
            path.display()
        ))
    })
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    limits: JsonlLimits,
) -> Result<Option<(Vec<u8>, u64)>, KwpError> {
    let mut line = Vec::with_capacity(limits.max_line_bytes.min(8 * 1024));
    let mut consumed = 0_u64;
    loop {
        let Some(chunk) = next_line_chunk(reader)? else {
            return Ok((consumed > 0).then_some((line, consumed)));
        };
        append_line_chunk(&mut line, &chunk.content, limits)?;
        consumed = consumed
            .checked_add(chunk.consumed)
            .ok_or_else(|| limits.quota("bytes"))?;
        if chunk.complete {
            return Ok(Some((line, consumed)));
        }
    }
}

struct LineChunk {
    content: Vec<u8>,
    consumed: u64,
    complete: bool,
}

fn next_line_chunk(reader: &mut impl BufRead) -> Result<Option<LineChunk>, KwpError> {
    let buffer = reader
        .fill_buf()
        .map_err(|error| KwpError::Internal(format!("could not read JSONL log: {error}")))?;
    if buffer.is_empty() {
        return Ok(None);
    }
    let newline = buffer.iter().position(|byte| *byte == b'\n');
    let consumed = newline.map_or(buffer.len(), |index| index + 1);
    let content_end = newline.unwrap_or(buffer.len());
    let chunk = LineChunk {
        content: buffer[..content_end].to_vec(),
        consumed: consumed as u64,
        complete: newline.is_some(),
    };
    reader.consume(consumed);
    Ok(Some(chunk))
}

fn append_line_chunk(
    line: &mut Vec<u8>,
    chunk: &[u8],
    limits: JsonlLimits,
) -> Result<(), KwpError> {
    if line.len().saturating_add(chunk.len()) > limits.max_line_bytes {
        return Err(limits.quota("line.bytes"));
    }
    line.extend_from_slice(chunk);
    Ok(())
}

fn add_decoded_size<T: Serialize>(
    current: u64,
    record: &T,
    limits: JsonlLimits,
) -> Result<u64, KwpError> {
    let size = serde_json::to_vec(record)
        .map_err(|error| KwpError::Internal(format!("could not meter JSONL record: {error}")))?
        .len() as u64;
    let next = current
        .checked_add(size)
        .ok_or_else(|| limits.quota("decoded.bytes"))?;
    if next > limits.max_decoded_bytes {
        Err(limits.quota("decoded.bytes"))
    } else {
        Ok(next)
    }
}
