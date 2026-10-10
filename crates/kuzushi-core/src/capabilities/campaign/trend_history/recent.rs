use super::{TrendSnapshot, TREND_HISTORY_LIMIT};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

pub(super) const MAX_HISTORY_BYTES: u64 = 1024 * 1024;

pub(super) fn load_recent_history(
    root: &Path,
    path: &Path,
    limit: usize,
) -> io::Result<Vec<TrendSnapshot>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let file = crate::bounded_file::open_regular_file_within(root, path)?;
    let (bytes, truncated) = read_history_tail(file)?;
    Ok(parse_recent_snapshots(&bytes, truncated, limit))
}

fn read_history_tail(mut file: File) -> io::Result<(Vec<u8>, bool)> {
    let size = file.metadata()?.len();
    let offset = size.saturating_sub(MAX_HISTORY_BYTES);
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::with_capacity((size - offset) as usize);
    file.take(size - offset).read_to_end(&mut bytes)?;
    Ok((bytes, offset > 0))
}

fn parse_recent_snapshots(bytes: &[u8], truncated: bool, limit: usize) -> Vec<TrendSnapshot> {
    let mut snapshots = complete_tail(bytes, truncated)
        .rsplit(|byte| *byte == b'\n')
        .filter_map(parse_snapshot)
        .take(limit.min(TREND_HISTORY_LIMIT))
        .collect::<Vec<_>>();
    snapshots.reverse();
    snapshots
}

fn complete_tail(bytes: &[u8], truncated: bool) -> &[u8] {
    if !truncated {
        return bytes;
    }
    let start = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |index| index + 1);
    &bytes[start..]
}

fn parse_snapshot(line: &[u8]) -> Option<TrendSnapshot> {
    serde_json::from_slice(line).ok()
}

#[cfg(test)]
mod tests;
