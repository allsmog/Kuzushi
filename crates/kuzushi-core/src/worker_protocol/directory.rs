use super::{fs_list_entry, KwpError, KWP_MAX_MESSAGE_BYTES};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub(super) const FS_LIST_MAX_ENTRIES: usize = 4_096;
pub(super) const FS_LIST_MAX_BYTES: u64 = (KWP_MAX_MESSAGE_BYTES - 1_024) as u64;

#[derive(Debug)]
pub(super) struct BoundedDirectory {
    pub(super) entries: Vec<Value>,
    pub(super) response_bytes: u64,
}

pub(super) fn read_bounded_directory(
    path: &Path,
    max_entries: usize,
    max_bytes: u64,
    byte_resource: &'static str,
) -> Result<BoundedDirectory, KwpError> {
    let mut entries = Vec::new();
    let mut response_bytes = b"{\"entries\":[]}".len() as u64;
    ensure_response_fits(response_bytes, max_bytes, byte_resource)?;
    let directory = fs::read_dir(path).map_err(|error| KwpError::Internal(error.to_string()))?;
    for entry in directory {
        if entries.len() >= max_entries {
            return Err(KwpError::quota("fs.entries"));
        }
        let value = fs_list_entry(entry.map_err(|error| KwpError::Internal(error.to_string()))?)?;
        let value_bytes = serde_json::to_vec(&value)
            .map_err(|error| KwpError::Internal(error.to_string()))?
            .len() as u64;
        let separator = u64::from(!entries.is_empty());
        response_bytes = response_bytes
            .checked_add(value_bytes.saturating_add(separator))
            .ok_or_else(|| KwpError::quota(byte_resource))?;
        ensure_response_fits(response_bytes, max_bytes, byte_resource)?;
        entries.push(value);
    }
    entries.sort_by(|left, right| entry_name(left).cmp(entry_name(right)));
    Ok(BoundedDirectory {
        entries,
        response_bytes,
    })
}

fn ensure_response_fits(
    response_bytes: u64,
    max_bytes: u64,
    resource: &'static str,
) -> Result<(), KwpError> {
    if response_bytes > max_bytes {
        Err(KwpError::quota(resource))
    } else {
        Ok(())
    }
}

fn entry_name(value: &Value) -> &str {
    value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_entries_and_enforces_count_before_collecting_limit_plus_one() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("z-last"), "z").unwrap();
        fs::write(temp.path().join("a-first"), "a").unwrap();

        let listing = read_bounded_directory(temp.path(), 2, u64::MAX, "fs.list.bytes").unwrap();
        assert_eq!(entry_name(&listing.entries[0]), "a-first");
        assert_eq!(entry_name(&listing.entries[1]), "z-last");
        assert_eq!(
            read_bounded_directory(temp.path(), 1, u64::MAX, "fs.list.bytes").unwrap_err(),
            KwpError::quota("fs.entries")
        );
    }

    #[test]
    fn exact_response_size_succeeds_and_limit_minus_one_fails() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("entry"), "value").unwrap();
        let measured = read_bounded_directory(temp.path(), 1, u64::MAX, "fs.bytes")
            .unwrap()
            .response_bytes;

        assert!(read_bounded_directory(temp.path(), 1, measured, "fs.bytes").is_ok());
        assert_eq!(
            read_bounded_directory(temp.path(), 1, measured - 1, "fs.bytes").unwrap_err(),
            KwpError::quota("fs.bytes")
        );
    }
}
