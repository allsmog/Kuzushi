//! `read_source` impl — bounded file reads with line-range slicing.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::canonicalise::canonicalise_within;

/// Hard cap on bytes returned in a single read. Beyond this we truncate
/// with a marker so the model can reissue with a narrower line range
/// rather than getting flooded.
pub const MAX_READ_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadSourceInput {
    pub file: String,
    #[serde(default)]
    pub start_line: Option<u32>,
    #[serde(default)]
    pub end_line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadSourceOutput {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub total_lines: u32,
    pub contents: String,
    pub truncated: bool,
}

/// Read a slice of `input.file` relative to `root`. Returns 1-indexed
/// inclusive line ranges so the model can navigate as it reads.
pub fn read_source(root: &Path, input: &ReadSourceInput) -> Result<ReadSourceOutput> {
    let canonical = canonicalise_within(root, &input.file)
        .with_context(|| format!("read_source: path {:?}", input.file))?;
    let raw = fs::read_to_string(&canonical)
        .with_context(|| format!("read_source: could not read {}", input.file))?;

    let lines: Vec<&str> = raw.split_inclusive('\n').collect();
    let total = lines.len() as u32;

    let start = input.start_line.unwrap_or(1).max(1);
    let end = input.end_line.unwrap_or(total).min(total);
    let (start, end) = if start > end {
        (1, total)
    } else {
        (start, end)
    };

    if total == 0 {
        return Ok(ReadSourceOutput {
            file: input.file.clone(),
            start_line: 1,
            end_line: 0,
            total_lines: 0,
            contents: String::new(),
            truncated: false,
        });
    }

    let slice = &lines[(start as usize - 1)..(end as usize)];
    let mut contents = slice.concat();
    let mut truncated = false;
    if contents.len() > MAX_READ_BYTES {
        // Truncate on a UTF-8 char boundary.
        let mut cap = MAX_READ_BYTES;
        while !contents.is_char_boundary(cap) {
            cap -= 1;
        }
        contents.truncate(cap);
        contents.push_str("\n... [truncated by read_source; reissue with narrower line range]\n");
        truncated = true;
    }

    Ok(ReadSourceOutput {
        file: input.file.clone(),
        start_line: start,
        end_line: end,
        total_lines: total,
        contents,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_lines(dir: &Path, name: &str, n: usize) -> std::path::PathBuf {
        let body: String = (1..=n).map(|i| format!("line {i}\n")).collect();
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn full_read_returns_every_line() {
        let tmp = tempdir().unwrap();
        write_lines(tmp.path(), "a.rs", 5);
        let out = read_source(
            tmp.path(),
            &ReadSourceInput {
                file: "a.rs".to_string(),
                start_line: None,
                end_line: None,
            },
        )
        .unwrap();
        assert_eq!(out.total_lines, 5);
        assert_eq!(out.start_line, 1);
        assert_eq!(out.end_line, 5);
        assert_eq!(out.contents, "line 1\nline 2\nline 3\nline 4\nline 5\n");
        assert!(!out.truncated);
    }

    #[test]
    fn line_range_is_inclusive_1_indexed() {
        let tmp = tempdir().unwrap();
        write_lines(tmp.path(), "a.rs", 10);
        let out = read_source(
            tmp.path(),
            &ReadSourceInput {
                file: "a.rs".to_string(),
                start_line: Some(3),
                end_line: Some(5),
            },
        )
        .unwrap();
        assert_eq!(out.contents, "line 3\nline 4\nline 5\n");
    }

    #[test]
    fn overshooting_end_line_clamps_to_total() {
        let tmp = tempdir().unwrap();
        write_lines(tmp.path(), "a.rs", 4);
        let out = read_source(
            tmp.path(),
            &ReadSourceInput {
                file: "a.rs".to_string(),
                start_line: Some(2),
                end_line: Some(99),
            },
        )
        .unwrap();
        assert_eq!(out.end_line, 4);
    }

    #[test]
    fn truncates_huge_reads_and_marks_flag() {
        let tmp = tempdir().unwrap();
        let body = "a".repeat(MAX_READ_BYTES + 100);
        fs::write(tmp.path().join("big.rs"), body).unwrap();
        let out = read_source(
            tmp.path(),
            &ReadSourceInput {
                file: "big.rs".to_string(),
                start_line: None,
                end_line: None,
            },
        )
        .unwrap();
        assert!(out.truncated);
        assert!(out.contents.contains("[truncated"));
    }

    #[test]
    fn rejects_path_escape() {
        let tmp = tempdir().unwrap();
        let inner = tmp.path().join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(tmp.path().join("outside.txt"), "secret").unwrap();
        let err = read_source(
            &inner,
            &ReadSourceInput {
                file: "../outside.txt".to_string(),
                start_line: None,
                end_line: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("read_source"));
    }
}
