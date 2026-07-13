use super::*;
use std::collections::{HashMap, HashSet};

const MAX_SINGLE_PATH_BYTES: usize = 4 * 1024;

pub(super) fn parse_tree_listing(
    listing: &[u8],
    limits: MaterializationLimits,
    case_insensitive: bool,
    expected_oid_len: usize,
) -> Result<(Vec<BoundTreeEntry>, u64)> {
    if listing.is_empty() {
        return Ok((Vec::new(), 0));
    }
    anyhow::ensure!(
        listing.ends_with(&[0]),
        "patch:finding bound tree listing was truncated"
    );
    let mut state = ManifestState::new(limits, case_insensitive);
    for record in listing[..listing.len() - 1].split(|byte| *byte == 0) {
        state.push(parse_tree_record(record, expected_oid_len)?)?;
    }
    Ok((state.entries, state.batch_output_bound))
}

fn parse_tree_record(record: &[u8], expected_oid_len: usize) -> Result<BoundTreeEntry> {
    let tab = record
        .iter()
        .position(|byte| *byte == b'\t')
        .context("patch:finding bound tree entry omitted its path separator")?;
    let header = std::str::from_utf8(&record[..tab])
        .context("patch:finding bound tree header was not UTF-8")?;
    let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
    anyhow::ensure!(
        fields.len() == 4,
        "patch:finding bound tree entry had an invalid header"
    );
    validate_blob_mode(fields[0], fields[1])?;
    validate_oid(fields[2], expected_oid_len)?;
    let size = fields[3]
        .parse::<u64>()
        .context("patch:finding bound tree entry had an invalid size")?;
    let (git_path, relative_path) = validated_git_path(&record[tab + 1..])?;
    Ok(BoundTreeEntry {
        mode: fields[0].to_string(),
        oid: fields[2].to_ascii_lowercase(),
        size,
        git_path,
        relative_path,
    })
}

fn validate_blob_mode(mode: &str, object_type: &str) -> Result<()> {
    if object_type == "commit" || mode == "160000" {
        anyhow::bail!("patch:finding bound tree contains an unsupported gitlink");
    }
    if mode == "120000" {
        anyhow::bail!("patch:finding bound tree contains an unsafe symbolic link");
    }
    anyhow::ensure!(
        object_type == "blob" && matches!(mode, "100644" | "100755"),
        "patch:finding bound tree contains an unsupported entry mode"
    );
    Ok(())
}

fn validate_oid(oid: &str, expected_len: usize) -> Result<()> {
    anyhow::ensure!(
        oid.len() == expected_len && oid.chars().all(|ch| ch.is_ascii_hexdigit()),
        "patch:finding bound tree entry had an invalid object id"
    );
    Ok(())
}

fn validated_git_path(raw: &[u8]) -> Result<(String, PathBuf)> {
    let path =
        std::str::from_utf8(raw).context("patch:finding bound tree contains a non-UTF-8 path")?;
    anyhow::ensure!(
        !path.is_empty()
            && path.len() <= MAX_SINGLE_PATH_BYTES
            && !path.starts_with('/')
            && !path.ends_with('/')
            && !path.contains("//")
            && !path.contains(['\\', '\n', '\r']),
        "patch:finding bound tree contains an unsafe path"
    );
    for component in path.split('/') {
        validate_git_path_component(component)?;
    }
    Ok((path.to_string(), PathBuf::from(path)))
}

fn validate_git_path_component(component: &str) -> Result<()> {
    anyhow::ensure!(
        !matches!(component, "." | "..") && !component.eq_ignore_ascii_case(".git"),
        "patch:finding bound tree path targets a reserved component"
    );
    #[cfg(windows)]
    anyhow::ensure!(
        !component.ends_with(['.', ' '])
            && !component.contains(':')
            && !windows_reserved_name(component),
        "patch:finding bound tree path is not representable safely on Windows"
    );
    Ok(())
}

#[cfg(windows)]
fn windows_reserved_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && matches!(&upper[..3], "COM" | "LPT")
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
}

struct ManifestState {
    limits: MaterializationLimits,
    case_insensitive: bool,
    entries: Vec<BoundTreeEntry>,
    exact_paths: HashSet<String>,
    directory_paths: HashSet<String>,
    folded_paths: HashMap<String, String>,
    total_bytes: u64,
    path_bytes: usize,
    index_bytes: usize,
    batch_request_bytes: usize,
    batch_output_bound: u64,
}

impl ManifestState {
    fn new(limits: MaterializationLimits, case_insensitive: bool) -> Self {
        Self {
            limits,
            case_insensitive,
            entries: Vec::new(),
            exact_paths: HashSet::new(),
            directory_paths: HashSet::new(),
            folded_paths: HashMap::new(),
            total_bytes: 0,
            path_bytes: 0,
            index_bytes: 0,
            batch_request_bytes: 0,
            batch_output_bound: 0,
        }
    }

    fn push(&mut self, entry: BoundTreeEntry) -> Result<()> {
        self.validate_collision(&entry.git_path)?;
        self.accumulate(&entry)?;
        self.entries.push(entry);
        Ok(())
    }

    fn validate_collision(&mut self, path: &str) -> Result<()> {
        self.validate_path_shape(path)?;
        anyhow::ensure!(
            self.exact_paths.insert(path.to_string()),
            "patch:finding bound tree contains a duplicate path"
        );
        if self.case_insensitive {
            self.validate_case_folded_prefixes(path)?;
        }
        Ok(())
    }

    fn validate_path_shape(&mut self, path: &str) -> Result<()> {
        anyhow::ensure!(
            !self.directory_paths.contains(path),
            "patch:finding bound tree contains a file/directory path collision"
        );
        let mut prefix = String::new();
        for component in path.split('/').take(path.split('/').count() - 1) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            anyhow::ensure!(
                !self.exact_paths.contains(&prefix),
                "patch:finding bound tree contains a file/directory path collision"
            );
            self.directory_paths.insert(prefix.clone());
        }
        Ok(())
    }

    fn validate_case_folded_prefixes(&mut self, path: &str) -> Result<()> {
        let mut prefix = String::new();
        for component in path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            let folded = prefix.to_lowercase();
            if let Some(existing) = self.folded_paths.get(&folded) {
                anyhow::ensure!(
                    existing == &prefix,
                    "patch:finding bound tree contains a case-folding path collision"
                );
            } else {
                self.folded_paths.insert(folded, prefix.clone());
            }
        }
        Ok(())
    }

    fn accumulate(&mut self, entry: &BoundTreeEntry) -> Result<()> {
        anyhow::ensure!(
            self.entries.len() < self.limits.max_files,
            "patch:finding bound tree exceeds its file-count limit"
        );
        anyhow::ensure!(
            entry.size <= self.limits.max_file_bytes,
            "patch:finding bound tree file exceeds its byte limit"
        );
        self.total_bytes = checked_add_u64(self.total_bytes, entry.size, "tree bytes")?;
        self.path_bytes = checked_add_usize(self.path_bytes, entry.git_path.len(), "path bytes")?;
        self.index_bytes = checked_add_usize(self.index_bytes, index_record_len(entry), "index")?;
        self.batch_request_bytes = checked_add_usize(
            self.batch_request_bytes,
            entry.oid.len() + 1,
            "batch request",
        )?;
        self.batch_output_bound = checked_add_u64(
            self.batch_output_bound,
            batch_record_bound(entry),
            "batch output",
        )?;
        self.ensure_totals()
    }

    fn ensure_totals(&self) -> Result<()> {
        anyhow::ensure!(
            self.total_bytes <= self.limits.max_total_bytes,
            "patch:finding bound tree exceeds its total byte limit"
        );
        anyhow::ensure!(
            self.path_bytes <= self.limits.max_path_bytes,
            "patch:finding bound tree exceeds its path byte limit"
        );
        anyhow::ensure!(
            self.index_bytes <= self.limits.max_index_bytes,
            "patch:finding bound tree exceeds its index byte limit"
        );
        anyhow::ensure!(
            self.batch_request_bytes <= self.limits.max_batch_request_bytes,
            "patch:finding bound tree exceeds its batch request limit"
        );
        anyhow::ensure!(
            self.batch_output_bound <= self.limits.max_batch_stream_bytes,
            "patch:finding bound tree exceeds its batch stream limit"
        );
        Ok(())
    }
}

fn checked_add_u64(current: u64, added: u64, label: &str) -> Result<u64> {
    current
        .checked_add(added)
        .with_context(|| format!("patch:finding bound tree {label} overflowed"))
}

fn checked_add_usize(current: usize, added: usize, label: &str) -> Result<usize> {
    current
        .checked_add(added)
        .with_context(|| format!("patch:finding bound tree {label} overflowed"))
}

fn index_record_len(entry: &BoundTreeEntry) -> usize {
    entry.mode.len() + 1 + entry.oid.len() + 1 + entry.git_path.len() + 1
}

fn batch_record_bound(entry: &BoundTreeEntry) -> u64 {
    entry.size
        + entry.oid.len() as u64
        + 1
        + "blob".len() as u64
        + 1
        + entry.size.to_string().len() as u64
        + 1
        + 1
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
