use crate::workspace::RepositoryInventory;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

mod coverage;
use coverage::SourceCoverage;

#[derive(Clone, Copy)]
pub(crate) struct SourcePrefixLimits {
    pub max_files: usize,
    pub max_bytes: usize,
    pub max_file_bytes: usize,
}

impl SourcePrefixLimits {
    fn validate(self) -> Result<()> {
        anyhow::ensure!(
            (1..=super::MAX_REPOSITORY_ENTRIES).contains(&self.max_files),
            "source prefix file limit is invalid"
        );
        anyhow::ensure!(
            (1..=super::MAX_REPOSITORY_INSPECTED_BYTES).contains(&self.max_bytes),
            "source prefix byte limit is invalid"
        );
        anyhow::ensure!(
            (1..=256 * 1024).contains(&self.max_file_bytes),
            "source prefix per-file limit is invalid"
        );
        Ok(())
    }
}

pub(crate) struct SourcePrefix {
    pub relative: String,
    pub text: String,
}

pub(crate) struct SourcePrefixes {
    pub(crate) files: Vec<SourcePrefix>,
    pub(crate) coverage: Value,
}

pub(crate) fn collect_source_prefixes(
    root: &Path,
    limits: SourcePrefixLimits,
    selected: &dyn Fn(&str) -> bool,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<SourcePrefixes> {
    limits.validate()?;
    let inventory =
        crate::workspace::build_repository_inventory_with_observer(root, progress, canceled)?;
    index_source_prefixes(root, inventory, limits, selected, canceled)
}

pub(crate) fn index_source_prefixes(
    root: &Path,
    inventory: RepositoryInventory,
    limits: SourcePrefixLimits,
    selected: &dyn Fn(&str) -> bool,
    canceled: &dyn Fn() -> bool,
) -> Result<SourcePrefixes> {
    limits.validate()?;
    ensure_active(canceled)?;
    let mut coverage = SourceCoverage::new(&inventory, limits);
    let excluded = inventory
        .generated_vendor_paths
        .iter()
        .map(|row| row.path.as_str())
        .collect::<BTreeSet<_>>();
    let paths = inventory
        .inspection
        .as_ref()
        .context("Source prefixes require an inventory inspection receipt")?;
    let mut files = Vec::new();
    for relative in &paths.files {
        ensure_active(canceled)?;
        if excluded.contains(relative.as_str()) || !selected(relative) {
            coverage.exclude(relative, "outside selected source paths");
            continue;
        }
        collect_file(root, relative, &mut files, &mut coverage);
    }
    Ok(SourcePrefixes {
        files,
        coverage: coverage.receipt(&inventory),
    })
}

fn collect_file(
    root: &Path,
    relative: &str,
    files: &mut Vec<SourcePrefix>,
    coverage: &mut SourceCoverage,
) {
    let Some(limit) = coverage.next_file_limit(relative) else {
        return;
    };
    match read_file(root, relative, limit) {
        Ok((bytes, truncated)) => record_file(relative, bytes, truncated, limit, files, coverage),
        Err(error) => coverage.omit(relative, &format!("source unavailable or unsafe: {error}")),
    }
}

fn read_file(root: &Path, relative: &str, limit: usize) -> Result<(Vec<u8>, bool)> {
    let mut file = crate::bounded_file::open_regular_file_within(root, Path::new(relative))?;
    let initial_size = file.metadata()?.len();
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64).read_to_end(&mut bytes)?;
    let final_size = file.metadata()?.len();
    let truncated = initial_size.max(final_size) > bytes.len() as u64;
    Ok((bytes, truncated))
}

fn record_file(
    relative: &str,
    bytes: Vec<u8>,
    truncated: bool,
    reserved: usize,
    files: &mut Vec<SourcePrefix>,
    coverage: &mut SourceCoverage,
) {
    coverage.record_bytes(relative, bytes.len(), truncated, reserved);
    if bytes
        .iter()
        .take(crate::bounded_file::BINARY_SNIFF_BYTES)
        .any(|byte| *byte == 0)
    {
        coverage.omit(relative, "binary-looking source was not indexed");
        return;
    }
    let text = match decode_source_prefix(&bytes, truncated) {
        Ok(text) => text,
        Err(error) => {
            coverage.omit(relative, &format!("source was not indexed: {error}"));
            return;
        }
    };
    coverage.record_text(text.len(), bytes.len() - text.len());
    files.push(SourcePrefix {
        relative: relative.into(),
        text: text.into(),
    });
    coverage.indexed_files += 1;
}

fn decode_source_prefix(bytes: &[u8], truncated: bool) -> Result<&str> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(error) => {
            anyhow::ensure!(
                truncated && error.error_len().is_none(),
                "invalid UTF-8 source"
            );
            Ok(std::str::from_utf8(&bytes[..error.valid_up_to()])?)
        }
    }
}

pub(crate) fn ensure_active(canceled: &dyn Fn() -> bool) -> Result<()> {
    anyhow::ensure!(!canceled(), "source prefix inspection canceled");
    Ok(())
}

#[cfg(test)]
mod tests;
