//! Bounded, no-follow input hashing for an approval's comparison identity.
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_INPUT_ENTRIES: usize = 100_000;
const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_ENGINE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(30);

pub(super) struct InputBudget {
    remaining_entries: usize,
    remaining_bytes: u64,
    deadline: Instant,
}

impl Default for InputBudget {
    fn default() -> Self {
        Self {
            remaining_entries: MAX_INPUT_ENTRIES,
            remaining_bytes: MAX_INPUT_BYTES,
            deadline: Instant::now() + SNAPSHOT_DEADLINE,
        }
    }
}

impl InputBudget {
    fn check_deadline(&self) -> Result<()> {
        anyhow::ensure!(Instant::now() < self.deadline,
            "Plan input inspection exceeded its 30-second deadline; no complete identity was recorded. Review a smaller explicit engine selection.");
        Ok(())
    }

    fn visit_entry(&mut self) -> Result<()> {
        self.check_deadline()?;
        anyhow::ensure!(self.remaining_entries > 0,
            "Plan input inspection exceeded its 100,000-entry limit; no complete identity was recorded. Review a smaller explicit engine selection.");
        self.remaining_entries -= 1;
        Ok(())
    }

    fn consume_bytes(&mut self, count: usize) -> Result<()> {
        self.check_deadline()?;
        anyhow::ensure!(count as u64 <= self.remaining_bytes,
            "Plan input inspection exceeded its 512 MiB read limit; no complete identity was recorded. Review a smaller explicit engine selection.");
        self.remaining_bytes -= count as u64;
        Ok(())
    }
}

pub(super) fn tree_rows(
    root: &Path,
    path: &Path,
    budget: &mut InputBudget,
    per_file_limit: u64,
) -> Result<Vec<(String, String)>> {
    let mut pending = vec![path.to_path_buf()];
    let mut rows = Vec::new();
    while let Some(directory) = pending.pop() {
        budget.check_deadline()?;
        let entries = crate::bounded_file::read_dir_within(root, &directory)
            .with_context(|| format!("could not inspect plan input {}", directory.display()))?;
        for entry in entries {
            budget.visit_entry()?;
            collect_entry(
                root,
                entry?,
                budget,
                per_file_limit,
                &mut pending,
                &mut rows,
            )?;
        }
    }
    rows.sort();
    Ok(rows)
}

pub(super) fn optional_tree_rows(
    root: &Path,
    path: &Path,
    budget: &mut InputBudget,
    per_file_limit: u64,
) -> Result<Option<Vec<(String, String)>>> {
    budget.check_deadline()?;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Could not inspect plan input directory"),
    };
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "Plan input directory must not be a symlink: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.is_dir(),
        "Plan input directory is not a directory: {}",
        path.display()
    );
    tree_rows(root, path, budget, per_file_limit).map(Some)
}

fn collect_entry(
    root: &Path,
    entry: std::fs::DirEntry,
    budget: &mut InputBudget,
    per_file_limit: u64,
    pending: &mut Vec<PathBuf>,
    rows: &mut Vec<(String, String)>,
) -> Result<()> {
    let kind = entry.file_type()?;
    let path = entry.path();
    anyhow::ensure!(
        !kind.is_symlink(),
        "plan input {} must not be a symlink",
        path.display()
    );
    if kind.is_dir() {
        pending.push(path);
        return Ok(());
    }
    anyhow::ensure!(kind.is_file(), "unsupported plan input {}", path.display());
    let file = crate::bounded_file::open_regular_file_within(root, &path)?;
    let digest = file_digest(file, budget, per_file_limit)
        .with_context(|| format!("Could not capture plan input {}", path.display()))?;
    rows.push((
        path.strip_prefix(root)?.to_string_lossy().into_owned(),
        digest,
    ));
    Ok(())
}

pub(super) fn executable_digest(path: &Path, budget: &mut InputBudget) -> Result<String> {
    budget.visit_entry()?;
    let file = crate::bounded_file::open_regular_file(path)
        .with_context(|| format!("could not inspect engine input {}", path.display()))?;
    file_digest(file, budget, MAX_ENGINE_FILE_BYTES)
        .with_context(|| format!("Could not capture engine input {}", path.display()))
}

fn file_digest(mut file: File, budget: &mut InputBudget, per_file_limit: u64) -> Result<String> {
    let before = file.metadata()?;
    anyhow::ensure!(before.len() <= per_file_limit,
        "Plan identity file exceeds its {per_file_limit}-byte limit; no complete identity was recorded");
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    while total < before.len() {
        budget.check_deadline()?;
        let window = read_window(budget, before.len() - total, buffer.len())?;
        let count = file.read(&mut buffer[..window])?;
        if count == 0 {
            break;
        }
        total += count as u64;
        budget.consume_bytes(count)?;
        digest.update(&buffer[..count]);
    }
    ensure_unchanged(&before, &file.metadata()?, total)?;
    let hex = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{hex}"))
}

fn read_window(budget: &InputBudget, remaining_file: u64, buffer_size: usize) -> Result<usize> {
    let window = remaining_file
        .min(budget.remaining_bytes)
        .min(buffer_size as u64) as usize;
    anyhow::ensure!(window > 0, "Plan input inspection exceeded its 512 MiB read limit; no complete identity was recorded. Review a smaller explicit engine selection.");
    Ok(window)
}

fn ensure_unchanged(before: &Metadata, after: &Metadata, inspected: u64) -> Result<()> {
    anyhow::ensure!(
        before.len() == inspected
            && before.len() == after.len()
            && before.modified()? == after.modified()?,
        "Plan identity input changed while hashing"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
