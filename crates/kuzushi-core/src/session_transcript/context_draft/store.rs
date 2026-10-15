use super::*;
use crate::bounded_file::read_regular_bytes_within;
use crate::session_transcript::store::{
    ensure_secure_directory, reject_kuzushi_symlink_ancestors, validate_secure_directory,
};
use anyhow::Context;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const MAX_RECORDS: usize = 128;
const MAX_RECOVERY_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ContextDraftStore {
    root: PathBuf,
}

impl ContextDraftStore {
    pub fn from_sessions_root(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().with_file_name("context-drafts"),
        }
    }

    pub fn write(&self, record: &ContextDraftRecord) -> Result<()> {
        record.validate()?;
        let directory = self.directory(&record.target, &record.source)?;
        ensure_secure_directory(&self.root)?;
        ensure_secure_directory(&directory)?;
        let path = directory.join(format!("{}.json", record.session_id));
        check_new_slot_capacity(&directory, &path)?;
        let record = merge_existing_resolutions(&path, record)?;
        record.validate()?;
        crate::fs_atomic::write_atomic_bytes(&path, &serde_json::to_vec(&record)?)
    }

    pub fn recover(
        &self,
        target: &Path,
        source: &ThreatModelRef,
    ) -> Result<Vec<RecoveredContextDraft>> {
        let directory = self.directory(target, source)?;
        reject_kuzushi_symlink_ancestors(&self.root)?;
        if !directory_exists(&directory)? {
            return Ok(Vec::new());
        }
        validate_secure_directory(&self.root)?;
        validate_secure_directory(&directory)?;
        let records = read_records(&directory, target, source)?;
        Ok(unresolved(records))
    }

    fn directory(&self, target: &Path, source: &ThreatModelRef) -> Result<PathBuf> {
        anyhow::ensure!(
            target.is_absolute() && self.root.is_absolute(),
            "Context draft paths must be absolute"
        );
        let identity = serde_json::to_vec(&(target, source))?;
        Ok(self.root.join(digest(&identity)))
    }
}

fn directory_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("Could not inspect saved context drafts"),
    }
}

fn merge_existing_resolutions(
    path: &Path,
    next: &ContextDraftRecord,
) -> Result<ContextDraftRecord> {
    if !directory_exists(path)? {
        return Ok(next.clone());
    }
    let existing = read_record(path)?.record;
    anyhow::ensure!(
        existing.target == next.target
            && existing.source == next.source
            && existing.session_id == next.session_id,
        "Saved context draft identity changed; original checkpoint retained"
    );
    let mut next = next.clone();
    next.resolved_hashes = next
        .resolved_hashes
        .iter()
        .chain(&existing.resolved_hashes)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(next)
}

fn read_records(
    directory: &Path,
    target: &Path,
    source: &ThreatModelRef,
) -> Result<Vec<RecoveredContextDraft>> {
    let mut records = Vec::new();
    let mut remaining = MAX_RECOVERY_BYTES;
    for (index, entry) in fs::read_dir(directory)?.enumerate() {
        anyhow::ensure!(
            index < MAX_RECORDS,
            "Context draft directory exceeds its recovery limit"
        );
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let bytes = read_regular_bytes_within(directory, &path, remaining.min(MAX_DRAFT_BYTES))?;
        remaining = remaining
            .checked_sub(bytes.len())
            .context("Context draft recovery byte limit reached")?;
        let recovered = decode_record(&bytes)?;
        verify_record_identity(&path, &recovered.record, target, source)?;
        records.push(recovered);
    }
    records.sort_by(|a, b| {
        (b.record.saved_at_seconds, &b.record.session_id)
            .cmp(&(a.record.saved_at_seconds, &a.record.session_id))
    });
    Ok(records)
}

fn verify_record_identity(
    path: &Path,
    record: &ContextDraftRecord,
    target: &Path,
    source: &ThreatModelRef,
) -> Result<()> {
    anyhow::ensure!(
        record.target == target && &record.source == source,
        "Saved context draft belongs to another target or revision"
    );
    anyhow::ensure!(
        path.file_stem().and_then(|name| name.to_str()) == Some(record.session_id.as_str()),
        "Saved context draft session does not match its filename"
    );
    Ok(())
}

fn read_record(path: &Path) -> Result<RecoveredContextDraft> {
    let parent = path
        .parent()
        .context("Saved context draft has no directory")?;
    decode_record(&read_regular_bytes_within(parent, path, MAX_DRAFT_BYTES)?)
}

fn decode_record(bytes: &[u8]) -> Result<RecoveredContextDraft> {
    let record: ContextDraftRecord = serde_json::from_slice(bytes)
        .context("Saved context draft is malformed; original checkpoint retained")?;
    record.validate()?;
    Ok(RecoveredContextDraft {
        record,
        record_hash: digest(bytes),
    })
}

fn unresolved(records: Vec<RecoveredContextDraft>) -> Vec<RecoveredContextDraft> {
    let resolved: BTreeSet<_> = records
        .iter()
        .flat_map(|r| r.record.resolved_hashes.iter().cloned())
        .collect();
    records
        .into_iter()
        .filter(|r| r.record.snapshot.is_some() && !resolved.contains(&r.record_hash))
        .collect()
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn check_new_slot_capacity(directory: &Path, slot: &Path) -> Result<()> {
    if directory_exists(slot)? {
        return Ok(());
    }
    let count = fs::read_dir(directory)?.take(MAX_RECORDS).count();
    anyhow::ensure!(
        count < MAX_RECORDS,
        "Context draft directory is full; existing checkpoints retained"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
