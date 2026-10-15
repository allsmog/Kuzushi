//! Shared private publication and bounded reading for operator editor data.
use super::store::{
    ensure_secure_directory, reject_kuzushi_symlink_ancestors, validate_secure_directory,
};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const MAX_EDITOR_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 128;
const MAX_READ_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct EditorCheckpointStore {
    root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct EditorCheckpointFile {
    pub record_id: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

impl EditorCheckpointStore {
    pub fn for_study_drafts(sessions_root: impl AsRef<Path>) -> Self {
        Self {
            root: sessions_root.as_ref().with_file_name("study-drafts"),
        }
    }

    pub fn read(&self, target: &Path) -> Result<Vec<EditorCheckpointFile>> {
        let directory = self.directory(target)?;
        reject_kuzushi_symlink_ancestors(&self.root)?;
        if !exists(&directory)? {
            return Ok(Vec::new());
        }
        validate_secure_directory(&self.root)?;
        validate_secure_directory(&directory)?;
        read_directory(&directory)
    }

    pub fn read_record(
        &self,
        target: &Path,
        record_id: &str,
    ) -> Result<Option<EditorCheckpointFile>> {
        super::store::validate_session_id(record_id)?;
        reject_kuzushi_symlink_ancestors(&self.root)?;
        let directory = self.directory(target)?;
        let path = directory.join(format!("{record_id}.json"));
        if !exists(&path)? {
            return Ok(None);
        }
        validate_secure_directory(&self.root)?;
        validate_secure_directory(&directory)?;
        Ok(Some(read_file(
            &directory,
            &path,
            MAX_EDITOR_CHECKPOINT_BYTES,
        )?))
    }

    pub fn write(&self, target: &Path, record_id: &str, bytes: &[u8]) -> Result<()> {
        super::store::validate_session_id(record_id)?;
        anyhow::ensure!(
            bytes.len() <= MAX_EDITOR_CHECKPOINT_BYTES,
            "Editor checkpoint exceeds its file limit"
        );
        let directory = self.directory(target)?;
        ensure_secure_directory(&self.root)?;
        ensure_secure_directory(&directory)?;
        let path = directory.join(format!("{record_id}.json"));
        validate_slot(&directory, &path)?;
        crate::fs_atomic::write_atomic_bytes(&path, bytes)
    }

    fn directory(&self, target: &Path) -> Result<PathBuf> {
        anyhow::ensure!(
            self.root.is_absolute() && target.is_absolute(),
            "Editor checkpoint paths must be absolute"
        );
        Ok(self.root.join(digest(&serde_json::to_vec(target)?)))
    }
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("Could not inspect editor checkpoint"),
    }
}

fn validate_slot(directory: &Path, path: &Path) -> Result<()> {
    if exists(path)? {
        read_file(directory, path, MAX_EDITOR_CHECKPOINT_BYTES)?;
        return Ok(());
    }
    let count = fs::read_dir(directory)?.take(MAX_FILES).count();
    anyhow::ensure!(
        count < MAX_FILES,
        "Editor checkpoint directory is full; existing drafts retained"
    );
    Ok(())
}

fn read_directory(directory: &Path) -> Result<Vec<EditorCheckpointFile>> {
    let mut files = Vec::new();
    let mut remaining = MAX_READ_BYTES;
    for (index, entry) in fs::read_dir(directory)?.enumerate() {
        anyhow::ensure!(
            index < MAX_FILES,
            "Editor checkpoint directory exceeds its recovery limit"
        );
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let file = read_file(directory, &path, remaining.min(MAX_EDITOR_CHECKPOINT_BYTES))?;
        remaining = remaining
            .checked_sub(file.bytes.len())
            .context("Editor checkpoint recovery byte limit reached")?;
        files.push(file);
    }
    Ok(files)
}

fn read_file(directory: &Path, path: &Path, limit: usize) -> Result<EditorCheckpointFile> {
    let record_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("Editor checkpoint record id is missing")?
        .to_owned();
    super::store::validate_session_id(&record_id)?;
    let bytes = crate::bounded_file::read_regular_bytes_within(directory, path, limit)?;
    Ok(EditorCheckpointFile {
        record_id,
        sha256: digest(&bytes),
        bytes,
    })
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests;
