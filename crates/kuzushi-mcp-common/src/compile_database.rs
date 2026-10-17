use crate::{cache::sha256_hex_bytes, ReadRootCapability};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod commands;

#[cfg(test)]
mod tests;

pub const MAX_COMPILE_DATABASE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_COMPILE_COMMANDS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileDatabaseReceipt {
    pub source_path: PathBuf,
    pub source_sha256: String,
    pub source_bytes: usize,
    pub prepared_sha256: String,
    pub prepared_bytes: usize,
    pub entries: usize,
}

/// A bounded compiler configuration retained independently of its source file.
/// Relative working directories are bound to the original database directory.
pub struct CompileDatabaseSnapshot {
    directory: tempfile::TempDir,
    path: PathBuf,
    receipt: CompileDatabaseReceipt,
}

impl CompileDatabaseSnapshot {
    pub fn capture(capability: &ReadRootCapability, source: &Path) -> Result<Self> {
        let opened = capability.open_strict(source, MAX_COMPILE_DATABASE_BYTES)?;
        let source_path = opened.path().to_path_buf();
        let mut raw = Vec::new();
        let source_sha256 = opened.copy_to_with_sha256_hex(&mut raw)?;
        let (prepared, entries) = commands::prepare(&source_path, &raw)?;
        let receipt = CompileDatabaseReceipt {
            source_path,
            source_sha256,
            source_bytes: raw.len(),
            prepared_sha256: sha256_hex_bytes(&prepared),
            prepared_bytes: prepared.len(),
            entries,
        };
        Self::retain(receipt, prepared)
    }

    fn retain(receipt: CompileDatabaseReceipt, bytes: Vec<u8>) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("kuzushi-compile-db-")
            .tempdir()?;
        let path = directory.path().join("compile_commands.json");
        std::fs::write(&path, bytes).context("could not retain compiler configuration")?;
        Ok(Self {
            directory,
            path,
            receipt,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn directory(&self) -> &Path {
        self.directory.path()
    }

    pub fn receipt(&self) -> &CompileDatabaseReceipt {
        &self.receipt
    }

    pub fn verify_unchanged(&self) -> Result<()> {
        let capability = ReadRootCapability::new([self.directory().to_path_buf()])?;
        let opened = capability.open_strict(self.path(), MAX_COMPILE_DATABASE_BYTES)?;
        let digest = opened.copy_to_with_sha256_hex(&mut std::io::sink())?;
        anyhow::ensure!(
            digest == self.receipt.prepared_sha256,
            "retained compiler configuration changed"
        );
        Ok(())
    }
}
