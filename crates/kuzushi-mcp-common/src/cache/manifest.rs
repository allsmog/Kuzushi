use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::fingerprint::RepoFingerprint;
use super::io::{read_bounded_file, write_atomic_file};
use super::paths::manifest_path;

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheManifest {
    pub repos: Vec<RepoEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoEntry {
    pub fingerprint: RepoFingerprint,
    /// Per-backend last-indexed timestamp (RFC 3339).
    pub backends: Vec<BackendEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendEntry {
    pub backend: String,
    pub last_indexed: String,
    pub commit: Option<String>,
    pub size_bytes: u64,
}

impl CacheManifest {
    pub fn load() -> Result<Self> {
        let path = manifest_path()?;
        load_manifest_path(&path)
    }

    pub fn save(&self) -> Result<()> {
        let path = manifest_path()?;
        self.save_to_path(&path)
    }

    pub(crate) fn save_to_path(&self, path: &Path) -> Result<()> {
        let raw = serde_json::to_string_pretty(self).context("could not encode manifest")?;
        write_manifest_path(path, raw)
    }
}

pub(crate) fn load_manifest_path(path: &Path) -> Result<CacheManifest> {
    if !path.exists() {
        return Ok(CacheManifest::default());
    }
    read_manifest_path(path)
}

pub(crate) fn read_manifest_path(path: &Path) -> Result<CacheManifest> {
    let raw = read_bounded_file(path, MAX_MANIFEST_BYTES)?
        .with_context(|| format!("manifest disappeared at {}", path.display()))?;
    serde_json::from_slice(&raw)
        .with_context(|| format!("cache manifest is malformed at {}", path.display()))
}

pub(crate) fn write_manifest_path(path: &Path, raw: String) -> Result<()> {
    write_atomic_file(path, raw.as_bytes(), MAX_MANIFEST_BYTES)
        .with_context(|| format!("could not write manifest to {}", path.display()))
}
