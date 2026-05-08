use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::sha256::sha256_bytes;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepoFingerprint {
    pub canonical_path: PathBuf,
    pub git_remote: Option<String>,
    pub hash: String,
}

pub fn repo_hash(path: &Path) -> Result<RepoFingerprint> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("could not canonicalize {}", path.display()))?;
    let git_remote = read_git_remote(&canonical);
    let hash = sha256_hex(&repo_hash_input(&canonical, git_remote.as_deref()));

    Ok(RepoFingerprint {
        canonical_path: canonical,
        git_remote,
        hash,
    })
}

fn repo_hash_input(canonical: &Path, git_remote: Option<&str>) -> String {
    let mut input = canonical.display().to_string();
    if let Some(remote) = git_remote {
        input.push('|');
        input.push_str(remote);
    }
    input
}

pub(crate) fn read_git_remote(repo: &Path) -> Option<String> {
    let head_config = repo.join(".git").join("config");
    if !head_config.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&head_config).ok()?;
    origin_remote_url(&raw)
}

fn origin_remote_url(raw: &str) -> Option<String> {
    let mut in_origin = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_origin = trimmed == "[remote \"origin\"]";
            continue;
        }
        if in_origin {
            if let Some(value) = remote_url_value(trimmed) {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn remote_url_value(trimmed: &str) -> Option<&str> {
    let value = trimmed
        .strip_prefix("url")?
        .trim_start_matches([' ', '='])
        .trim();
    (!value.is_empty()).then_some(value)
}

pub(crate) fn sha256_hex(input: &str) -> String {
    let bytes = sha256_bytes(input.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}
