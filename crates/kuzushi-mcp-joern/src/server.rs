//! Lifecycle helpers for `joern --server`.
//!
//! Two responsibilities:
//! 1. `parse(repo)` — shell out to `joern-parse` to materialise a CPG
//!    under the kuzushi cache.
//! 2. `query(cpg_id, scala)` — POST a Scala query to `joern --server`'s
//!    REST endpoint and return the parsed JSON result.
//!
//! Joern's server REST API is documented at
//! <https://docs.joern.io/server/>. We use the `/query-sync` endpoint
//! which blocks until the query completes (no need to poll).
//!
//! Network use here is local-loopback only; we assume the operator started
//! `joern --server` on `127.0.0.1:8080` (the default) or supplied a
//! `JOERN_SERVER_URL` env override.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpgHandle {
    pub cpg_id: String,
    pub repo_path: PathBuf,
    pub cpg_file: PathBuf,
    pub languages: Vec<String>,
}

/// Run `joern-parse <repo>` and persist the resulting `cpg.bin.zip` under
/// `~/.kuzushi/index/joern/<repo-hash>/<commit>/`.
pub async fn parse_repo(repo: &Path) -> Result<CpgHandle> {
    let canonical = std::fs::canonicalize(repo)
        .with_context(|| format!("repo path not found: {}", repo.display()))?;
    let fingerprint = kuzushi_mcp_common::cache::repo_hash(&canonical)?;
    let commit = read_head_commit(&canonical).unwrap_or_else(|| "noref".to_string());
    let dest = kuzushi_mcp_common::cache::index_root()?
        .join("joern")
        .join(&fingerprint.hash)
        .join(&commit);
    tokio::fs::create_dir_all(&dest).await?;

    let output_file = dest.join("cpg.bin.zip");
    let output = Command::new("joern-parse")
        .arg(canonical.as_os_str())
        .arg("--output")
        .arg(&output_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("could not spawn `joern-parse`")?;
    if !output.status.success() {
        anyhow::bail!(
            "joern-parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(CpgHandle {
        cpg_id: format!("{}:{}", fingerprint.hash, commit),
        repo_path: canonical,
        cpg_file: output_file,
        languages: vec![],
    })
}

fn read_head_commit(repo: &Path) -> Option<String> {
    let head = repo.join(".git").join("HEAD");
    let raw = std::fs::read_to_string(&head).ok()?;
    let trimmed = raw.trim();
    if let Some(reference) = trimmed.strip_prefix("ref: ") {
        let ref_path = repo.join(".git").join(reference);
        std::fs::read_to_string(&ref_path)
            .ok()
            .map(|s| s.trim().chars().take(12).collect())
    } else {
        Some(trimmed.chars().take(12).collect())
    }
}

/// Run a Scala query against a running `joern --server` instance. Returns
/// the parsed `stdout` payload from joern (a JSON string of the CPG result).
pub async fn run_query(scala: &str) -> Result<String> {
    let url =
        std::env::var("JOERN_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    // We don't take a `reqwest` dependency for this skeleton — instead we
    // shell out to `curl` (universal) when available, which is fine for
    // local-loopback POSTs. A future iteration can swap in a typed HTTP
    // client if we want streaming or structured errors.
    if kuzushi_mcp_common::doctor::which("curl").is_none() {
        anyhow::bail!(
            "BackendUnavailable: curl not on PATH; the joern MCP server uses curl as a transport in this preview"
        );
    }

    let body = serde_json::json!({ "query": scala }).to_string();
    let output = Command::new("curl")
        .arg("-fsS")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(&body)
        .arg(format!("{url}/query-sync"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("could not spawn curl for joern query")?;
    if !output.status.success() {
        anyhow::bail!(
            "joern --server query failed (is it running on {}?): {}",
            url,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_head_commit_returns_none_for_non_repo() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_head_commit(tmp.path()).is_none());
    }

    #[test]
    fn read_head_commit_handles_detached_head() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("HEAD"), "deadbeef1234abcd5678\n").unwrap();
        let commit = read_head_commit(tmp.path()).unwrap();
        assert_eq!(commit, "deadbeef1234");
    }

    #[test]
    fn read_head_commit_handles_symbolic_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            git_dir.join("refs/heads/main"),
            "1234567890abcdef1234567890\n",
        )
        .unwrap();
        let commit = read_head_commit(tmp.path()).unwrap();
        assert_eq!(commit, "1234567890ab");
    }
}
