use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
// `Stdio` is still used by `parse_repo` below — `joern-parse` is a
// real subprocess (the JVM tool we're wrapping). Only the HTTP query
// path moved to native Rust.

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
    let job = JoernParseJob::new(repo)?;
    materialize_joern_cpg(&job).await?;
    Ok(job.handle())
}

async fn materialize_joern_cpg(job: &JoernParseJob) -> Result<()> {
    tokio::fs::create_dir_all(&job.dest).await?;
    run_joern_parse(&job.canonical, &job.output_file).await?;
    Ok(())
}

struct JoernParseJob {
    canonical: PathBuf,
    commit: String,
    repo_hash: String,
    dest: PathBuf,
    output_file: PathBuf,
}

impl JoernParseJob {
    fn new(repo: &Path) -> Result<Self> {
        let canonical = std::fs::canonicalize(repo)
            .with_context(|| format!("repo path not found: {}", repo.display()))?;
        let commit = read_head_commit(&canonical).unwrap_or_else(|| "noref".to_string());
        let (repo_hash, dest) = joern_cpg_destination(&canonical, &commit)?;
        let output_file = dest.join("cpg.bin.zip");
        Ok(Self {
            canonical,
            commit,
            repo_hash,
            dest,
            output_file,
        })
    }

    fn handle(self) -> CpgHandle {
        CpgHandle {
            cpg_id: format!("{}:{}", self.repo_hash, self.commit),
            repo_path: self.canonical,
            cpg_file: self.output_file,
            languages: vec![],
        }
    }
}

fn joern_cpg_destination(repo: &Path, commit: &str) -> Result<(String, PathBuf)> {
    let fingerprint = kuzushi_mcp_common::cache::repo_hash(repo)?;
    let dest = kuzushi_mcp_common::cache::index_root()?
        .join("joern")
        .join(&fingerprint.hash)
        .join(commit);
    Ok((fingerprint.hash, dest))
}

async fn run_joern_parse(repo: &Path, output_file: &Path) -> Result<()> {
    let output = Command::new("joern-parse")
        .arg(repo.as_os_str())
        .arg("--output")
        .arg(output_file)
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
    Ok(())
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

/// Run a Scala query against a running `joern --server` instance via a
/// native Rust HTTP client (`reqwest` over `rustls`). Returns the raw
/// stdout payload from joern (a JSON string of the CPG result).
pub async fn run_query(scala: &str) -> Result<String> {
    let url = joern_server_url();
    let client = joern_http_client()?;
    let response = send_joern_query(&client, &url, scala).await?;
    read_joern_response(response).await
}

fn joern_server_url() -> String {
    std::env::var("JOERN_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

fn joern_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("could not build joern HTTP client")
}

async fn send_joern_query(
    client: &reqwest::Client,
    url: &str,
    scala: &str,
) -> Result<reqwest::Response> {
    client
        .post(format!("{url}/query-sync"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "query": scala }))
        .send()
        .await
        .with_context(|| format!("joern --server unreachable at {url} (is it running?)"))
}

async fn read_joern_response(response: reqwest::Response) -> Result<String> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("joern --server query failed: HTTP {status}: {body}");
    }

    response
        .text()
        .await
        .context("could not read joern response body")
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
