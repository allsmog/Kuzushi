use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpgHandle {
    pub cpg_id: String,
    pub repo_path: PathBuf,
    pub cpg_file: PathBuf,
    pub languages: Vec<String>,
}

pub async fn parse_repo(repo: &Path) -> Result<CpgHandle> {
    let job = JoernParseJob::new(repo)?;
    materialize_joern_cpg(&job).await?;
    Ok(job.handle())
}

pub(crate) async fn materialize_joern_cpg(job: &JoernParseJob) -> Result<()> {
    tokio::fs::create_dir_all(&job.dest).await?;
    run_joern_parse(&job.canonical, &job.output_file).await?;
    Ok(())
}

pub(crate) struct JoernParseJob {
    pub(crate) canonical: PathBuf,
    pub(crate) commit: String,
    pub(crate) repo_hash: String,
    pub(crate) dest: PathBuf,
    pub(crate) output_file: PathBuf,
}

impl JoernParseJob {
    pub(crate) fn new(repo: &Path) -> Result<Self> {
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

    pub(crate) fn handle(self) -> CpgHandle {
        CpgHandle {
            cpg_id: format!("{}:{}", self.repo_hash, self.commit),
            repo_path: self.canonical,
            cpg_file: self.output_file,
            languages: vec![],
        }
    }
}

pub(crate) fn joern_cpg_destination(repo: &Path, commit: &str) -> Result<(String, PathBuf)> {
    let fingerprint = kuzushi_mcp_common::cache::repo_hash(repo)?;
    let dest = kuzushi_mcp_common::cache::index_root()?
        .join("joern")
        .join(&fingerprint.hash)
        .join(commit);
    Ok((fingerprint.hash, dest))
}

pub(crate) async fn run_joern_parse(repo: &Path, output_file: &Path) -> Result<()> {
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

pub(crate) fn read_head_commit(repo: &Path) -> Option<String> {
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

pub async fn run_query(scala: &str) -> Result<String> {
    let url = joern_server_url();
    let client = joern_http_client()?;
    let response = send_joern_query(&client, &url, scala).await?;
    read_joern_response(response).await
}
