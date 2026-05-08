use super::prelude::*;
use super::*;

pub(crate) struct CompletionTool;

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

pub(crate) fn ensure_repo_path(args: &Value) -> Result<PathBuf> {
    let raw = args
        .get("repoPath")
        .and_then(Value::as_str)
        .or_else(|| args.get("repo_path").and_then(Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("missing required argument: repoPath"))?;
    Ok(PathBuf::from(raw))
}

pub(crate) fn optional_repo_path(args: &Value) -> Option<PathBuf> {
    args.get("repoPath")
        .and_then(Value::as_str)
        .or_else(|| args.get("repo_path").and_then(Value::as_str))
        .map(PathBuf::from)
}

pub(crate) fn require_string<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}

pub(crate) fn ensure_binary_available() -> Result<()> {
    if kuzushi_mcp_common::doctor::which("global").is_none()
        || kuzushi_mcp_common::doctor::which("gtags").is_none()
    {
        anyhow::bail!(
            "BackendUnavailable: gtags/global not on PATH. Install GNU GLOBAL (e.g. `apt install global` / `brew install global`)."
        );
    }
    Ok(())
}

pub(crate) async fn run_global_x(repo: &Path, args: &[&str]) -> Result<Vec<Symbol>> {
    let output = Command::new("global")
        .args(args)
        .current_dir(repo)
        .output()
        .await
        .with_context(|| format!("failed to spawn `global {}`", args.join(" ")))?;
    let stdout = global_stdout_or_empty(output)?;
    let records = parse_global_x(&stdout);
    Ok(records_to_symbols(records, repo))
}

pub(crate) fn global_stdout_or_empty(output: Output) -> Result<String> {
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if global_status_means_no_matches(&output, &stderr) {
        return Ok(String::new());
    }
    anyhow::bail!("global exited with {}: {}", output.status, stderr.trim());
}

pub(crate) fn global_status_means_no_matches(output: &Output, stderr: &str) -> bool {
    stderr.contains("not found") || stderr.contains("no such") || output.status.code() == Some(3)
}

pub(crate) async fn run_gtags(repo: &Path) -> Result<()> {
    let output = Command::new("gtags")
        .arg("--quiet")
        .current_dir(repo)
        .output()
        .await
        .context("failed to spawn `gtags`")?;
    if !output.status.success() {
        anyhow::bail!(
            "gtags exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub(crate) async fn run_global_lines(
    repo: &Path,
    args: &[&str],
    spawn_context: &str,
) -> Result<Vec<String>> {
    let output = Command::new("global")
        .args(args)
        .current_dir(repo)
        .output()
        .await
        .context(spawn_context.to_string())?;
    let stdout = global_stdout_or_empty(output)?;
    Ok(stdout
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

#[async_trait]
impl ToolHandler for IndexTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let repo = ensure_repo_path(&args)?;
        ensure_binary_available()?;
        let repo = std::fs::canonicalize(&repo)
            .with_context(|| format!("repo path not found: {}", repo.display()))?;
        run_gtags(&repo).await?;
        Ok(json!({
            "repoPath": repo,
            "indexed": true,
        }))
    }
}
