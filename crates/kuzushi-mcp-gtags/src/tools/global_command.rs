use crate::parser::{parse_global_x, records_to_symbols};
use anyhow::{Context, Result};
use kuzushi_mcp_common::schema::Symbol;
use std::path::Path;
use std::process::Output;
use tokio::process::Command;

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
