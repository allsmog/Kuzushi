use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

pub(crate) fn changed_files(target: &Path, diff_base: &str) -> Result<Vec<String>> {
    verify_diff_base(target, diff_base)?;
    let output = run_git_diff(target, diff_base)?;
    Ok(changed_file_lines(&output.stdout))
}

fn verify_diff_base(target: &Path, diff_base: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", diff_base])
        .current_dir(target)
        .output()
        .with_context(|| "chrome-rce:review-trigger requires git; install git or omit diffBase")?;
    if !output.status.success() {
        anyhow::bail!(
            "chrome-rce:review-trigger could not resolve diffBase {:?}: {}",
            diff_base,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn run_git_diff(target: &Path, diff_base: &str) -> Result<std::process::Output> {
    let output = Command::new("git")
        .args(["diff", "--name-only", &format!("{diff_base}...HEAD")])
        .current_dir(target)
        .output()
        .with_context(|| "chrome-rce:review-trigger requires git; install git or omit diffBase")?;
    if !output.status.success() {
        anyhow::bail!(
            "chrome-rce:review-trigger git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

fn changed_file_lines(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect()
}
