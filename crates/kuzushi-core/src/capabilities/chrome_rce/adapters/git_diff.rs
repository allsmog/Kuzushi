use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

pub(crate) fn changed_files(target: &Path, diff_base: &str) -> Result<Vec<String>> {
    crate::git_rev::ensure_safe_git_rev(diff_base, "chrome-rce:review-trigger diffBase")?;
    verify_diff_base(target, diff_base)?;
    let output = run_git_diff(target, diff_base)?;
    Ok(changed_file_lines(&output.stdout))
}

fn verify_diff_base(target: &Path, diff_base: &str) -> Result<()> {
    let mut command = Command::new("git");
    command
        .args(["rev-parse", "--verify", diff_base])
        .current_dir(target);
    let output = crate::bounded_subprocess::output(&mut command, "git rev-parse")
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
    let mut command = Command::new("git");
    command
        .args(["diff", "--name-only", &format!("{diff_base}...HEAD")])
        .current_dir(target);
    let output = crate::bounded_subprocess::output(&mut command, "git diff")
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
