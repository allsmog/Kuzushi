use crate::run_artifacts::RunTargetGitMetadata;
use std::path::Path;
use std::process::Command;

pub fn target_git_metadata(target: &Path) -> Option<RunTargetGitMetadata> {
    let sha = git_stdout(target, &["rev-parse", "HEAD"])?;
    Some(RunTargetGitMetadata {
        sha,
        branch: git_branch(target),
        dirty: git_dirty(target),
    })
}

fn git_branch(target: &Path) -> Option<String> {
    git_stdout(target, &["branch", "--show-current"]).filter(|branch| !branch.trim().is_empty())
}

fn git_dirty(target: &Path) -> bool {
    git_stdout(target, &["status", "--porcelain"])
        .map(|status| !status.trim().is_empty())
        .unwrap_or(false)
}

fn git_stdout(target: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(target)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}
