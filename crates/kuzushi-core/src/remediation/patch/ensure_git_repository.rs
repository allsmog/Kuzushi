use super::*;

pub(crate) const PATCH_WORKTREES_DIR: &str = "worktrees";

pub(crate) fn patch_worktrees_root(repo_root: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(repo_root).join(PATCH_WORKTREES_DIR)
}

pub(crate) fn ensure_git_repository(repo_root: &Path) -> Result<()> {
    let output = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(repo_root)
        .output()
        .with_context(|| "patch:finding could not start git; install Git and retry")?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "true" {
        anyhow::bail!(
            "patch:finding requires a git repository target; initialize git or pass --target <repo>"
        );
    }
    Ok(())
}

pub(crate) fn create_disposable_worktree(repo_root: &Path) -> Result<PathBuf> {
    let worktree_base = patch_worktrees_root(repo_root);
    fs::create_dir_all(&worktree_base)
        .with_context(|| format!("Could not create {}", worktree_base.display()))?;
    let worktree_path = worktree_base.join(Uuid::new_v4().to_string());
    let output = Command::new("git")
        .args([
            "worktree",
            "add",
            "--detach",
            &worktree_path.display().to_string(),
            "HEAD",
        ])
        .current_dir(repo_root)
        .output()
        .with_context(|| "patch:finding could not create disposable git worktree")?;
    if !output.status.success() {
        anyhow::bail!(
            "patch:finding could not create disposable git worktree: {}",
            command_output_text(&output)
        );
    }
    Ok(worktree_path)
}

pub(crate) fn cleanup_worktree(repo_root: &Path, worktree_path: &Path) {
    let _ = Command::new("git")
        .args([
            "worktree",
            "remove",
            "--force",
            &worktree_path.display().to_string(),
        ])
        .current_dir(repo_root)
        .output();
}

pub(crate) fn run_git_with_input(cwd: &Path, args: &[&str], input: &str) -> Result<String> {
    let mut child = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| "patch:finding could not start git; install Git and retry")?;
    child
        .stdin
        .as_mut()
        .context("patch:finding could not open git stdin")?
        .write_all(input.as_bytes())?;
    let output = child
        .wait_with_output()
        .context("patch:finding could not read git output")?;
    if !output.status.success() {
        anyhow::bail!("{}", command_output_text(&output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(crate) fn run_shell_command(cwd: &Path, command: &str) -> Result<String> {
    let output = Command::new("sh")
        .args(["-lc", command])
        .current_dir(cwd)
        .output()
        .with_context(|| format!("patch:finding could not start validation command {command:?}"))?;
    if !output.status.success() {
        anyhow::bail!("{}", command_output_text(&output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(crate) fn command_output_text(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    [stderr, stdout]
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_worktrees_root_uses_workspace_state_root() {
        let root = Path::new("/repo");
        assert_eq!(
            patch_worktrees_root(root),
            crate::workspace::workspace_state_root(root).join(PATCH_WORKTREES_DIR)
        );
    }
}
