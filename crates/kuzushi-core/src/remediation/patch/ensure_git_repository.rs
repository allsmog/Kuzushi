use super::*;

pub(crate) const PATCH_WORKTREES_DIR: &str = "worktrees";

pub(crate) fn unattended_patch_control() -> PatchCommandControl<'static> {
    PatchCommandControl::unattended(std::time::Duration::from_millis(
        DEFAULT_PATCH_VALIDATION_TIMEOUT_MS,
    ))
}

pub(crate) fn patch_worktrees_root(repo_root: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(repo_root).join(PATCH_WORKTREES_DIR)
}

pub(crate) fn ensure_git_repository(
    repo_root: &Path,
    control: PatchCommandControl<'_>,
) -> Result<()> {
    control.ensure_active()?;
    let output = control
        .run_git(
            repo_root,
            &["rev-parse", "--is-inside-work-tree"],
            "git rev-parse",
        )
        .map_err(|error| {
            patch_command_error(
                "patch:finding could not start git; install Git and retry",
                error,
            )
        })?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "true" {
        anyhow::bail!(
            "patch:finding requires a git repository target; initialize git or pass --target <repo>"
        );
    }
    Ok(())
}

pub(crate) fn create_disposable_worktree(
    repo_root: &Path,
    control: PatchCommandControl<'_>,
) -> Result<PathBuf> {
    control.ensure_active()?;
    let declared_worktree_base = patch_worktrees_root(repo_root);
    let relative_base = declared_worktree_base
        .strip_prefix(repo_root)
        .context("Patch worktree root escaped the workspace")?;
    let worktree_base = ensure_patch_worktree_base(repo_root, &declared_worktree_base)?;
    let relative = relative_base.join(Uuid::new_v4().to_string());
    let worktree_path = crate::workspace::prepare_workspace_output_path(repo_root, &relative)?;
    if let Err(error) = create_git_worktree(repo_root, &worktree_path, control) {
        return Err(cleanup_worktree_after_error(
            repo_root,
            &worktree_path,
            control,
            error,
        ));
    }
    validate_created_worktree(
        repo_root,
        &worktree_base,
        &worktree_path,
        &relative,
        control,
    )
}

fn ensure_patch_worktree_base(repo_root: &Path, worktree_base: &Path) -> Result<PathBuf> {
    let relative = worktree_base
        .strip_prefix(repo_root)
        .context("Patch worktree root escaped the workspace")?;
    crate::workspace::ensure_workspace_output_dir(repo_root, relative)
}

fn create_git_worktree(
    repo_root: &Path,
    worktree_path: &Path,
    control: PatchCommandControl<'_>,
) -> Result<()> {
    let worktree_path = worktree_path.display().to_string();
    let output = control
        .run_git(
            repo_root,
            &["worktree", "add", "--detach", &worktree_path, "HEAD"],
            "git worktree add",
        )
        .map_err(|error| {
            patch_command_error(
                "patch:finding could not create disposable git worktree",
                error,
            )
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "patch:finding could not create disposable git worktree: {}",
            command_output_text(&output)
        );
    }
    Ok(())
}

fn validate_created_worktree(
    repo_root: &Path,
    worktree_base: &Path,
    worktree_path: &Path,
    relative: &Path,
    control: PatchCommandControl<'_>,
) -> Result<PathBuf> {
    let validated = match crate::workspace::ensure_workspace_output_dir(repo_root, relative) {
        Ok(path) => path,
        Err(error) => {
            let error = error
                .context("patch:finding created an unsafe or missing disposable worktree output");
            return Err(cleanup_worktree_after_error(
                repo_root,
                worktree_path,
                control,
                error,
            ));
        }
    };
    if validated != worktree_path || !validated.starts_with(worktree_base) {
        let error = anyhow::anyhow!(
            "patch:finding created a worktree outside the authorized workspace state directory"
        );
        return Err(cleanup_worktree_after_error(
            repo_root,
            worktree_path,
            control,
            error,
        ));
    }
    Ok(validated)
}

fn cleanup_worktree_after_error(
    repo_root: &Path,
    worktree_path: &Path,
    control: PatchCommandControl<'_>,
    error: anyhow::Error,
) -> anyhow::Error {
    match cleanup_worktree(repo_root, worktree_path, control) {
        Ok(()) => error,
        Err(cleanup) => cleanup.context(error),
    }
}

pub(crate) fn cleanup_worktree(
    repo_root: &Path,
    worktree_path: &Path,
    control: PatchCommandControl<'_>,
) -> Result<()> {
    let worktree_path = worktree_path.display().to_string();
    let output = control.cleanup().run_git(
        repo_root,
        &["worktree", "remove", "--force", &worktree_path],
        "git worktree remove",
    )?;
    anyhow::ensure!(
        output.status.success(),
        "patch:finding could not remove disposable git worktree: {}",
        command_output_text(&output)
    );
    Ok(())
}

pub(crate) fn run_git_with_input(
    cwd: &Path,
    args: &[&str],
    input: &str,
    control: PatchCommandControl<'_>,
) -> Result<String> {
    control.ensure_active()?;
    anyhow::ensure!(
        input.len() <= 16 * 1024 * 1024,
        "patch:finding diff exceeds the 16 MiB validation limit"
    );
    let output = control
        .run_git_with_input(cwd, args, input.as_bytes(), "git patch validation")
        .map_err(|error| {
            patch_command_error(
                "patch:finding could not run git; install Git and retry",
                error,
            )
        })?;
    if !output.status.success() {
        anyhow::bail!("{}", command_output_text(&output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(crate) fn run_shell_command(
    cwd: &Path,
    command: &str,
    control: PatchCommandControl<'_>,
) -> Result<String> {
    control.ensure_active()?;
    let output = control
        .run_shell(cwd, command, "patch validation command")
        .map_err(|error| {
            patch_command_error(
                &format!("patch:finding could not start validation command {command:?}"),
                error,
            )
        })?;
    if !output.status.success() {
        anyhow::bail!("{}", command_output_text(&output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn patch_command_error(message: &str, error: anyhow::Error) -> anyhow::Error {
    anyhow::anyhow!("{message}: {error:#}")
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
    use std::process::Command;
    use std::time::Duration;

    fn git_is_unavailable() -> bool {
        Command::new("git").arg("--version").output().is_err()
    }

    fn initialize_repo(repo: &Path) {
        run_git(repo, &["init"]);
        std::fs::write(repo.join("demo.txt"), "before\n").unwrap();
        run_git(repo, &["add", "demo.txt"]);
        run_git(repo, &["commit", "-m", "initial"]);
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.email=kuzushi@example.invalid"])
            .args(["-c", "user.name=Kuzushi Test"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .current_dir(repo)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    #[test]
    fn patch_worktrees_root_uses_workspace_state_root() {
        let root = Path::new("/repo");
        assert_eq!(
            patch_worktrees_root(root),
            crate::workspace::workspace_state_root(root).join(PATCH_WORKTREES_DIR)
        );
    }

    #[cfg(unix)]
    #[test]
    fn worktree_creation_rejects_symlinked_state_root_before_git_runs() {
        use std::os::unix::fs::symlink;

        let repo = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), repo.path().join(".kuzushi")).unwrap();

        assert!(create_disposable_worktree(repo.path(), unattended_patch_control()).is_err());
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn validation_command_deadline_kills_sleeping_process_tree() {
        let temp = tempfile::tempdir().unwrap();
        let control = PatchCommandControl::new(None, Duration::from_millis(40));

        let error = run_shell_command(temp.path(), "sleep 60", control)
            .unwrap_err()
            .to_string();

        assert!(error.contains("deadline"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn validation_command_observes_cancellation() {
        let temp = tempfile::tempdir().unwrap();
        let cancellation = crate::scan::ScanCancellation::default();
        let cancel_from_thread = cancellation.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            cancel_from_thread.cancel();
        });
        let control = PatchCommandControl::new(Some(&cancellation), Duration::from_secs(30));

        let error = run_shell_command(temp.path(), "sleep 60", control)
            .unwrap_err()
            .to_string();
        canceller.join().unwrap();

        assert!(error.contains("cancelled"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn failed_worktree_creation_cleanup_removes_path_and_registration() {
        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        let control = unattended_patch_control();
        let worktree = create_disposable_worktree(repo.path(), control).unwrap();

        let error = cleanup_worktree_after_error(
            repo.path(),
            &worktree,
            control,
            anyhow::anyhow!("git worktree add exceeded deadline"),
        );

        assert!(error.to_string().contains("deadline"), "{error:#}");
        assert!(!worktree.exists());
        assert_eq!(
            std::fs::read_dir(patch_worktrees_root(repo.path()))
                .unwrap()
                .count(),
            0
        );
        let listing = Command::new("git")
            .args(["worktree", "list", "--porcelain"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(listing.status.success());
        assert!(!String::from_utf8_lossy(&listing.stdout).contains(".kuzushi/worktrees"));
    }
}
