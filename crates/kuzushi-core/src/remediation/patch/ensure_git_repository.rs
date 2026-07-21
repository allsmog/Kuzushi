use super::*;

mod materialize_bound_tree;

use materialize_bound_tree::materialize_bound_commit;

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

pub(crate) fn bind_patch_source_snapshot(repo_root: &Path, input: &mut Value) -> Result<()> {
    let expected = input
        .get(PATCH_SOURCE_COMMIT_INPUT_KEY)
        .map(|_| patch_source_commit(input))
        .transpose()?;
    crate::workspace::initialize_workspace_state(repo_root)?;
    let actual = clean_patch_source_commit(repo_root, unattended_patch_control())?;
    ensure_expected_source_commit(expected.as_deref(), &actual)?;
    input
        .as_object_mut()
        .context("patch:finding input must be an object")?
        .insert(
            PATCH_SOURCE_COMMIT_INPUT_KEY.to_string(),
            Value::String(actual),
        );
    Ok(())
}

pub(crate) fn verify_patch_source_snapshot(
    repo_root: &Path,
    expected: &str,
    control: PatchCommandControl<'_>,
) -> Result<()> {
    let actual = clean_patch_source_commit(repo_root, control)?;
    ensure_expected_source_commit(Some(expected), &actual)
}

fn ensure_expected_source_commit(expected: Option<&str>, actual: &str) -> Result<()> {
    if expected.is_some_and(|expected| expected != actual) {
        anyhow::bail!(
            "patch:finding source commit changed after preparation; prepare and authorize the operation again"
        );
    }
    Ok(())
}

fn clean_patch_source_commit(repo_root: &Path, control: PatchCommandControl<'_>) -> Result<String> {
    ensure_git_repository(repo_root, control)?;
    let before = resolve_head_commit(repo_root, control)?;
    ensure_clean_patch_source(repo_root, control)?;
    let after = resolve_head_commit(repo_root, control)?;
    anyhow::ensure!(
        before == after,
        "patch:finding source commit changed while binding the operation; retry preparation"
    );
    Ok(after)
}

pub(crate) fn resolve_head_commit(
    repo_root: &Path,
    control: PatchCommandControl<'_>,
) -> Result<String> {
    let output = control
        .run_git(
            repo_root,
            &["rev-parse", "--verify", "HEAD^{commit}"],
            "git resolve patch source commit",
        )
        .map_err(|error| {
            patch_command_error(
                "patch:finding could not resolve the repository source commit",
                error,
            )
        })?;
    anyhow::ensure!(
        output.status.success(),
        "patch:finding requires a repository with at least one commit: {}",
        command_output_text(&output)
    );
    let commit = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    anyhow::ensure!(
        matches!(commit.len(), 40 | 64) && commit.chars().all(|ch| ch.is_ascii_hexdigit()),
        "patch:finding could not resolve a full Git source commit"
    );
    Ok(commit)
}

fn ensure_clean_patch_source(repo_root: &Path, control: PatchCommandControl<'_>) -> Result<()> {
    let output = control
        .run_git(
            repo_root,
            &[
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored=no",
                "--ignore-submodules=none",
            ],
            "git inspect patch source status",
        )
        .map_err(|error| {
            patch_command_error(
                "patch:finding could not inspect repository source status",
                error,
            )
        })?;
    anyhow::ensure!(
        output.status.success(),
        "patch:finding could not inspect repository source status: {}",
        command_output_text(&output)
    );
    anyhow::ensure!(
        output.stdout.is_empty(),
        "patch:finding requires a clean Git source snapshot; commit or stash tracked/staged changes and remove untracked source files, then retry"
    );
    Ok(())
}

pub(crate) fn create_disposable_worktree(
    repo_root: &Path,
    source_commit: &str,
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
    let mut cleanup_guard = WorktreeCleanupGuard::new(repo_root, worktree_path.clone());
    if let Err(error) = create_git_worktree(repo_root, &worktree_path, source_commit, control) {
        return Err(cleanup_worktree_after_error(
            repo_root,
            &worktree_path,
            control,
            error,
        ));
    }
    let validated = validate_created_worktree(
        repo_root,
        &worktree_base,
        &worktree_path,
        &relative,
        control,
    )?;
    cleanup_guard.disarm();
    Ok(validated)
}

fn ensure_patch_worktree_base(repo_root: &Path, worktree_base: &Path) -> Result<PathBuf> {
    crate::workspace::initialize_workspace_state(repo_root)?;
    let relative = worktree_base
        .strip_prefix(repo_root)
        .context("Patch worktree root escaped the workspace")?;
    crate::workspace::ensure_workspace_output_dir(repo_root, relative)
}

fn create_git_worktree(
    repo_root: &Path,
    worktree_path: &Path,
    source_commit: &str,
    control: PatchCommandControl<'_>,
) -> Result<()> {
    materialize_bound_commit(repo_root, worktree_path, source_commit, control)
}

pub(crate) fn with_disposable_worktree<T>(
    repo_root: &Path,
    source_commit: &str,
    control: PatchCommandControl<'_>,
    operation: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    let worktree = create_disposable_worktree(repo_root, source_commit, control)?;
    let mut guard = WorktreeCleanupGuard::new(repo_root, worktree);
    let operation = operation(guard.path());
    let cleanup = guard.cleanup(control);
    combine_worktree_operation(operation, cleanup)
}

fn combine_worktree_operation<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup)) => Err(cleanup.context(error)),
    }
}

struct WorktreeCleanupGuard {
    repo_root: PathBuf,
    worktree: PathBuf,
    armed: bool,
}

impl WorktreeCleanupGuard {
    fn new(repo_root: &Path, worktree: PathBuf) -> Self {
        Self {
            repo_root: repo_root.to_path_buf(),
            worktree,
            armed: true,
        }
    }

    fn path(&self) -> &Path {
        &self.worktree
    }

    fn cleanup(&mut self, control: PatchCommandControl<'_>) -> Result<()> {
        let result = cleanup_worktree(&self.repo_root, &self.worktree, control);
        if result.is_ok() {
            self.armed = false;
        }
        result
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WorktreeCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = cleanup_worktree(&self.repo_root, &self.worktree, unattended_patch_control());
        }
    }
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
    _control: PatchCommandControl<'_>,
) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(worktree_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let base = std::fs::canonicalize(patch_worktrees_root(repo_root))?;
    let parent = std::fs::canonicalize(
        worktree_path
            .parent()
            .context("patch worktree path has no parent")?,
    )?;
    anyhow::ensure!(
        parent == base,
        "refusing to remove checkout outside patch state"
    );
    if metadata.file_type().is_symlink() {
        std::fs::remove_file(worktree_path)?;
    } else {
        std::fs::remove_dir_all(worktree_path)?;
    }
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
    let combined = [stderr, stdout]
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    redact_validation_output(&combined)
}

fn redact_validation_output(output: &str) -> String {
    use std::sync::OnceLock;
    static ASSIGNMENT: OnceLock<regex::Regex> = OnceLock::new();
    static TOKEN: OnceLock<regex::Regex> = OnceLock::new();
    let assignment = ASSIGNMENT.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)(api[_-]?key|access[_-]?token|token|secret|password|authorization|credential)[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]+"#,
        )
        .expect("validator assignment redaction regex must compile")
    });
    let token = TOKEN.get_or_init(|| {
        regex::Regex::new(
            r"(?i)\b(?:gh[pousr]_[a-z0-9_]{16,}|sk-[a-z0-9_-]{16,}|AKIA[0-9A-Z]{16})\b",
        )
        .expect("validator token redaction regex must compile")
    });
    let redacted = assignment.replace_all(output, "$1=<redacted>");
    let redacted = token.replace_all(&redacted, "<redacted>");
    redacted.chars().take(16 * 1024).collect()
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

    fn run_git_stdout(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-c", "user.email=kuzushi@example.invalid"])
            .args(["-c", "user.name=Kuzushi Test"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .current_dir(repo)
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?} failed");
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn directory_bytes(path: &Path) -> u64 {
        std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .map(|path| {
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    directory_bytes(&path)
                } else {
                    metadata.len()
                }
            })
            .sum()
    }

    fn head_commit(repo: &Path) -> String {
        resolve_head_commit(repo, unattended_patch_control()).unwrap()
    }

    #[cfg(unix)]
    fn configure_malicious_source_commands(repo: &Path, marker: &Path, filter: &Path) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::write(
            filter,
            format!("#!/bin/sh\nPATH=/usr/bin:/bin\ntouch '{}'\ncat\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(filter, std::fs::Permissions::from_mode(0o755)).unwrap();
        let filter_path = filter.display().to_string();
        run_git(repo, &["config", "filter.evil.smudge", &filter_path]);
        run_git(repo, &["config", "filter.evil.required", "true"]);
        run_git(repo, &["config", "core.fsmonitor", &filter_path]);
    }

    fn install_blob_replacement(repo: &Path, replacement: &Path) {
        let original_blob = run_git_stdout(repo, &["rev-parse", "HEAD:demo.txt"]);
        std::fs::write(replacement, "replaced\n").unwrap();
        let replacement_path = replacement.display().to_string();
        let replacement_blob = run_git_stdout(repo, &["hash-object", "-w", &replacement_path]);
        run_git(repo, &["replace", &original_blob, &replacement_blob]);
    }

    fn bind_source(repo: &Path) -> Result<Value> {
        let mut input = json!({"fingerprint": "finding-1"});
        bind_patch_source_snapshot(repo, &mut input)?;
        Ok(input)
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
    fn cleanup_removes_dangling_symlink_checkout() {
        use std::os::unix::fs::symlink;

        let repo = tempfile::tempdir().unwrap();
        let base = patch_worktrees_root(repo.path());
        std::fs::create_dir_all(&base).unwrap();
        let checkout = base.join("dangling-checkout");
        symlink(base.join("missing-target"), &checkout).unwrap();

        cleanup_worktree(repo.path(), &checkout, unattended_patch_control()).unwrap();

        assert!(std::fs::symlink_metadata(&checkout).is_err());
    }

    #[test]
    fn validator_output_redacts_credentials_before_retry_or_persistence() {
        let output = redact_validation_output(
            "authorization: bearer-value\nAPI_KEY=top-secret\nghp_abcdefghijklmnopqrstuvwxyz",
        );

        assert!(!output.contains("bearer-value"));
        assert!(!output.contains("top-secret"));
        assert!(!output.contains("ghp_"));
        assert!(output.contains("<redacted>"));
    }

    #[cfg(unix)]
    #[test]
    fn worktree_creation_rejects_symlinked_state_root_before_git_runs() {
        use std::os::unix::fs::symlink;

        let repo = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), repo.path().join(".kuzushi")).unwrap();

        assert!(create_disposable_worktree(
            repo.path(),
            "0000000000000000000000000000000000000000",
            unattended_patch_control(),
        )
        .is_err());
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[test]
    fn source_binding_rejects_dirty_tracked_file() {
        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        std::fs::write(repo.path().join("demo.txt"), "modified\n").unwrap();

        let error = bind_source(repo.path()).unwrap_err().to_string();

        assert!(error.contains("clean Git source snapshot"), "{error}");
    }

    #[test]
    fn source_binding_rejects_staged_file() {
        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        std::fs::write(repo.path().join("demo.txt"), "staged\n").unwrap();
        run_git(repo.path(), &["add", "demo.txt"]);

        let error = bind_source(repo.path()).unwrap_err().to_string();

        assert!(error.contains("clean Git source snapshot"), "{error}");
    }

    #[test]
    fn source_binding_rejects_untracked_file() {
        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        std::fs::write(repo.path().join("untracked.rs"), "fn main() {}\n").unwrap();

        let error = bind_source(repo.path()).unwrap_err().to_string();

        assert!(error.contains("clean Git source snapshot"), "{error}");
    }

    #[test]
    fn source_binding_allows_ignored_runtime_artifacts() {
        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        crate::workspace::initialize_workspace_state(repo.path()).unwrap();
        std::fs::write(repo.path().join(".kuzushi/run.json"), "{}\n").unwrap();

        let input = bind_source(repo.path()).unwrap();

        assert_eq!(
            input[PATCH_SOURCE_COMMIT_INPUT_KEY],
            Value::String(head_commit(repo.path()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn validation_command_deadline_kills_sleeping_process_tree() {
        if !crate::remediation::patch_process_adapter::validation_network_sandbox_available() {
            return;
        }
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
        if !crate::remediation::patch_process_adapter::validation_network_sandbox_available() {
            return;
        }
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
        let source_commit = head_commit(repo.path());
        let worktree = create_disposable_worktree(repo.path(), &source_commit, control).unwrap();

        let error = cleanup_worktree_after_error(
            repo.path(),
            &worktree,
            control,
            anyhow::anyhow!("validation checkout exceeded deadline"),
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

    #[cfg(unix)]
    #[test]
    fn validation_checkout_never_runs_source_repository_hooks() {
        use std::os::unix::fs::PermissionsExt;

        if git_is_unavailable() {
            return;
        }
        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        initialize_repo(&repo);
        let marker = outer.path().join("hook-ran");
        let hook = repo.join(".git/hooks/post-checkout");
        std::fs::write(&hook, format!("#!/bin/sh\nPATH=/usr/bin:/bin\ntouch '{}'\n", marker.display())).unwrap();
        let mut permissions = std::fs::metadata(&hook).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&hook, permissions).unwrap();

        let control = unattended_patch_control();
        let source_commit = head_commit(&repo);
        let checkout = create_disposable_worktree(&repo, &source_commit, control).unwrap();

        assert!(
            !marker.exists(),
            "source repository hook must never execute"
        );
        cleanup_worktree(&repo, &checkout, control).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn materialization_ignores_replace_refs_filters_and_source_config() {
        if git_is_unavailable() {
            return;
        }
        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        initialize_repo(&repo);
        std::fs::write(repo.join(".gitattributes"), "demo.txt filter=evil\n").unwrap();
        run_git(&repo, &["add", ".gitattributes"]);
        run_git(&repo, &["commit", "-m", "attributes"]);
        let source_commit = head_commit(&repo);

        let marker = outer.path().join("filter-ran");
        let filter = outer.path().join("evil-filter.sh");
        configure_malicious_source_commands(&repo, &marker, &filter);
        let replacement = outer.path().join("replacement.txt");
        install_blob_replacement(&repo, &replacement);

        let control = unattended_patch_control();
        let checkout = create_disposable_worktree(&repo, &source_commit, control).unwrap();

        assert_eq!(
            std::fs::read_to_string(checkout.join("demo.txt")).unwrap(),
            "before\n"
        );
        assert!(!marker.exists(), "source-configured command must not run");
        let checkout_config = std::fs::read_to_string(checkout.join(".git/config")).unwrap();
        assert!(!checkout_config.contains("filter.evil"));
        assert!(run_git_stdout(&checkout, &["replace", "-l"]).is_empty());
        cleanup_worktree(&repo, &checkout, control).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn materialization_preserves_executable_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        let tool = repo.path().join("tool.sh");
        std::fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        run_git(repo.path(), &["add", "tool.sh"]);
        run_git(repo.path(), &["commit", "-m", "executable"]);
        let source_commit = head_commit(repo.path());
        let control = unattended_patch_control();

        let checkout = create_disposable_worktree(repo.path(), &source_commit, control).unwrap();

        assert_eq!(
            std::fs::metadata(checkout.join("tool.sh")).unwrap().mode() & 0o111,
            0o111
        );
        assert!(
            run_git_stdout(&checkout, &["ls-tree", "HEAD", "tool.sh"]).starts_with("100755 blob ")
        );
        cleanup_worktree(repo.path(), &checkout, control).unwrap();
    }

    #[test]
    fn multi_attempt_materialization_does_not_copy_unreachable_history() {
        if git_is_unavailable() {
            return;
        }
        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        initialize_repo(&repo);
        let source_commit = head_commit(&repo);
        let unreachable = outer.path().join("unreachable.bin");
        let mut bytes = vec![0_u8; 6 * 1024 * 1024];
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        std::fs::write(&unreachable, bytes).unwrap();
        run_git(
            &repo,
            &["hash-object", "-w", &unreachable.display().to_string()],
        );
        let source_object_bytes = directory_bytes(&repo.join(".git/objects"));
        let control = unattended_patch_control();

        let first = create_disposable_worktree(&repo, &source_commit, control).unwrap();
        let second = create_disposable_worktree(&repo, &source_commit, control).unwrap();
        let checkout_bytes = directory_bytes(&first) + directory_bytes(&second);

        assert!(source_object_bytes > 4 * 1024 * 1024);
        assert!(checkout_bytes * 4 < source_object_bytes);
        cleanup_worktree(&repo, &first, control).unwrap();
        cleanup_worktree(&repo, &second, control).unwrap();
    }

    #[test]
    fn disposable_wrapper_cleans_after_error_and_panic() {
        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        let source_commit = head_commit(repo.path());
        let control = unattended_patch_control();

        let error = with_disposable_worktree(repo.path(), &source_commit, control, |_| {
            Err::<(), _>(anyhow::anyhow!("controlled failure"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("controlled failure"));
        assert_eq!(
            std::fs::read_dir(patch_worktrees_root(repo.path()))
                .unwrap()
                .count(),
            0
        );

        let panic = std::panic::catch_unwind(|| {
            let _ =
                with_disposable_worktree(repo.path(), &source_commit, control, |_| -> Result<()> {
                    panic!("controlled panic")
                });
        });
        assert!(panic.is_err());
        assert_eq!(
            std::fs::read_dir(patch_worktrees_root(repo.path()))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn materialization_cancellation_and_deadline_leave_no_partial_checkout() {
        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        let source_commit = head_commit(repo.path());
        let cancellation = crate::scan::ScanCancellation::default();
        cancellation.cancel();
        let cancelled = PatchCommandControl::new(Some(&cancellation), Duration::from_secs(5));

        assert!(create_disposable_worktree(repo.path(), &source_commit, cancelled).is_err());
        let expired = PatchCommandControl::new(None, Duration::from_nanos(1));
        assert!(create_disposable_worktree(repo.path(), &source_commit, expired).is_err());
        assert_eq!(
            std::fs::read_dir(patch_worktrees_root(repo.path()))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn validation_checkout_materializes_the_bound_commit_not_ambient_head() {
        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        let bound_commit = head_commit(repo.path());
        std::fs::write(repo.path().join("demo.txt"), "after\n").unwrap();
        run_git(repo.path(), &["add", "demo.txt"]);
        run_git(repo.path(), &["commit", "-m", "move head"]);

        let control = unattended_patch_control();
        let checkout = create_disposable_worktree(repo.path(), &bound_commit, control).unwrap();

        assert_eq!(
            std::fs::read_to_string(checkout.join("demo.txt")).unwrap(),
            "before\n"
        );
        assert_eq!(
            resolve_head_commit(&checkout, control).unwrap(),
            bound_commit
        );
        cleanup_worktree(repo.path(), &checkout, control).unwrap();
    }

    #[test]
    fn bound_commit_can_be_materialized_in_distinct_synthesis_and_validation_checkouts() {
        if git_is_unavailable() {
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        initialize_repo(repo.path());
        let source_commit = head_commit(repo.path());
        let control = unattended_patch_control();

        let synthesis = create_disposable_worktree(repo.path(), &source_commit, control).unwrap();
        let validation = create_disposable_worktree(repo.path(), &source_commit, control).unwrap();

        assert_ne!(synthesis, validation);
        assert_eq!(
            resolve_head_commit(&synthesis, control).unwrap(),
            source_commit
        );
        assert_eq!(
            resolve_head_commit(&validation, control).unwrap(),
            source_commit
        );
        cleanup_worktree(repo.path(), &synthesis, control).unwrap();
        cleanup_worktree(repo.path(), &validation, control).unwrap();
    }
}
