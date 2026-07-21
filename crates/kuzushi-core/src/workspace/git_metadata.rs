use crate::run_artifacts::RunTargetGitMetadata;
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

/// Read-only metadata git calls (status/rev-parse/branch) must never wedge
/// the caller: `git status` alone is multiple seconds on a 400k-file repo.
const GIT_METADATA_TIMEOUT: Duration = Duration::from_secs(10);
/// Mutating calls (checkout --detach) legitimately take longer on huge trees.
const GIT_MUTATION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRevisionSwitch {
    pub previous: RunTargetGitMetadata,
    pub current: RunTargetGitMetadata,
}

pub fn target_git_metadata(target: &Path) -> Option<RunTargetGitMetadata> {
    let sha = git_stdout(target, &["rev-parse", "HEAD"])?;
    Some(RunTargetGitMetadata {
        sha,
        branch: git_branch(target),
        dirty: git_dirty_excluding_kuzushi_state(target),
    })
}

pub fn switch_target_revision(target: &Path, reference: &str) -> Result<TargetRevisionSwitch> {
    let reference = normalized_git_reference(reference)?;
    let previous = target_git_metadata(target).context("target is not a git repository")?;
    if git_dirty_excluding_kuzushi_state(target) {
        bail!("refusing revision switch with dirty worktree; commit or stash changes first");
    }
    let resolved = resolve_target_git_commit(target, reference)
        .with_context(|| format!("could not resolve git revision {reference:?}"))?;
    run_git_checked(target, &["checkout", "--detach", &resolved])
        .with_context(|| format!("could not switch target to {resolved}"))?;
    let current = target_git_metadata(target)
        .context("target revision switched but metadata is unavailable")?;
    Ok(TargetRevisionSwitch { previous, current })
}

pub fn resolve_target_git_commit(target: &Path, reference: &str) -> Option<String> {
    let reference = normalized_git_reference(reference).ok()?;
    let commit_spec = format!("{reference}^{{commit}}");
    git_stdout(
        target,
        &["rev-parse", "--verify", "--quiet", commit_spec.as_str()],
    )
}

fn normalized_git_reference(reference: &str) -> Result<&str> {
    let reference = reference.trim();
    if reference.is_empty() {
        bail!("git revision cannot be blank");
    }
    if reference.split_whitespace().count() > 1 {
        bail!("git revision cannot contain whitespace");
    }
    Ok(reference)
}

fn git_branch(target: &Path) -> Option<String> {
    git_stdout(target, &["branch", "--show-current"]).filter(|branch| !branch.trim().is_empty())
}

fn git_dirty_excluding_kuzushi_state(target: &Path) -> bool {
    git_stdout(target, &["status", "--porcelain"])
        .map(|status| dirty_status_lines(&status).any(|line| !status_line_is_kuzushi_state(line)))
        .unwrap_or(false)
}

fn dirty_status_lines(status: &str) -> impl Iterator<Item = &str> {
    status.lines().filter(|line| !line.trim().is_empty())
}

fn status_line_is_kuzushi_state(line: &str) -> bool {
    let path = line
        .get(3..)
        .unwrap_or(line)
        .rsplit(" -> ")
        .next()
        .unwrap_or("")
        .trim();
    path == ".kuzushi" || path.starts_with(".kuzushi/")
}

fn git_stdout(target: &Path, args: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(target).args(args);
    let output = bounded_git_output(&mut command, GIT_METADATA_TIMEOUT).ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn run_git_checked(target: &Path, args: &[&str]) -> Result<()> {
    let mut command = Command::new("git");
    command.arg("-C").arg(target).args(args);
    let output = bounded_git_output(&mut command, GIT_MUTATION_TIMEOUT)
        .with_context(|| format!("failed to run git {}", args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    bail!(
        "git {} failed{}",
        args.join(" "),
        if stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        }
    )
}

fn bounded_git_output(command: &mut Command, timeout: Duration) -> Result<Output> {
    crate::bounded_subprocess::output_with_limits_and_control(
        command,
        "git",
        crate::bounded_subprocess::DEFAULT_STDOUT_LIMIT,
        crate::bounded_subprocess::DEFAULT_STDERR_LIMIT,
        timeout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn switch_target_revision_checks_out_clean_repo_revision() {
        let Some(repo) = temp_git_repo() else {
            return;
        };
        let first = git_head(repo.path()).unwrap();
        fs::write(repo.path().join("tracked.txt"), "second\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(
            repo.path(),
            &["-c", "commit.gpgsign=false", "commit", "-m", "second"],
        );
        let second = git_head(repo.path()).unwrap();

        let outcome = switch_target_revision(repo.path(), &first).unwrap();

        assert_eq!(outcome.previous.sha, second);
        assert_eq!(outcome.current.sha, first);
        assert!(!outcome.current.dirty);
    }

    #[test]
    fn switch_target_revision_refuses_dirty_worktree() {
        let Some(repo) = temp_git_repo() else {
            return;
        };
        let head = git_head(repo.path()).unwrap();
        fs::write(repo.path().join("tracked.txt"), "dirty\n").unwrap();

        let error = switch_target_revision(repo.path(), "HEAD").unwrap_err();

        assert!(error.to_string().contains("dirty worktree"));
        assert_eq!(git_head(repo.path()).unwrap(), head);
    }

    #[test]
    fn switch_target_revision_ignores_kuzushi_state_dir() {
        let Some(repo) = temp_git_repo() else {
            return;
        };
        let first = git_head(repo.path()).unwrap();
        fs::write(repo.path().join("tracked.txt"), "second\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(
            repo.path(),
            &["-c", "commit.gpgsign=false", "commit", "-m", "second"],
        );
        let run_dir = crate::run_artifacts::run_dir(repo.path(), "run-1");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(run_dir.join("run.json"), "{}").unwrap();

        let outcome = switch_target_revision(repo.path(), &first).unwrap();

        assert_eq!(outcome.current.sha, first);
    }

    #[test]
    fn target_git_metadata_ignores_kuzushi_state_dir() {
        let Some(repo) = temp_git_repo() else {
            return;
        };
        let run_dir = crate::run_artifacts::run_dir(repo.path(), "run-1");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(run_dir.join("run.json"), "{}").unwrap();

        let metadata = target_git_metadata(repo.path()).unwrap();

        assert!(!metadata.dirty);
    }

    #[test]
    fn bounded_git_output_kills_a_wedged_subprocess() {
        let started = std::time::Instant::now();
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 60"]);

        let result = bounded_git_output(&mut command, Duration::from_millis(50));

        assert!(result.is_err(), "wedged subprocess must not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timeout must fire well before the subprocess would finish"
        );
    }

    fn temp_git_repo() -> Option<tempfile::TempDir> {
        if Command::new("git").arg("--version").output().is_err() {
            return None;
        }
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init"]);
        git(repo.path(), &["checkout", "-b", "main"]);
        git(repo.path(), &["config", "user.email", "test@example.com"]);
        git(repo.path(), &["config", "user.name", "Kuzushi Test"]);
        fs::write(repo.path().join("tracked.txt"), "initial\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(
            repo.path(),
            &["-c", "commit.gpgsign=false", "commit", "-m", "initial"],
        );
        Some(repo)
    }

    fn git(target: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(target)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_head(target: &Path) -> Option<String> {
        git_stdout(target, &["rev-parse", "HEAD"])
    }
}
