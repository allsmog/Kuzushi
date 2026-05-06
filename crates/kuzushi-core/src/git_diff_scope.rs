//! `--since <ref>` diff-scoped scanning.
//!
//! Runs `git diff --name-only <ref>...HEAD` against the target tree and
//! returns the list of changed files (relative to the repo root). Other
//! modules use the result to narrow their walks — `full_mode_multi`
//! filters its file list, and the eval harness can scope the scan to
//! "what changed in this PR" without re-scanning the entire codebase.
//!
//! Failure modes are surfaced as `Result::Err` rather than swallowed —
//! a missing git repo, a bad ref, or a permission error all produce a
//! clear error so the operator can fix their config.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct DiffScope {
    /// Files that differ between `since_ref` and HEAD (or the working
    /// tree). Paths are relative to the repository root.
    pub files: Vec<PathBuf>,
    /// The ref operator passed in.
    pub since_ref: String,
    /// Whether the working tree was included (`<ref>...HEAD` vs
    /// `<ref>...` (working tree)).
    pub include_worktree: bool,
}

impl DiffScope {
    /// Whether this scope contains the given path. Comparison is exact —
    /// callers should pass repo-relative paths.
    pub fn contains_path(&self, candidate: &Path) -> bool {
        self.files.iter().any(|p| p == candidate)
    }

    /// Whether this scope contains any path with the given prefix.
    /// Useful for engines that emit findings keyed on a sub-directory.
    pub fn contains_prefix(&self, prefix: &Path) -> bool {
        self.files.iter().any(|p| p.starts_with(prefix))
    }
}

/// Resolve the diff-scoped file list for a target tree against `since_ref`.
///
/// `include_worktree=true` includes uncommitted changes
/// (`git diff --name-only <ref>` instead of `<ref>...HEAD`).
pub fn git_diff_files(
    target: &Path,
    since_ref: &str,
    include_worktree: bool,
) -> Result<DiffScope> {
    let trimmed = since_ref.trim();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "diff_scope: since_ref must be non-empty"
    );
    anyhow::ensure!(
        !trimmed.contains(['\n', '\0', ';', '|', '`']),
        "diff_scope: since_ref contains forbidden characters"
    );

    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(target);
    cmd.arg("diff").arg("--name-only");
    let arg = if include_worktree {
        // Files that differ between `<ref>` and the working tree —
        // includes staged + unstaged.
        trimmed.to_string()
    } else {
        // Files that differ between `<ref>` and HEAD — committed only.
        format!("{trimmed}...HEAD")
    };
    cmd.arg(arg);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
        .output()
        .with_context(|| format!("diff_scope: could not invoke git in {}", target.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "diff_scope: git diff failed (exit {}): {}",
            output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".to_string()),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8(output.stdout)
        .context("diff_scope: git output was not valid UTF-8")?;
    let mut files = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        files.push(PathBuf::from(trimmed));
    }
    files.sort();
    files.dedup();

    Ok(DiffScope {
        files,
        since_ref: since_ref.to_string(),
        include_worktree,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.email=test@example.com", "-c", "user.name=test"])
            .arg("-C")
            .arg(dir)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git binary required for these tests");
        if !status.success() {
            panic!("git {args:?} in {} failed", dir.display());
        }
    }

    fn git_capture(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("git binary required");
        if !out.status.success() {
            panic!("git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        String::from_utf8(out.stdout).unwrap()
    }

    fn make_repo() -> (tempfile::TempDir, String) {
        let tmp = tempdir().unwrap();
        git(tmp.path(), &["init", "-q", "-b", "main"]);
        fs::write(tmp.path().join("a.c"), "void a(){}\n").unwrap();
        fs::write(tmp.path().join("b.c"), "void b(){}\n").unwrap();
        git(tmp.path(), &["add", "."]);
        git(tmp.path(), &["commit", "-q", "-m", "first", "--no-gpg-sign"]);
        let head = git_capture(tmp.path(), &["rev-parse", "HEAD"]).trim().to_string();
        (tmp, head)
    }

    #[test]
    fn returns_empty_when_no_diff() {
        let (tmp, base) = make_repo();
        let scope = git_diff_files(tmp.path(), &base, false).unwrap();
        assert!(scope.files.is_empty(), "expected empty diff, got {:?}", scope.files);
        let _ = tmp;
    }

    #[test]
    fn returns_changed_files_against_committed_base() {
        let (tmp, base) = make_repo();
        // Modify a.c and add c.c, then commit.
        fs::write(tmp.path().join("a.c"), "void a_v2(){}\n").unwrap();
        fs::write(tmp.path().join("c.c"), "void c(){}\n").unwrap();
        git(tmp.path(), &["add", "."]);
        git(tmp.path(), &["commit", "-q", "-m", "second", "--no-gpg-sign"]);

        let scope = git_diff_files(tmp.path(), &base, false).unwrap();
        let names: Vec<&str> = scope.files.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(names, vec!["a.c", "c.c"]);
    }

    #[test]
    fn include_worktree_picks_up_uncommitted_changes() {
        let (tmp, base) = make_repo();
        fs::write(tmp.path().join("b.c"), "// edited but not committed\nvoid b(){}\n").unwrap();
        let committed_only = git_diff_files(tmp.path(), &base, false).unwrap();
        // No new commits → committed-only diff is empty.
        assert!(committed_only.files.is_empty());
        let with_worktree = git_diff_files(tmp.path(), &base, true).unwrap();
        let names: Vec<&str> = with_worktree.files.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(names, vec!["b.c"]);
    }

    #[test]
    fn rejects_bad_ref_with_useful_error() {
        let (tmp, _) = make_repo();
        let err = git_diff_files(tmp.path(), "no-such-ref-xyz", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("git diff failed"), "{err}");
    }

    #[test]
    fn rejects_injection_chars_in_ref() {
        let tmp = tempdir().unwrap();
        for evil in ["abc; rm -rf /", "abc | cat", "abc`whoami`"] {
            let err = git_diff_files(tmp.path(), evil, false).unwrap_err().to_string();
            assert!(err.contains("forbidden characters"), "{err}");
        }
    }

    #[test]
    fn contains_path_matches_exact_relative() {
        let scope = DiffScope {
            files: vec![PathBuf::from("src/foo.c"), PathBuf::from("src/bar.c")],
            since_ref: "main".to_string(),
            include_worktree: false,
        };
        assert!(scope.contains_path(Path::new("src/foo.c")));
        assert!(!scope.contains_path(Path::new("src/baz.c")));
        assert!(scope.contains_prefix(Path::new("src")));
        assert!(!scope.contains_prefix(Path::new("docs")));
    }
}
