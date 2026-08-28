use super::*;

/// The scannable files a git reference changed, plus the reference that
/// produced them.
///
/// Shell `scan since <ref>` and CLI `kuzushi scan --since <ref>` express the
/// same operator intent, so both resolve their scope through this one value
/// instead of each running their own git/fs walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedScanScope {
    /// Target-relative paths that git reported as changed and that still
    /// exist as files. Sorted and deduped by the underlying diff.
    pub paths: Vec<PathBuf>,
    /// The operator-supplied git reference the diff was taken against.
    pub diff_base: String,
}

impl ChangedScanScope {
    /// Canonical `sast:scan` input for this scope.
    ///
    /// `paths` and `diffBase` are both declared `sast:scan` options, so this
    /// object passes descriptor validation at the shared dispatch boundary.
    pub fn to_sast_scan_input(&self) -> serde_json::Value {
        let paths = self
            .paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        json!({ "paths": paths, "diffBase": self.diff_base })
    }
}

/// Resolve the changed-file scope for "scan everything touched since
/// `reference`".
///
/// Returns `Ok(None)` when the reference resolved but left no scannable file,
/// so callers can report "nothing to scan" instead of silently widening.
pub fn changed_scan_input(
    target_root: &Path,
    reference: &str,
    include_worktree: bool,
) -> Result<Option<ChangedScanScope>> {
    let diff = crate::workspace::diff_scope::git_diff_files(target_root, reference, include_worktree)?;
    let paths = retain_existing_files(target_root, diff.files);
    if paths.is_empty() {
        return Ok(None);
    }
    Ok(Some(ChangedScanScope {
        paths,
        diff_base: diff.since_ref,
    }))
}

/// Filesystem adapter: drop paths git reported that no longer exist in the
/// worktree (deletions, renames away). Scanners cannot open them, and writing
/// them into a scope file only manufactures phantom coverage.
fn retain_existing_files(target_root: &Path, files: Vec<PathBuf>) -> Vec<PathBuf> {
    files
        .into_iter()
        .filter(|path| target_root.join(path).is_file())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn commit_all(root: &Path, message: &str) {
        git(root, &["add", "-A"]);
        git(root, &["-c", "commit.gpgsign=false", "commit", "-m", message]);
    }

    /// Repo with one commit containing `keep.rs` and `drop.rs`, returning the
    /// base revision.
    fn base_repo(root: &Path) -> String {
        fs::write(root.join("keep.rs"), "fn keep() {}\n").unwrap();
        fs::write(root.join("drop.rs"), "fn drop_me() {}\n").unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "tests@example.com"]);
        git(root, &["config", "user.name", "Kuzushi Tests"]);
        commit_all(root, "base");
        git(root, &["rev-parse", "HEAD"])
    }

    #[cfg(unix)]
    #[test]
    fn changed_scan_input_drops_deleted_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let base = base_repo(root);

        fs::write(root.join("keep.rs"), "fn keep2() {}\n").unwrap();
        fs::remove_file(root.join("drop.rs")).unwrap();
        commit_all(root, "edit and delete");

        let scope = changed_scan_input(root, &base, false).unwrap().unwrap();
        assert_eq!(scope.paths, vec![PathBuf::from("keep.rs")]);
        assert_eq!(scope.diff_base, base);
    }

    #[cfg(unix)]
    #[test]
    fn changed_scan_input_to_sast_scan_input_carries_paths_and_diff_base() {
        let scope = ChangedScanScope {
            paths: vec![PathBuf::from("src/a.rs"), PathBuf::from("src/b.rs")],
            diff_base: "HEAD~2".to_string(),
        };
        assert_eq!(
            scope.to_sast_scan_input(),
            json!({ "paths": ["src/a.rs", "src/b.rs"], "diffBase": "HEAD~2" })
        );
    }

    #[cfg(unix)]
    #[test]
    fn changed_scan_input_include_worktree_sees_uncommitted_edits() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let base = base_repo(root);

        fs::write(root.join("keep.rs"), "fn keep_dirty() {}\n").unwrap();

        assert!(changed_scan_input(root, &base, false).unwrap().is_none());
        let scope = changed_scan_input(root, &base, true).unwrap().unwrap();
        assert_eq!(scope.paths, vec![PathBuf::from("keep.rs")]);
    }

    #[cfg(unix)]
    #[test]
    fn changed_scan_input_reports_nothing_to_scan_without_changes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let base = base_repo(root);
        assert!(changed_scan_input(root, &base, false).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn changed_scan_input_surfaces_invalid_reference_error() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        base_repo(root);
        let error = changed_scan_input(root, "no-such-ref", false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("git diff failed"), "unexpected error: {error}");
    }
}
