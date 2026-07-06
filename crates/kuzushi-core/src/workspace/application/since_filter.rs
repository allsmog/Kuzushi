use crate::workspace::resolve_target_git_commit;
use anyhow::{bail, Result};
use std::path::Path;

pub fn findings_since_filter_expression(target: Option<&Path>, reference: &str) -> Result<String> {
    let reference = normalized_since_ref(reference)?;
    let target = target.ok_or_else(|| anyhow::anyhow!("since requires an active target"))?;
    if let Some(sha) = resolve_target_git_commit(target, reference) {
        return Ok(format!("rev:{sha}"));
    }
    if looks_like_sha_prefix(reference) {
        return Ok(format!("rev:{}", reference.to_ascii_lowercase()));
    }
    Ok(format!("branch:{}", reference.to_ascii_lowercase()))
}

fn normalized_since_ref(reference: &str) -> Result<&str> {
    let reference = reference.trim();
    if reference.is_empty() {
        bail!("since needs a git ref");
    }
    if reference.split_whitespace().count() > 1 {
        bail!("since git ref cannot contain whitespace");
    }
    Ok(reference)
}

fn looks_like_sha_prefix(reference: &str) -> bool {
    reference.len() >= 7 && reference.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    #[test]
    fn resolves_git_ref_to_revision_filter() {
        let Some(repo) = temp_git_repo() else {
            return;
        };
        let head = git_head(repo.path()).unwrap();

        let expression = findings_since_filter_expression(Some(repo.path()), "HEAD").unwrap();

        assert_eq!(expression, format!("rev:{head}"));
    }

    #[test]
    fn keeps_sha_prefix_without_git_resolution() {
        let expression =
            findings_since_filter_expression(Some(Path::new("/missing")), "ABCDEF1").unwrap();

        assert_eq!(expression, "rev:abcdef1");
    }

    #[test]
    fn falls_back_to_branch_filter_for_named_ref() {
        let expression =
            findings_since_filter_expression(Some(Path::new("/missing")), "Feature/Thing").unwrap();

        assert_eq!(expression, "branch:feature/thing");
    }

    #[test]
    fn rejects_missing_target() {
        let error = findings_since_filter_expression(None, "main").unwrap_err();

        assert!(error.to_string().contains("active target"));
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
        let output = Command::new("git")
            .arg("-C")
            .arg(target)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}
