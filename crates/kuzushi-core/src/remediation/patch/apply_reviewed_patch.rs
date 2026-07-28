use super::*;
use std::path::Component;

const MAX_PATCH_TOUCHED_FILE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedPatchApplyReport {
    pub checked: bool,
    pub applied: bool,
    pub touched_paths: Vec<String>,
    pub touched_files: Vec<crate::findings::PatchLifecycleFile>,
    pub diff_hash: String,
    pub base_commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedPatchApplyPlan {
    pub touched_paths: Vec<String>,
    pub touched_files: Vec<crate::findings::PatchLifecycleFile>,
    pub diff_hash: String,
    pub source_commit: String,
}

pub fn apply_reviewed_patch(repo_root: &Path, diff: &str) -> Result<ReviewedPatchApplyReport> {
    let control = unattended_patch_control();
    ensure_git_repository(repo_root, control)?;
    let source_commit = resolve_head_commit(repo_root, control)?;
    let plan = prepare_reviewed_patch_apply(repo_root, diff, &source_commit)?;
    apply_prepared_reviewed_patch(repo_root, diff, &plan)
}

pub fn prepare_reviewed_patch_apply(
    repo_root: &Path,
    diff: &str,
    source_commit: &str,
) -> Result<ReviewedPatchApplyPlan> {
    let control = unattended_patch_control();
    verify_patch_source_snapshot(repo_root, source_commit, control)?;
    let touched_paths = validated_diff_paths(diff)?;
    let before_hashes = touched_path_hashes(repo_root, &touched_paths)?;
    check_reviewed_patch(repo_root, diff, control)?;
    Ok(ReviewedPatchApplyPlan {
        touched_files: lifecycle_files(
            &touched_paths,
            &before_hashes,
            &vec![None; touched_paths.len()],
        ),
        touched_paths,
        diff_hash: patch_diff_hash(diff),
        source_commit: source_commit.to_string(),
    })
}

pub fn apply_prepared_reviewed_patch(
    repo_root: &Path,
    diff: &str,
    plan: &ReviewedPatchApplyPlan,
) -> Result<ReviewedPatchApplyReport> {
    anyhow::ensure!(
        patch_diff_hash(diff) == plan.diff_hash,
        "reviewed patch changed after application intent was recorded"
    );
    let control = unattended_patch_control();
    verify_patch_source_snapshot(repo_root, &plan.source_commit, control)?;
    ensure_planned_files_unchanged(repo_root, plan)?;
    check_reviewed_patch(repo_root, diff, control)?;
    run_git_with_input(repo_root, &["apply"], diff, control)
        .map_err(|error| anyhow::anyhow!("reviewed patch failed during `git apply`: {error:#}"))?;
    let after_hashes = touched_path_hashes(repo_root, &plan.touched_paths)?;
    Ok(ReviewedPatchApplyReport {
        checked: true,
        applied: true,
        touched_paths: plan.touched_paths.clone(),
        touched_files: lifecycle_files(
            &plan.touched_paths,
            &plan
                .touched_files
                .iter()
                .map(|file| file.before_hash.clone())
                .collect::<Vec<_>>(),
            &after_hashes,
        ),
        diff_hash: plan.diff_hash.clone(),
        base_commit: Some(plan.source_commit.clone()),
    })
}

fn check_reviewed_patch(
    repo_root: &Path,
    diff: &str,
    control: PatchCommandControl<'_>,
) -> Result<()> {
    run_git_with_input(repo_root, &["apply", "--check"], diff, control)
        .map(|_| ())
        .map_err(|error| {
            anyhow::anyhow!("reviewed patch did not pass `git apply --check`: {error:#}")
        })
}

fn ensure_planned_files_unchanged(repo_root: &Path, plan: &ReviewedPatchApplyPlan) -> Result<()> {
    let current = touched_path_hashes(repo_root, &plan.touched_paths)?;
    let expected = plan
        .touched_files
        .iter()
        .map(|file| file.before_hash.clone())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        current == expected,
        "reviewed patch target files changed after application intent was recorded"
    );
    Ok(())
}

fn lifecycle_files(
    paths: &[String],
    before_hashes: &[Option<String>],
    after_hashes: &[Option<String>],
) -> Vec<crate::findings::PatchLifecycleFile> {
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| crate::findings::PatchLifecycleFile {
            path: path.clone(),
            before_hash: before_hashes[index].clone(),
            after_hash: after_hashes[index].clone(),
        })
        .collect()
}

pub(crate) fn patch_diff_hash(diff: &str) -> String {
    crate::identity::hash_parts("kuzushi.patch.diff.v1", &[diff.as_bytes()]).to_string()
}

fn touched_path_hashes(repo_root: &Path, paths: &[String]) -> Result<Vec<Option<String>>> {
    paths
        .iter()
        .map(|path| hash_optional_file(repo_root, Path::new(path)))
        .collect()
}

pub(crate) fn hash_optional_file(root: &Path, path: &Path) -> Result<Option<String>> {
    match crate::bounded_file::read_regular_bytes_within(root, path, MAX_PATCH_TOUCHED_FILE_BYTES) {
        Ok(bytes) => Ok(Some(
            crate::identity::hash_parts("kuzushi.patch.file.v1", &[&bytes]).to_string(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not read {}", path.display())),
    }
}

fn validated_diff_paths(diff: &str) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for raw in candidate_diff_paths(diff) {
        let Some(path) = normalize_patch_path(raw)? else {
            continue;
        };
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        anyhow::bail!("reviewed patch did not name any repository-relative file paths");
    }
    Ok(paths)
}

fn candidate_diff_paths(diff: &str) -> Vec<&str> {
    diff.lines()
        .flat_map(candidate_paths_from_line)
        .collect::<Vec<_>>()
}

fn candidate_paths_from_line(line: &str) -> Vec<&str> {
    if let Some(rest) = line.strip_prefix("diff --git ") {
        return diff_git_paths(rest);
    }
    for prefix in [
        "--- ",
        "+++ ",
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return vec![trim_diff_metadata(rest)];
        }
    }
    Vec::new()
}

fn diff_git_paths(rest: &str) -> Vec<&str> {
    let mut parts = rest.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(left), Some(right)) => vec![left, right],
        _ => Vec::new(),
    }
}

fn trim_diff_metadata(value: &str) -> &str {
    value.split('\t').next().unwrap_or(value).trim()
}

fn normalize_patch_path(raw: &str) -> Result<Option<String>> {
    let raw = trim_diff_metadata(raw);
    if raw == "/dev/null" {
        return Ok(None);
    }
    let path = raw
        .strip_prefix("a/")
        .or_else(|| raw.strip_prefix("b/"))
        .unwrap_or(raw);
    validate_repository_relative_path(path)?;
    Ok(Some(path.to_string()))
}

fn validate_repository_relative_path(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        anyhow::bail!("reviewed patch contains an empty file path");
    }
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        anyhow::bail!("reviewed patch path {path:?} must be repository-relative");
    }
    for component in candidate.components() {
        validate_repository_path_component(component, path)?;
    }
    Ok(())
}

fn validate_repository_path_component(component: Component<'_>, path: &str) -> Result<()> {
    match component {
        Component::Normal(value) if value == std::ffi::OsStr::new(".git") => {
            anyhow::bail!("reviewed patch must not write inside .git");
        }
        Component::Normal(_) | Component::CurDir => Ok(()),
        Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
            anyhow::bail!("reviewed patch path {path:?} escapes the repository root");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn apply_reviewed_patch_updates_active_worktree() {
        if git_is_unavailable() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        initialize_repo(repo);

        let report = apply_reviewed_patch(repo, demo_diff()).unwrap();

        assert!(report.checked);
        assert!(report.applied);
        assert_eq!(report.touched_paths, vec!["demo.txt"]);
        assert_eq!(
            std::fs::read_to_string(repo.join("demo.txt")).unwrap(),
            "after\n"
        );
    }

    #[test]
    fn reviewed_patch_rejects_path_traversal() {
        let error = validated_diff_paths(
            "diff --git a/../outside.txt b/../outside.txt\n\
             --- a/../outside.txt\n\
             +++ b/../outside.txt\n",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("escapes the repository root"));
    }

    #[test]
    fn reviewed_patch_rejects_git_dir_writes() {
        let error = validated_diff_paths(
            "diff --git a/.git/config b/.git/config\n\
             --- a/.git/config\n\
             +++ b/.git/config\n",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains(".git"));
    }

    #[test]
    fn preparation_is_source_bound_and_does_not_mutate() {
        if git_is_unavailable() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        initialize_repo(repo);
        let source = resolve_head_commit(repo, unattended_patch_control()).unwrap();

        let plan = prepare_reviewed_patch_apply(repo, demo_diff(), &source).unwrap();

        assert_eq!(plan.source_commit, source);
        assert_eq!(
            std::fs::read_to_string(repo.join("demo.txt")).unwrap(),
            "before\n"
        );
    }

    #[test]
    fn preparation_rejects_a_different_generation_commit() {
        if git_is_unavailable() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        initialize_repo(repo);
        let wrong_source = "0123456789012345678901234567890123456789";

        let error = prepare_reviewed_patch_apply(repo, demo_diff(), wrong_source)
            .unwrap_err()
            .to_string();

        assert!(error.contains("source commit changed"));
        assert_eq!(
            std::fs::read_to_string(repo.join("demo.txt")).unwrap(),
            "before\n"
        );
    }

    fn initialize_repo(repo: &Path) {
        run_git(repo, &["init"]);
        std::fs::write(repo.join("demo.txt"), "before\n").unwrap();
        run_git(repo, &["add", "demo.txt"]);
        run_git(repo, &["commit", "-m", "initial"]);
    }

    fn git_is_unavailable() -> bool {
        Command::new("git").arg("--version").output().is_err()
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.email=kuzushi@example.invalid"])
            .args(["-c", "user.name=Kuzushi Test"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .current_dir(repo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn demo_diff() -> &'static str {
        "diff --git a/demo.txt b/demo.txt\n\
         --- a/demo.txt\n\
         +++ b/demo.txt\n\
         @@ -1 +1 @@\n\
         -before\n\
         +after\n"
    }
}
