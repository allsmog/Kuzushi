use super::*;

pub(crate) fn validate_patch(
    worktree_path: &Path,
    diff: &str,
    plan: &PatchValidationPlan,
) -> ValidationResult {
    let mut logs = Vec::new();

    if let Some(result) = validate_git_apply_steps(worktree_path, diff, &mut logs) {
        return result;
    }

    if let Some(result) = validate_build_and_test_steps(worktree_path, plan, &mut logs) {
        return result;
    }

    validation_success(logs)
}

fn validate_git_apply_steps(
    worktree_path: &Path,
    diff: &str,
    logs: &mut Vec<String>,
) -> Option<ValidationResult> {
    if let Some(result) = validate_git_apply_check(worktree_path, diff, logs) {
        return Some(result);
    }
    validate_git_apply(worktree_path, diff, logs)
}

fn validate_git_apply_check(
    worktree_path: &Path,
    diff: &str,
    logs: &mut Vec<String>,
) -> Option<ValidationResult> {
    validate_git_input_step(
        worktree_path,
        &["apply", "--check"],
        diff,
        "git apply --check",
        PatchStatus::ApplyFailed,
        logs,
    )
}

fn validate_git_apply(
    worktree_path: &Path,
    diff: &str,
    logs: &mut Vec<String>,
) -> Option<ValidationResult> {
    validate_git_input_step(
        worktree_path,
        &["apply"],
        diff,
        "git apply",
        PatchStatus::ApplyFailed,
        logs,
    )
}

fn validate_build_and_test_steps(
    worktree_path: &Path,
    plan: &PatchValidationPlan,
    logs: &mut Vec<String>,
) -> Option<ValidationResult> {
    if let Some(result) = validate_optional_shell_step(
        worktree_path,
        plan.build.as_deref(),
        "build",
        PatchStatus::BuildFailed,
        logs,
    ) {
        return Some(result);
    }
    validate_optional_shell_step(
        worktree_path,
        plan.test.as_deref(),
        "tests",
        PatchStatus::TestsFailed,
        logs,
    )
}

fn validate_optional_shell_step(
    worktree_path: &Path,
    command: Option<&str>,
    label: &str,
    failure_status: PatchStatus,
    logs: &mut Vec<String>,
) -> Option<ValidationResult> {
    validate_shell_step(worktree_path, command?, label, failure_status, logs)
}

fn validation_success(mut logs: Vec<String>) -> ValidationResult {
    logs.push("All validations passed.".to_string());
    ValidationResult {
        status: PatchStatus::Sound,
        output: logs.join("\n"),
    }
}

pub(crate) fn validate_git_input_step(
    worktree_path: &Path,
    args: &[&str],
    input: &str,
    label: &str,
    failure_status: PatchStatus,
    logs: &mut Vec<String>,
) -> Option<ValidationResult> {
    match run_git_with_input(worktree_path, args, input) {
        Ok(_) => {
            logs.push(format!("{label}: OK"));
            None
        }
        Err(error) => Some(validation_failure(
            logs,
            failure_status,
            format!("{label}: FAILED - {error}"),
        )),
    }
}

pub(crate) fn validate_shell_step(
    worktree_path: &Path,
    command: &str,
    label: &str,
    failure_status: PatchStatus,
    logs: &mut Vec<String>,
) -> Option<ValidationResult> {
    match run_shell_command(worktree_path, command) {
        Ok(_) => {
            logs.push(format!("{label} ({command}): OK"));
            None
        }
        Err(error) => Some(validation_failure(
            logs,
            failure_status,
            format!("{label} ({command}): FAILED - {error}"),
        )),
    }
}

pub(crate) fn validation_failure(
    logs: &mut Vec<String>,
    status: PatchStatus,
    message: String,
) -> ValidationResult {
    logs.push(message);
    ValidationResult {
        status,
        output: logs.join("\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_applies_diff_only_inside_disposable_worktree() {
        if git_is_unavailable() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        initialize_repo(repo);
        let worktree = create_disposable_worktree(repo).unwrap();
        let plan = PatchValidationPlan {
            build: None,
            test: None,
        };

        let result = validate_patch(&worktree, rename_demo_diff(), &plan);

        assert_eq!(result.status, PatchStatus::Sound);
        assert_eq!(std::fs::read_to_string(repo.join("demo.txt")).unwrap(), "before\n");
        assert_eq!(
            std::fs::read_to_string(worktree.join("demo.txt")).unwrap(),
            "after\n"
        );
        cleanup_worktree(repo, &worktree);
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
            .args(args)
            .current_dir(repo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn rename_demo_diff() -> &'static str {
        "diff --git a/demo.txt b/demo.txt\n\
         --- a/demo.txt\n\
         +++ b/demo.txt\n\
         @@ -1 +1 @@\n\
         -before\n\
         +after\n"
    }
}
