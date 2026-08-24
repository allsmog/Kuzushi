use super::*;

pub(crate) fn validate_patch(
    worktree_path: &Path,
    diff: &str,
    plan: &PatchValidationPlan,
    control: PatchCommandControl<'_>,
) -> Result<ValidationResult> {
    ensure_patch_validation_plan(plan)?;
    let mut logs = Vec::new();

    if let Some(result) = validate_git_apply_steps(worktree_path, diff, &mut logs, control)? {
        return Ok(result);
    }

    if let Some(result) = validate_build_and_test_steps(worktree_path, plan, &mut logs, control)? {
        return Ok(result);
    }

    Ok(validation_success(logs))
}

fn validate_git_apply_steps(
    worktree_path: &Path,
    diff: &str,
    logs: &mut Vec<String>,
    control: PatchCommandControl<'_>,
) -> Result<Option<ValidationResult>> {
    if let Some(result) = validate_git_apply_check(worktree_path, diff, logs, control)? {
        return Ok(Some(result));
    }
    validate_git_apply(worktree_path, diff, logs, control)
}

fn validate_git_apply_check(
    worktree_path: &Path,
    diff: &str,
    logs: &mut Vec<String>,
    control: PatchCommandControl<'_>,
) -> Result<Option<ValidationResult>> {
    validate_git_input_step(
        worktree_path,
        &["apply", "--check"],
        diff,
        "git apply --check",
        PatchStatus::ApplyFailed,
        logs,
        control,
    )
}

fn validate_git_apply(
    worktree_path: &Path,
    diff: &str,
    logs: &mut Vec<String>,
    control: PatchCommandControl<'_>,
) -> Result<Option<ValidationResult>> {
    validate_git_input_step(
        worktree_path,
        &["apply"],
        diff,
        "git apply",
        PatchStatus::ApplyFailed,
        logs,
        control,
    )
}

fn validate_build_and_test_steps(
    worktree_path: &Path,
    plan: &PatchValidationPlan,
    logs: &mut Vec<String>,
    control: PatchCommandControl<'_>,
) -> Result<Option<ValidationResult>> {
    if let Some(result) = validate_optional_shell_step(
        worktree_path,
        plan.build.as_deref(),
        "build",
        PatchStatus::BuildFailed,
        logs,
        control,
    )? {
        return Ok(Some(result));
    }
    validate_optional_shell_step(
        worktree_path,
        plan.test.as_deref(),
        "tests",
        PatchStatus::TestsFailed,
        logs,
        control,
    )
}

fn validate_optional_shell_step(
    worktree_path: &Path,
    command: Option<&str>,
    label: &str,
    failure_status: PatchStatus,
    logs: &mut Vec<String>,
    control: PatchCommandControl<'_>,
) -> Result<Option<ValidationResult>> {
    let Some(command) = command else {
        return Ok(None);
    };
    validate_shell_step(worktree_path, command, label, failure_status, logs, control)
}

fn validation_success(mut logs: Vec<String>) -> ValidationResult {
    logs.push("All configured validations passed.".to_string());
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
    control: PatchCommandControl<'_>,
) -> Result<Option<ValidationResult>> {
    match run_git_with_input(worktree_path, args, input, control) {
        Ok(_) => {
            logs.push(format!("{label}: OK"));
            Ok(None)
        }
        Err(error) => validation_command_failure(
            control,
            error,
            logs,
            failure_status,
            format!("{label}: FAILED"),
        ),
    }
}

pub(crate) fn validate_shell_step(
    worktree_path: &Path,
    command: &str,
    label: &str,
    failure_status: PatchStatus,
    logs: &mut Vec<String>,
    control: PatchCommandControl<'_>,
) -> Result<Option<ValidationResult>> {
    match run_shell_command(worktree_path, command, control) {
        Ok(_) => {
            logs.push(format!("{label} ({command}): OK"));
            Ok(None)
        }
        Err(error) => validation_command_failure(
            control,
            error,
            logs,
            failure_status,
            format!("{label} ({command}): FAILED"),
        ),
    }
}

fn validation_command_failure(
    control: PatchCommandControl<'_>,
    error: anyhow::Error,
    logs: &mut Vec<String>,
    status: PatchStatus,
    prefix: String,
) -> Result<Option<ValidationResult>> {
    control.ensure_active()?;
    Ok(Some(validation_failure(
        logs,
        status,
        format!("{prefix} - {error}"),
    )))
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
    use std::process::{Command, Stdio};

    #[test]
    fn validation_refuses_apply_only_plan_before_touching_worktree() {
        if git_is_unavailable() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        initialize_repo(repo);
        let control = unattended_patch_control();
        let mut input = json!({"fingerprint": "finding-1"});
        bind_repository_source_snapshot(repo, &mut input).unwrap();
        let source_commit = patch_source_commit(&input).unwrap();
        let worktree = create_disposable_worktree(repo, &source_commit, control).unwrap();
        let plan = PatchValidationPlan {
            build: None,
            test: None,
        };

        let error = validate_patch(&worktree, rename_demo_diff(), &plan, control).unwrap_err();

        assert!(error.to_string().contains("requires at least one build or test validation command"));
        assert_eq!(
            std::fs::read_to_string(repo.join("demo.txt")).unwrap(),
            "before\n"
        );
        assert_eq!(
            std::fs::read_to_string(worktree.join("demo.txt")).unwrap(),
            "before\n"
        );
        cleanup_worktree(repo, &worktree, control).unwrap();
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
            // Stay hermetic against a host git config that forces signing.
            .args(["-c", "commit.gpgsign=false"])
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
