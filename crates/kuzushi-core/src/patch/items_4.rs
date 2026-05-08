use super::prelude::*;
use super::*;

pub(crate) fn validate_patch(
    worktree_path: &Path,
    diff: &str,
    plan: &PatchValidationPlan,
) -> ValidationResult {
    let mut logs = Vec::new();

    if let Some(result) = validate_git_input_step(
        worktree_path,
        &["apply", "--check"],
        diff,
        "git apply --check",
        PatchStatus::ApplyFailed,
        &mut logs,
    ) {
        return result;
    }

    if let Some(result) = validate_git_input_step(
        worktree_path,
        &["apply"],
        diff,
        "git apply",
        PatchStatus::ApplyFailed,
        &mut logs,
    ) {
        return result;
    }

    if let Some(command) = &plan.build {
        if let Some(result) = validate_shell_step(
            worktree_path,
            command,
            "build",
            PatchStatus::BuildFailed,
            &mut logs,
        ) {
            return result;
        }
    }

    if let Some(command) = &plan.test {
        if let Some(result) = validate_shell_step(
            worktree_path,
            command,
            "tests",
            PatchStatus::TestsFailed,
            &mut logs,
        ) {
            return result;
        }
    }

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
