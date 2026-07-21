use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

const GIT_PROOF_TIMEOUT: Duration = Duration::from_secs(5);
// The config-origin enumeration repeats the absolute origin path for every
// config key; monorepos with large configs exceed 16 KiB long before the
// output is adversarial. 1 MiB keeps the read bounded without rejecting
// legitimate workspaces.
const GIT_STDOUT_LIMIT: usize = 1024 * 1024;
const GIT_STDERR_LIMIT: usize = 16 * 1024;
const DISPLAY_DIAGNOSTIC_LIMIT: usize = 2 * 1024;

pub(super) fn configured_global_exclude(root: &Path) -> Result<Option<PathBuf>> {
    let output = git_output(
        root,
        &["config", "--path", "--get", "core.excludesFile"],
        "Git global exclude lookup",
    )?;
    match output.status.code() {
        Some(0) => parse_git_path(root, &output.stdout).map(Some),
        Some(1) => Ok(None),
        _ => anyhow::bail!(
            "Could not resolve Git global exclude policy: {}",
            command_failure(&output)
        ),
    }
}

pub(super) fn canonical_git_path(root: &Path, arguments: &[&str]) -> Result<PathBuf> {
    let path = command_git_path(root, arguments)?;
    std::fs::canonicalize(&path)
        .with_context(|| format!("Could not resolve Git policy path {}", path.display()))
}

pub(super) fn resolved_git_path(root: &Path, arguments: &[&str]) -> Result<PathBuf> {
    command_git_path(root, arguments)
}

fn command_git_path(root: &Path, arguments: &[&str]) -> Result<PathBuf> {
    let output = git_output(root, arguments, "Git repository identity")?;
    anyhow::ensure!(
        output.status.success(),
        "Could not resolve Git repository identity: {}",
        command_failure(&output)
    );
    parse_git_path(root, &output.stdout)
}

fn parse_git_path(root: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let value = std::str::from_utf8(bytes)
        .context("Git returned a non-UTF-8 policy path")?
        .trim();
    anyhow::ensure!(!value.is_empty(), "Git returned an empty policy path");
    let path = PathBuf::from(value);
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}

pub(super) fn git_output(root: &Path, arguments: &[&str], label: &str) -> Result<Output> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(arguments);
    crate::bounded_subprocess::output_with_limits_and_control(
        &mut command,
        label,
        GIT_STDOUT_LIMIT,
        GIT_STDERR_LIMIT,
        GIT_PROOF_TIMEOUT,
    )
}

pub(super) fn command_is_missing(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

pub(super) fn command_failure(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let message = [stderr.trim(), stdout.trim()]
        .into_iter()
        .find(|value| !value.is_empty())
        .unwrap_or("Git command failed without diagnostics");
    truncate_diagnostic(message)
}

fn truncate_diagnostic(message: &str) -> String {
    if message.len() <= DISPLAY_DIAGNOSTIC_LIMIT {
        return message.to_string();
    }
    let end = message
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= DISPLAY_DIAGNOSTIC_LIMIT)
        .last()
        .unwrap_or_default();
    format!("{}...", &message[..end])
}
