//! Bounded, source-only Git inspection. Failures cannot become a clean-source claim.
use super::SourceComparisonBudget;
use crate::run_artifacts::RunTargetGitMetadata;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

const MAX_GIT_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn metadata(
    target: &Path,
    cancellation: Option<&crate::ScanCancellation>,
) -> Result<RunTargetGitMetadata> {
    let sha = text_output(
        target,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        cancellation,
    )?;
    let branch = text_output(target, &["branch", "--show-current"], cancellation)?;
    let status = output(
        target,
        &["status", "--porcelain=v1", "-z", "--untracked-files=normal"],
        cancellation,
    )?;
    anyhow::ensure!(
        status.status.success(),
        "Git status could not establish working-tree state"
    );
    Ok(RunTargetGitMetadata {
        sha,
        branch: (!branch.is_empty()).then_some(branch),
        dirty: status_is_dirty(&status.stdout)?,
    })
}

fn text_output(
    target: &Path,
    args: &[&str],
    cancellation: Option<&crate::ScanCancellation>,
) -> Result<String> {
    let result = output(target, args, cancellation)?;
    anyhow::ensure!(
        result.status.success(),
        "sweep requires readable Git metadata"
    );
    Ok(String::from_utf8(result.stdout)
        .context("Git metadata is not valid UTF-8")?
        .trim()
        .to_string())
}

pub(super) fn whole_repo_diff(
    target: &Path,
    from: &str,
    to: &str,
    cancellation: Option<&crate::ScanCancellation>,
    budget: &mut SourceComparisonBudget,
) -> Result<Option<String>> {
    if !valid_revision(from) {
        return Ok(None);
    }
    let output_limit = budget.reserve_diff()?.min(MAX_GIT_OUTPUT_BYTES);
    let output = limited_output(
        target,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            // A move must expose both paths before filtering by scope.
            "--no-renames",
            "--name-only",
            "-z",
            &format!("{from}..{to}"),
            "--",
        ],
        cancellation,
        output_limit,
    )?;
    budget.record_bytes(output.stdout.len())?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8(output.stdout).context(
        "Git paths are not valid UTF-8; source comparison is unavailable",
    )?))
}

fn valid_revision(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn output(
    target: &Path,
    args: &[&str],
    cancellation: Option<&crate::ScanCancellation>,
) -> Result<Output> {
    limited_output(target, args, cancellation, MAX_GIT_OUTPUT_BYTES)
}

fn limited_output(
    target: &Path,
    args: &[&str],
    cancellation: Option<&crate::ScanCancellation>,
    max_stdout_bytes: usize,
) -> Result<Output> {
    let mut command = Command::new("git");
    command
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("-C")
        .arg(target)
        .args(["-c", "core.fsmonitor=false"])
        .args(args);
    crate::bounded_subprocess::output_with_limits_and_cancellation(
        &mut command,
        "coverage Git inspection",
        max_stdout_bytes,
        64 * 1024,
        cancellation,
        GIT_TIMEOUT,
    )
}

fn paths(bytes: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(bytes)
        .context("Git paths are not valid UTF-8; source comparison is unavailable")?;
    Ok(text
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect())
}

fn status_is_dirty(bytes: &[u8]) -> Result<bool> {
    let rows = paths(bytes)?;
    let mut rows = rows.iter();
    while let Some(row) = rows.next() {
        let path = row.get(3..).context("Git status entry is malformed")?;
        let previous = renamed_path(row, &mut rows)?;
        if outside_state(path) || previous.is_some_and(outside_state) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn renamed_path<'a>(
    row: &str,
    rows: &mut impl Iterator<Item = &'a String>,
) -> Result<Option<&'a str>> {
    let status = row.get(..2).context("Git status entry is malformed")?;
    if !status.contains(['R', 'C']) {
        return Ok(None);
    }
    rows.next()
        .map(|path| Some(path.as_str()))
        .context("Git rename status is incomplete")
}

fn outside_state(path: &str) -> bool {
    path != ".kuzushi" && !path.starts_with(".kuzushi/")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nul_paths_preserve_unicode_and_newlines_without_a_false_scope_miss() {
        assert_eq!(
            paths("docs/π.rs\0docs/a\nb.rs\0".as_bytes()).unwrap(),
            vec!["docs/π.rs", "docs/a\nb.rs"]
        );
        assert!(paths(&[255]).is_err());
        assert!(!valid_revision("--output=elsewhere"));
    }
    #[test]
    fn status_ignores_state_only_and_checks_both_sides_of_a_rename() {
        assert!(!status_is_dirty(b"?? .kuzushi/\0").unwrap());
        assert!(status_is_dirty(b" M docs/a\nb.rs\0").unwrap());
        assert!(status_is_dirty(b"R  .kuzushi/moved\0src/original.rs\0").unwrap());
        assert!(status_is_dirty(b"R  .kuzushi/moved\0").is_err());
    }
}
