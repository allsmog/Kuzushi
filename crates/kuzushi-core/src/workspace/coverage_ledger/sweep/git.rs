//! Bounded, source-only Git inspection. Failures cannot become a clean-source claim.
use crate::run_artifacts::RunTargetGitMetadata;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

const MAX_GIT_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn metadata(target: &Path) -> Result<RunTargetGitMetadata> {
    let sha = text_output(target, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let branch = text_output(target, &["branch", "--show-current"])?;
    let status = output(
        target,
        &["status", "--porcelain=v1", "-z", "--untracked-files=normal"],
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

fn text_output(target: &Path, args: &[&str]) -> Result<String> {
    let result = output(target, args)?;
    anyhow::ensure!(
        result.status.success(),
        "sweep requires readable Git metadata"
    );
    Ok(String::from_utf8(result.stdout)
        .context("Git metadata is not valid UTF-8")?
        .trim()
        .to_string())
}

pub(super) fn whole_repo_diff(target: &Path, from: &str, to: &str) -> Result<Option<Vec<String>>> {
    if !valid_revision(from) {
        return Ok(None);
    }
    let output = output(
        target,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "-z",
            &format!("{from}..{to}"),
            "--",
        ],
    )?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(paths(&output.stdout)?))
}

fn valid_revision(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn output(target: &Path, args: &[&str]) -> Result<Output> {
    let mut command = Command::new("git");
    command
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("-C")
        .arg(target)
        .args(["-c", "core.fsmonitor=false"])
        .args(args);
    crate::bounded_subprocess::output_with_limits_and_control(
        &mut command,
        "coverage Git inspection",
        MAX_GIT_OUTPUT_BYTES,
        64 * 1024,
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
