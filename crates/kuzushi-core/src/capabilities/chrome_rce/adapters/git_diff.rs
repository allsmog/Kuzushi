use crate::capabilities::chrome_rce::domain::{ChangedPathLimits, CommittedPathComparison};
use crate::ScanCancellation;
use anyhow::{Context, Result};
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Duration, Instant};

pub(crate) fn compare_committed_paths(
    target: &Path,
    diff_base: &str,
    limits: ChangedPathLimits,
    cancellation: Option<&ScanCancellation>,
) -> Result<CommittedPathComparison> {
    crate::git_rev::ensure_safe_git_rev(diff_base, "chrome-rce:review-trigger diffBase")?;
    let git = ComparisonGit::new(target, limits, cancellation)?;
    let base_commit = git.commit(diff_base)?;
    let head_commit = git.commit("HEAD")?;
    let merge_base = git.merge_base(&base_commit, &head_commit)?;
    let repository_prefix = git.prefix()?;
    let mut changed_files = git.changed_paths(&merge_base, &head_commit)?;
    anyhow::ensure!(
        git.commit("HEAD")? == head_commit,
        "HEAD changed during path comparison; run a new comparison before using these hints"
    );
    let total_changed_files = changed_files.len();
    changed_files.truncate(limits.max_changed_files);
    let omitted_changed_files = total_changed_files - changed_files.len();
    Ok(CommittedPathComparison {
        base_commit,
        merge_base,
        head_commit,
        repository_prefix,
        changed_files,
        total_changed_files,
        omitted_changed_files,
    })
}

struct ComparisonGit<'a> {
    target: &'a Path,
    limits: ChangedPathLimits,
    cancellation: Option<&'a ScanCancellation>,
    deadline: Instant,
}

impl<'a> ComparisonGit<'a> {
    fn new(
        target: &'a Path,
        limits: ChangedPathLimits,
        cancellation: Option<&'a ScanCancellation>,
    ) -> Result<Self> {
        anyhow::ensure!(
            limits.max_changed_files > 0 && limits.max_git_output_bytes > 0,
            "Changed-path limits must be positive"
        );
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(limits.git_timeout_ms))
            .context("Git comparison deadline is outside the supported clock range")?;
        Ok(Self {
            target,
            limits,
            cancellation,
            deadline,
        })
    }

    fn output(&self, args: &[&str], limit: usize) -> Result<Vec<u8>> {
        let mut command = comparison_command(self.target, args);
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        anyhow::ensure!(!remaining.is_zero(), "Git path comparison deadline reached");
        let output = crate::bounded_subprocess::output_with_limits_and_cancellation(
            &mut command, "Git path comparison", limit, 32 * 1024, self.cancellation, remaining,
        ).context("Could not read Git path comparison; verify Git is installed and the target is a repository")?;
        anyhow::ensure!(
            output.status.success(),
            "Git path comparison failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    fn commit(&self, revision: &str) -> Result<String> {
        let revision = format!("{revision}^{{commit}}");
        let body = self
            .output(
                &["rev-parse", "--verify", "--end-of-options", &revision],
                4096,
            )
            .with_context(|| format!("Could not resolve comparison commit {revision:?}"))?;
        parse_commit(&body)
    }

    fn merge_base(&self, base: &str, head: &str) -> Result<String> {
        let body = self.output(&["merge-base", "--all", base, head], 4096)?;
        parse_commit(&body)
            .context("Comparison requires one merge base; multiple merge bases are ambiguous")
    }

    fn prefix(&self) -> Result<String> {
        let body = self.output(&["rev-parse", "--show-prefix"], 4096)?;
        let text = std::str::from_utf8(&body).context("Git target prefix is not UTF-8")?;
        let prefix = text.strip_suffix('\n').unwrap_or(text);
        anyhow::ensure!(
            !prefix.contains(['\n', '\r', '\0']),
            "Git target prefix contains unsupported control characters"
        );
        Ok(prefix.to_owned())
    }

    fn changed_paths(&self, base: &str, head: &str) -> Result<Vec<String>> {
        let body = self.output(
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--relative",
                "--name-only",
                "-z",
                base,
                head,
                "--",
                ".",
            ],
            self.limits.max_git_output_bytes,
        )?;
        parse_changed_paths(&body)
    }
}

fn comparison_command(target: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args)
        .current_dir(target);
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_COUNT",
    ] {
        command.env_remove(key);
    }
    command
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn parse_commit(body: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(body)
        .context("Git commit identity is not UTF-8")?
        .trim();
    anyhow::ensure!(
        [40, 64].contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Expected one exact Git commit identity"
    );
    Ok(text.to_owned())
}

fn parse_changed_paths(body: &[u8]) -> Result<Vec<String>> {
    anyhow::ensure!(
        body.is_empty() || body.last() == Some(&0),
        "Git path output has incomplete NUL framing"
    );
    body.split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(parse_path)
        .collect()
}

fn parse_path(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes)
        .context("A changed Git path is not UTF-8; comparison withheld")?;
    let path = Path::new(text);
    anyhow::ensure!(
        !path.is_absolute() && !path.components().any(|part| part == Component::ParentDir),
        "Changed Git path escapes the selected target"
    );
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests;
