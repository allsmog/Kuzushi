use super::proof_cache::{self, PolicySnapshot};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

mod command;
mod config_inputs;
mod inputs;

use command::{
    canonical_git_path, command_failure, command_is_missing, configured_global_exclude, git_output,
    resolved_git_path,
};
use config_inputs::config_policy_inputs;
use inputs::git_marker_paths;

pub(super) const GENERATED_PROBES: &[&str] = &[
    ".kuzushi/.gitignore",
    ".kuzushi/v3/latest",
    ".kuzushi/v3/run-history.index.sqlite3",
    ".kuzushi/v3/run-history.index.dirty",
    ".kuzushi/v3/index.sqlite3",
    ".kuzushi/v3/log/kuzushi-ignore-probe/event.json",
    ".kuzushi/v3/objects/kuzushi-ignore-probe",
    ".kuzushi/v3/runs/kuzushi-ignore-probe/summary.json",
    ".kuzushi/worktrees/kuzushi-ignore-probe/source.rs",
];
pub(super) const TRACKABLE_PROBES: &[&str] = &[
    ".kuzushi/scope.toml",
    ".kuzushi/prompts/kuzushi-ignore-probe.md",
    ".kuzushi/v3/config.toml",
];

pub(super) fn validate_effective_policy(root: &Path) -> Result<PolicySnapshot> {
    let Some(context) = discover_git_context(root)? else {
        return proof_cache::capture(git_marker_paths(root));
    };
    let paths = context.policy_inputs(root)?;
    let before = proof_cache::capture(paths.clone())?;
    validate_probes(root)?;
    let current_context = discover_git_context(root)?.context(
        "Git repository identity disappeared while Kuzushi was validating its ignore policy",
    )?;
    anyhow::ensure!(
        context == current_context,
        "Git repository identity changed while Kuzushi was validating its ignore policy; retry"
    );
    let after = proof_cache::capture(current_context.policy_inputs(root)?)?;
    anyhow::ensure!(
        before == after,
        "Git ignore inputs changed while Kuzushi was validating them; retry"
    );
    Ok(after)
}

#[derive(Debug, PartialEq, Eq)]
struct GitContext {
    repository_root: PathBuf,
    git_dir: PathBuf,
    common_dir: PathBuf,
    info_exclude: PathBuf,
    configured_global_exclude: Option<PathBuf>,
    config_inputs: Vec<PathBuf>,
}

impl GitContext {
    fn discover(root: &Path) -> Result<Self> {
        Ok(Self {
            repository_root: canonical_git_path(root, &["rev-parse", "--show-toplevel"])?,
            git_dir: canonical_git_path(root, &["rev-parse", "--absolute-git-dir"])?,
            common_dir: resolved_git_path(root, &["rev-parse", "--git-common-dir"])?,
            info_exclude: resolved_git_path(root, &["rev-parse", "--git-path", "info/exclude"])?,
            configured_global_exclude: configured_global_exclude(root)?,
            config_inputs: config_policy_inputs(root)?,
        })
    }
}

fn discover_git_context(root: &Path) -> Result<Option<GitContext>> {
    let output = match git_output(
        root,
        &["rev-parse", "--is-inside-work-tree"],
        "Git worktree probe",
    ) {
        Ok(output) => output,
        Err(error) if command_is_missing(&error) => {
            return no_git_marker_or_error(root, &format!("{error:#}"))
        }
        Err(error) => return Err(error).context("Could not inspect workspace Git context"),
    };
    if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true" {
        return GitContext::discover(root).map(Some);
    }
    no_git_marker_or_error(root, &command_failure(&output))
}

fn validate_probes(root: &Path) -> Result<()> {
    let mut arguments = vec!["check-ignore", "--no-index", "--"];
    arguments.extend(GENERATED_PROBES.iter().copied());
    arguments.extend(TRACKABLE_PROBES.iter().copied());
    let output = git_output(root, &arguments, "Git ignore proof")
        .context("Could not run the Git ignore proof")?;
    anyhow::ensure!(
        matches!(output.status.code(), Some(0 | 1)),
        "git check-ignore failed: {}",
        command_failure(&output)
    );
    let ignored = std::str::from_utf8(&output.stdout)
        .context("git check-ignore returned non-UTF-8 probe paths")?
        .lines()
        .map(str::to_string)
        .collect::<HashSet<_>>();
    for path in GENERATED_PROBES {
        ensure_generated_probe_is_ignored(&ignored, path)?;
    }
    for path in TRACKABLE_PROBES {
        ensure_trackable_probe_is_visible(&ignored, path)?;
    }
    Ok(())
}

fn ensure_generated_probe_is_ignored(ignored: &HashSet<String>, path: &str) -> Result<()> {
    if !ignored.contains(path) {
        anyhow::bail!(
            "Effective Git ignore policy does not exclude generated workspace path `{path}`; update .kuzushi/.gitignore"
        );
    }
    Ok(())
}

fn ensure_trackable_probe_is_visible(ignored: &HashSet<String>, path: &str) -> Result<()> {
    if ignored.contains(path) {
        anyhow::bail!(
            "Effective Git ignore policy hides trackable workspace path `{path}`; update parent and .kuzushi ignore rules"
        );
    }
    Ok(())
}

fn no_git_marker_or_error(root: &Path, reason: &str) -> Result<Option<GitContext>> {
    if has_git_marker(root)? {
        anyhow::bail!("Could not prove workspace ignore policy in its Git worktree: {reason}");
    }
    Ok(None)
}

fn has_git_marker(root: &Path) -> Result<bool> {
    for path in git_marker_paths(root) {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Could not inspect Git marker {}", path.display()))
            }
        }
    }
    Ok(false)
}
