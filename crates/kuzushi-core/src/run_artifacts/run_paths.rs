use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub fn new_run_id(prefix: &str) -> String {
    let prefix = sanitize_run_id_prefix(prefix);
    let prefix = if prefix.is_empty() {
        "run"
    } else {
        prefix.as_str()
    };
    let suffix = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}-{}", now_unix_millis(), &suffix[..12])
}

pub fn runs_root(target: impl AsRef<Path>) -> PathBuf {
    kuzushi_root(target).join("runs")
}

pub fn run_dir(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    runs_root(target).join(run_id)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RunId(String);

impl RunId {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() || value.len() > 200 {
            anyhow::bail!("run id must contain between 1 and 200 characters");
        }
        let mut chars = value.chars();
        if !chars.next().is_some_and(|ch| ch.is_ascii_alphanumeric()) {
            anyhow::bail!("run id must start with an ASCII letter or digit: {value:?}");
        }
        if !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')) {
            anyhow::bail!("run id contains a path separator or unsupported character: {value:?}");
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactPath(PathBuf);

impl ArtifactPath {
    pub fn parse(value: impl AsRef<Path>) -> Result<Self> {
        let value = value.as_ref();
        let components = value.components().collect::<Vec<_>>();
        if components.is_empty()
            || components
                .iter()
                .any(|item| !matches!(item, Component::Normal(_)))
        {
            anyhow::bail!(
                "run artifact path must be a non-empty relative path: {}",
                value.display()
            );
        }
        Ok(Self(value.to_path_buf()))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

pub(crate) fn checked_runs_root(target: impl AsRef<Path>) -> Result<PathBuf> {
    crate::workspace::validated_workspace_descendant(target, run_state_relative_path("runs"))
}

pub(crate) fn ensure_run_dir(target: impl AsRef<Path>, run_id: &str) -> Result<PathBuf> {
    let target = target.as_ref();
    let run_id = RunId::parse(run_id)?;
    crate::workspace::initialize_workspace_state(target)?;
    let relative = run_state_relative_path("runs").join(run_id.as_str());
    let candidate = crate::workspace::validated_workspace_descendant(target, &relative)?;
    let is_new = matches!(
        std::fs::symlink_metadata(&candidate),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    if !is_new {
        return crate::workspace::ensure_workspace_descendant_dir(target, relative);
    }
    create_indexed_run_dir(target, relative, &candidate, run_id.as_str())
}

fn create_indexed_run_dir(
    target: &Path,
    relative: PathBuf,
    candidate: &Path,
    run_id: &str,
) -> Result<PathBuf> {
    let history_guard = prepared_history_guard_for_new_run(target, candidate);
    if candidate.exists() {
        return crate::workspace::ensure_workspace_descendant_dir(target, relative);
    }
    crate::workspace::ensure_workspace_descendant_dir(target, run_state_relative_path("runs"))?;
    let created = create_run_directory(candidate)?;
    if !created {
        let _ = super::run_history_index::mark_run_history_dirty_best_effort(target);
        return crate::workspace::ensure_workspace_descendant_dir(target, relative);
    }
    super::run_history_index::record_run_directory_best_effort(
        target,
        run_id,
        history_guard.as_ref(),
    );
    Ok(candidate.to_path_buf())
}

fn prepared_history_guard_for_new_run(
    target: &Path,
    candidate: &Path,
) -> Option<crate::file_lock::ExclusiveFileLock> {
    let guard = super::run_ledger::acquire_run_history_index_lock(target).ok()?;
    if candidate.exists() {
        return Some(guard);
    }
    super::run_history_index::prepare_run_history_update_under_lock(target, &guard).ok()?;
    Some(guard)
}

fn create_run_directory(path: &Path) -> Result<bool> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("Could not create run directory {}", path.display()))
        }
    }
}

pub(crate) fn checked_run_artifact_path(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: impl AsRef<Path>,
) -> Result<PathBuf> {
    let run_id = RunId::parse(run_id)?;
    let artifact = ArtifactPath::parse(artifact)?;
    crate::workspace::validated_workspace_descendant(
        target,
        run_state_relative_path("runs")
            .join(run_id.as_str())
            .join(artifact.as_path()),
    )
}

pub(crate) fn ensure_run_artifact_parent(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: impl AsRef<Path>,
) -> Result<PathBuf> {
    let target = target.as_ref();
    let run_id = RunId::parse(run_id)?;
    let artifact = ArtifactPath::parse(artifact)?;
    ensure_run_dir(target, run_id.as_str())?;
    let parent = artifact.as_path().parent().unwrap_or_else(|| Path::new(""));
    let relative = run_state_relative_path("runs")
        .join(run_id.as_str())
        .join(parent);
    crate::workspace::ensure_workspace_descendant_dir(target, relative)
}

pub(crate) fn checked_latest_run_path(target: impl AsRef<Path>) -> Result<PathBuf> {
    crate::workspace::validated_workspace_descendant(target, run_state_relative_path("latest"))
}

pub(crate) fn checked_run_history_index_path(target: impl AsRef<Path>) -> Result<PathBuf> {
    crate::workspace::validated_workspace_descendant(
        target,
        run_state_relative_path("run-history.index.sqlite3"),
    )
}

pub(crate) fn checked_legacy_run_history_index_path(target: impl AsRef<Path>) -> Result<PathBuf> {
    crate::workspace::validated_workspace_descendant(
        target,
        run_state_relative_path("run-history.index.jsonl"),
    )
}

pub(crate) fn checked_run_history_dirty_path(target: impl AsRef<Path>) -> Result<PathBuf> {
    crate::workspace::validated_workspace_descendant(
        target,
        run_state_relative_path("run-history.index.dirty"),
    )
}

fn run_state_relative_path(leaf: impl Into<OsString>) -> PathBuf {
    PathBuf::from(crate::workspace::KUZUSHI_STATE_DIR)
        .join(crate::workspace::WORKSPACE_STATE_VERSION_DIR)
        .join(leaf.into())
}

pub fn run_artifact_path(
    target: impl AsRef<Path>,
    run_id: &str,
    leaf: impl AsRef<Path>,
) -> PathBuf {
    run_dir(target, run_id).join(leaf)
}

pub fn kuzushi_root(target: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_root(target)
        .join(crate::workspace::WORKSPACE_STATE_VERSION_DIR)
}

pub fn latest_run_path(target: impl AsRef<Path>) -> PathBuf {
    kuzushi_root(target).join("latest")
}

fn sanitize_run_id_prefix(prefix: &str) -> String {
    prefix
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase()
}

fn now_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_run_ids_embed_millisecond_ordering_time() {
        let run_id = new_run_id("run");
        let (without_suffix, _) = run_id.rsplit_once('-').unwrap();
        let (_, timestamp) = without_suffix.rsplit_once('-').unwrap();

        assert!(timestamp.parse::<u128>().unwrap() >= 1_000_000_000_000);
    }

    #[test]
    fn run_artifact_paths_use_workspace_v3_state_dir() {
        let target = Path::new("/repo");

        assert_eq!(
            kuzushi_root(target),
            crate::workspace::workspace_state_dir(target)
        );
        assert_eq!(
            runs_root(target),
            crate::workspace::workspace_state_dir(target).join("runs")
        );
        assert_eq!(
            latest_run_path(target),
            crate::workspace::workspace_state_dir(target).join("latest")
        );
        assert_eq!(
            run_artifact_path(target, "run-123", "failures.json"),
            crate::workspace::workspace_state_dir(target)
                .join("runs")
                .join("run-123")
                .join("failures.json")
        );
    }
}
