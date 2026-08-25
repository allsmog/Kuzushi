//! Kuzushi context boundary.
//!
//! Repository context is deterministic input for scanners, threat modeling,
//! recommender planning, and reports. It should remain free of LLM dispatch and
//! UI rendering concerns.

use serde_json::Value;
use std::path::{Path, PathBuf};

pub use crate::repository_inventory::*;
pub use crate::static_context::*;

pub const CONTEXT_SNAPSHOT_FILE: &str = "context-snapshot.json";

/// Maximum size of Kuzushi's canonical repository-context artifact.
///
/// Context snapshots intentionally carry inventory and attack-surface data and
/// can exceed ordinary prompt-source limits on large repositories. Producers
/// and consumers must share this artifact bound; prompt construction applies
/// its smaller, operator-configured limit after the JSON is parsed.
pub const MAX_CONTEXT_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

pub fn context_snapshot_path(target: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(CONTEXT_SNAPSHOT_FILE)
}

/// Whether a persisted context snapshot can describe the target that is
/// active now. `Unverifiable` is deliberately distinct from `Stale`: legacy
/// snapshots can be readable without carrying enough identity to authorize
/// reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextSnapshotFreshness {
    Current,
    Stale(String),
    Unverifiable(String),
}

impl ContextSnapshotFreshness {
    pub fn is_current(&self) -> bool {
        matches!(self, Self::Current)
    }

    pub fn disclosure(&self) -> Option<&str> {
        match self {
            Self::Current => None,
            Self::Stale(reason) | Self::Unverifiable(reason) => Some(reason),
        }
    }
}

/// Authenticate snapshot provenance against the current target. Call this at
/// hydration / execution boundaries rather than from a per-frame renderer:
/// dirty and non-Git targets require a content-tree hash.
pub fn context_snapshot_freshness(target: &Path, snapshot: &Value) -> ContextSnapshotFreshness {
    if let Some(freshness) = target_path_freshness(target, snapshot) {
        return freshness;
    }
    let current = crate::workspace::target_git_metadata(target);
    match current.as_ref() {
        Some(git) => git_snapshot_freshness(target, snapshot, git),
        None => non_git_snapshot_freshness(target, snapshot),
    }
}

fn target_path_freshness(target: &Path, snapshot: &Value) -> Option<ContextSnapshotFreshness> {
    let recorded = snapshot.get("target")?.as_str()?.trim();
    if recorded.is_empty() || paths_refer_to_same_target(target, Path::new(recorded)) {
        return None;
    }
    Some(ContextSnapshotFreshness::Stale(format!(
        "snapshot target {} differs from active target {}",
        recorded,
        target.display()
    )))
}

fn paths_refer_to_same_target(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn git_snapshot_freshness(
    target: &Path,
    snapshot: &Value,
    current: &crate::run_artifacts::RunTargetGitMetadata,
) -> ContextSnapshotFreshness {
    let Some(revision) = snapshot_text(snapshot, "/provenance/revision") else {
        return ContextSnapshotFreshness::Unverifiable(
            "snapshot has no repository revision; run context:build".to_string(),
        );
    };
    if revision != current.sha {
        return ContextSnapshotFreshness::Stale(format!(
            "snapshot rev {} -> target {}",
            short_revision(revision),
            short_revision(&current.sha)
        ));
    }
    let Some(recorded_dirty) = snapshot
        .pointer("/provenance/revisionDirty")
        .and_then(Value::as_bool)
    else {
        return ContextSnapshotFreshness::Unverifiable(
            "snapshot has no repository dirty-state claim; run context:build".to_string(),
        );
    };
    if recorded_dirty != current.dirty {
        return ContextSnapshotFreshness::Stale(format!(
            "snapshot dirty state {} -> target {}",
            recorded_dirty, current.dirty
        ));
    }
    if current.dirty {
        tree_snapshot_freshness(target, snapshot)
    } else {
        ContextSnapshotFreshness::Current
    }
}

fn non_git_snapshot_freshness(target: &Path, snapshot: &Value) -> ContextSnapshotFreshness {
    if snapshot_text(snapshot, "/provenance/revision").is_some() {
        return ContextSnapshotFreshness::Stale(
            "snapshot records a Git revision but the active target is not a Git checkout"
                .to_string(),
        );
    }
    tree_snapshot_freshness(target, snapshot)
}

fn tree_snapshot_freshness(target: &Path, snapshot: &Value) -> ContextSnapshotFreshness {
    let Some(expected) = snapshot_text(snapshot, "/provenance/treeHash") else {
        return ContextSnapshotFreshness::Unverifiable(
            "snapshot has no content-tree identity; run context:build".to_string(),
        );
    };
    match crate::incremental_index::current_workspace_tree_hash(target) {
        Ok(actual) if expected == actual => ContextSnapshotFreshness::Current,
        Ok(_) => ContextSnapshotFreshness::Stale(
            "snapshot content tree differs from the active target".to_string(),
        ),
        Err(error) => ContextSnapshotFreshness::Unverifiable(format!(
            "could not authenticate the active target tree: {error:#}"
        )),
    }
}

fn snapshot_text<'a>(snapshot: &'a Value, pointer: &str) -> Option<&'a str> {
    snapshot
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn short_revision(revision: &str) -> &str {
    revision.get(..7).unwrap_or(revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn context_snapshot_path_uses_workspace_state_root() {
        let target = Path::new("/repo");
        let state_root = crate::workspace::workspace_state_root(target);

        assert_eq!(
            context_snapshot_path(target),
            state_root.join(CONTEXT_SNAPSHOT_FILE)
        );
    }

    #[test]
    fn non_git_snapshot_freshness_uses_the_content_tree() {
        let target = tempdir().unwrap();
        fs::write(target.path().join("source.rs"), "fn first() {}\n").unwrap();
        let tree_hash =
            crate::incremental_index::current_workspace_tree_hash(target.path()).unwrap();
        let snapshot = json!({
            "target": target.path(),
            "provenance": { "treeHash": tree_hash }
        });

        assert_eq!(
            context_snapshot_freshness(target.path(), &snapshot),
            ContextSnapshotFreshness::Current
        );

        fs::write(target.path().join("source.rs"), "fn changed() {}\n").unwrap();
        assert!(matches!(
            context_snapshot_freshness(target.path(), &snapshot),
            ContextSnapshotFreshness::Stale(_)
        ));
    }

    #[test]
    fn legacy_snapshot_without_tree_identity_is_unverifiable() {
        let target = tempdir().unwrap();
        fs::write(target.path().join("source.rs"), "fn first() {}\n").unwrap();
        let snapshot = json!({
            "target": target.path(),
            "provenance": {}
        });

        assert!(matches!(
            context_snapshot_freshness(target.path(), &snapshot),
            ContextSnapshotFreshness::Unverifiable(_)
        ));
    }

    #[test]
    fn snapshot_from_another_target_is_stale() {
        let target = tempdir().unwrap();
        let other = tempdir().unwrap();
        let snapshot = json!({
            "target": other.path(),
            "provenance": {}
        });

        let freshness = context_snapshot_freshness(target.path(), &snapshot);
        assert!(matches!(freshness, ContextSnapshotFreshness::Stale(_)));
        assert!(freshness
            .disclosure()
            .is_some_and(|reason| reason.contains("differs from active target")));
    }
}
