use super::domain::{ContextSnapshotIdentity, EntryPointCatalog};
use super::persistence::read_context_snapshot;
use anyhow::{Context, Result};
use std::path::Path;

/// The context snapshot still parses, but it no longer describes the current
/// target. Producers (`entry-points:extract`, `threat-model:build`) refuse on
/// it; verification recognizes it and degrades to an ungrounded surface scan
/// instead of dying. Genuine I/O or corruption never carries this type.
#[derive(Debug)]
pub(super) struct StaleContextSnapshotSource(String);

impl StaleContextSnapshotSource {
    fn error(message: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(Self(message.into()))
    }
}

impl std::fmt::Display for StaleContextSnapshotSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StaleContextSnapshotSource {}

/// The stale-source disclosure behind an error, when there is one.
pub(super) fn stale_source_disclosure(error: &anyhow::Error) -> Option<String> {
    error
        .downcast_ref::<StaleContextSnapshotSource>()
        .map(StaleContextSnapshotSource::to_string)
}

fn stale_unless(is_current: bool, message: &str) -> Result<()> {
    if is_current {
        return Ok(());
    }
    Err(StaleContextSnapshotSource::error(message))
}

pub(super) fn validate_current_source_identity(
    target: &Path,
    snapshot: &ContextSnapshotIdentity,
) -> Result<()> {
    let current = crate::workspace::target_git_metadata(target);
    validate_current_git_identity(snapshot, current.as_ref())?;
    if current.as_ref().is_none_or(|git| git.dirty) {
        validate_current_tree_identity(target, snapshot)?;
    }
    Ok(())
}

pub(super) fn validate_catalog_source_identity(
    target: &Path,
    catalog: &EntryPointCatalog,
) -> Result<()> {
    let identity = ContextSnapshotIdentity {
        target: catalog.target.clone(),
        timestamp: catalog.snapshot_timestamp,
        sha256: catalog.provenance.context_snapshot_sha256.clone(),
        revision: catalog.provenance.revision.clone(),
        revision_dirty: catalog.provenance.revision_dirty,
        tree_hash: catalog.provenance.context_snapshot_tree_hash.clone(),
    };
    validate_current_source_identity(target, &identity)
}

fn validate_current_git_identity(
    snapshot: &ContextSnapshotIdentity,
    current: Option<&crate::run_artifacts::RunTargetGitMetadata>,
) -> Result<()> {
    match (snapshot.revision.as_deref(), current) {
        (Some(revision), Some(current)) => validate_matched_git_identity(snapshot, revision, current),
        (None, None) => stale_unless(
            snapshot.revision_dirty.is_none(),
            "context snapshot repository identity is stale",
        ),
        _ => Err(StaleContextSnapshotSource::error(
            "context snapshot repository identity is unavailable or stale; run `context:build`",
        )),
    }
}

fn validate_matched_git_identity(
    snapshot: &ContextSnapshotIdentity,
    revision: &str,
    current: &crate::run_artifacts::RunTargetGitMetadata,
) -> Result<()> {
    stale_unless(revision == current.sha, "context snapshot revision is stale")?;
    stale_unless(
        snapshot.revision_dirty == Some(current.dirty),
        "context snapshot dirty state is stale",
    )
}

fn validate_current_tree_identity(
    target: &Path,
    snapshot: &ContextSnapshotIdentity,
) -> Result<()> {
    let Some(expected) = snapshot.tree_hash.as_deref() else {
        return Err(StaleContextSnapshotSource::error(
            "dirty or non-Git context snapshot has no treeHash; run `context:build`",
        ));
    };
    let current = crate::incremental_index::current_workspace_tree_hash(target)
        .context("Could not authenticate the current target tree")?;
    stale_unless(expected == current, "context snapshot tree identity is stale")
}

pub(super) fn revalidate_snapshot_source(
    target: &Path,
    expected: &ContextSnapshotIdentity,
) -> Result<()> {
    let latest = read_context_snapshot(target)?
        .context("context snapshot disappeared while resolving entry points")?;
    anyhow::ensure!(
        latest.identity == *expected,
        "context snapshot changed while resolving entry points"
    );
    validate_current_source_identity(target, &latest.identity)
}
