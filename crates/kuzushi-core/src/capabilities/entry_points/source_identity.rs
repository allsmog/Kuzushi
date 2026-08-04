use super::domain::{ContextSnapshotIdentity, EntryPointCatalog};
use super::persistence::read_context_snapshot;
use anyhow::{Context, Result};
use std::path::Path;

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
        (Some(revision), Some(current)) => {
            anyhow::ensure!(revision == current.sha, "context snapshot revision is stale");
            anyhow::ensure!(
                snapshot.revision_dirty == Some(current.dirty),
                "context snapshot dirty state is stale"
            );
        }
        (None, None) => anyhow::ensure!(
            snapshot.revision_dirty.is_none(),
            "context snapshot repository identity is stale"
        ),
        _ => anyhow::bail!(
            "context snapshot repository identity is unavailable or stale; run `context:build`"
        ),
    }
    Ok(())
}

fn validate_current_tree_identity(
    target: &Path,
    snapshot: &ContextSnapshotIdentity,
) -> Result<()> {
    let expected = snapshot.tree_hash.as_deref().with_context(|| {
        "dirty or non-Git context snapshot has no treeHash; run `context:build`"
    })?;
    let current = crate::incremental_index::current_workspace_tree_hash(target)
        .context("Could not authenticate the current target tree")?;
    anyhow::ensure!(expected == current, "context snapshot tree identity is stale");
    Ok(())
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
