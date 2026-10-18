//! Prepare related export reads at one ledger revision before publishing files.
use crate::{FindingStore, WorkspaceTarget};
use anyhow::Result;

#[derive(Clone, Copy, PartialEq, Eq)]
struct ExportReadRevision {
    projection: crate::storage_v3::ProjectionMeta,
    changes: i64,
}

fn read_revision(store: &FindingStore) -> Result<ExportReadRevision> {
    Ok(ExportReadRevision {
        projection: store.projection_meta()?,
        changes: store.read_change_version()?,
    })
}

pub(super) fn with_export_revision<T>(
    workspace: &WorkspaceTarget,
    prepare: impl FnOnce(&FindingStore) -> Result<T>,
) -> Result<T> {
    let store = FindingStore::open(workspace.findings_db_path())?;
    let before = read_revision(&store)?;
    let prepared = store.with_projection_snapshot(prepare)?;
    let after = read_revision(&store)?;
    require_same_revision(before, after)?;
    Ok(prepared)
}

fn require_same_revision(before: ExportReadRevision, after: ExportReadRevision) -> Result<()> {
    anyhow::ensure!(before == after,
        "Findings changed while preparing the export. No new export was published. Refresh Report and retry.");
    Ok(())
}

#[cfg(test)]
mod tests;
