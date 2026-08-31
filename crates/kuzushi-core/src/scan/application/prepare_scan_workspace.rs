use crate::findings::FindingStore;
use crate::suppressions::SuppressionReconcileSummary;
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use std::fmt::Display;

/// Scan-start workspace preparation outcome. Both the suppression sweep and
/// source-tree identity registration are load-bearing: a scan must not begin
/// if either cannot be established. `tree_identity_warning` is retained for
/// compatibility with callers compiled against the existing shape, but is
/// always `None` because identity loss now aborts preparation instead of
/// degrading to a transient warning.
pub struct ScanWorkspacePreparation {
    pub suppressions: SuppressionReconcileSummary,
    pub tree_identity_warning: Option<String>,
}

pub fn prepare_scan_workspace_state(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
) -> Result<ScanWorkspacePreparation> {
    prepare_scan_workspace_state_with_observer(workspace, store, &mut |_| {})
}

/// Same preparation with a per-file observer over the tree-identity walk:
/// the walk full-content-hashes every file (minutes on monorepos), and the
/// caller's progress surface must show heartbeats instead of going silent
/// before the scan starts.
pub fn prepare_scan_workspace_state_with_observer(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    on_files_hashed: &mut dyn FnMut(usize),
) -> Result<ScanWorkspacePreparation> {
    register_scan_tree_identity(workspace, on_files_hashed)?;
    let suppressions =
        crate::suppressions::run_suppression_sweep(store, workspace, "system:scan-start")
            .map(|sweep| sweep.summary)
            .context("suppression sweep failed at scan start; refusing to use stale state")?;
    Ok(ScanWorkspacePreparation {
        suppressions,
        tree_identity_warning: None,
    })
}

/// A scan without a registered tree identity cannot later prove which source
/// tree its findings came from. Treat that as a preparation failure rather
/// than running successfully with unverifiable provenance.
fn register_scan_tree_identity(
    workspace: &WorkspaceTarget,
    on_files_hashed: &mut dyn FnMut(usize),
) -> Result<()> {
    require_scan_tree_identity(
        crate::incremental_index::register_workspace_tree_identity_with_observer(
            workspace,
            on_files_hashed,
        ),
    )
}

fn require_scan_tree_identity<T, E>(result: std::result::Result<T, E>) -> Result<()>
where
    E: Display,
{
    result.map(|_| ()).map_err(|error| {
        anyhow::anyhow!(
            "workspace tree identity unavailable; refusing to start scan without verifiable source provenance: {error}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_with_source(target: &tempfile::TempDir) -> WorkspaceTarget {
        std::fs::create_dir_all(target.path().join("src")).unwrap();
        std::fs::write(target.path().join("src/lib.rs"), "pub fn ready() {}\n").unwrap();
        WorkspaceTarget::new(target.path()).unwrap()
    }

    #[test]
    fn preparation_registers_tree_identity_without_content_blobs() {
        let target = tempfile::tempdir().unwrap();
        let workspace = workspace_with_source(&target);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();

        let preparation = prepare_scan_workspace_state(&workspace, &store).unwrap();

        assert!(preparation.suppressions.is_noop());
        assert!(preparation.tree_identity_warning.is_none());
        let connection = rusqlite::Connection::open(workspace.findings_db_path()).unwrap();
        let snapshot_count: i64 = connection
            .query_row("select count(*) from target_snapshots", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(snapshot_count, 1);
        let indexed_file_count: i64 = connection
            .query_row("select count(*) from indexed_files", [], |row| row.get(0))
            .unwrap();
        assert_eq!(indexed_file_count, 0);
    }

    #[test]
    fn identity_registration_failure_is_a_scan_preparation_error() {
        let error = require_scan_tree_identity::<(), _>(Err("source file could not be hashed"))
            .expect_err("missing tree identity must fail closed");

        let message = error.to_string();
        assert!(message.contains("workspace tree identity unavailable"));
        assert!(message.contains("refusing to start scan without verifiable source provenance"));
        assert!(message.contains("source file could not be hashed"));
    }
}
