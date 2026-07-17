use crate::findings::FindingStore;
use crate::suppressions::SuppressionReconcileSummary;
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};

pub fn prepare_scan_workspace_state(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
) -> Result<SuppressionReconcileSummary> {
    crate::incremental_index::index_workspace_snapshot(workspace)
        .context("could not prepare the shared workspace index before scan")?;
    crate::suppressions::run_suppression_sweep(store, workspace, "system:scan-start")
        .map(|sweep| sweep.summary)
        .context("suppression sweep failed at scan start; refusing to use stale state")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_indexes_workspace_and_reconciles_suppressions() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("src")).unwrap();
        std::fs::write(target.path().join("src/lib.rs"), "pub fn ready() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();

        let summary = prepare_scan_workspace_state(&workspace, &store).unwrap();

        assert!(summary.is_noop());
        let connection = rusqlite::Connection::open(workspace.findings_db_path()).unwrap();
        let snapshot_count: i64 = connection
            .query_row("select count(*) from target_snapshots", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(snapshot_count, 1);
    }
}
