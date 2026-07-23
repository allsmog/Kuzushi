use crate::findings::FindingStore;
use crate::suppressions::SuppressionReconcileSummary;
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};

/// Scan-start workspace preparation outcome. The suppression sweep is
/// load-bearing (its failure aborts the scan); the tree identity exists for
/// provenance only and degrades to an operator-visible warning.
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
    let tree_identity_warning = register_scan_tree_identity(workspace, on_files_hashed);
    let suppressions =
        crate::suppressions::run_suppression_sweep(store, workspace, "system:scan-start")
            .map(|sweep| sweep.summary)
            .context("suppression sweep failed at scan start; refusing to use stale state")?;
    Ok(ScanWorkspacePreparation {
        suppressions,
        tree_identity_warning,
    })
}

/// Scan provenance needs a verifiable tree identity, not a full content
/// index: the hash-only registration fits monorepo-scale targets whose file
/// count blows the blob-store budget, and losing the identity costs
/// verification of this scan's provenance only — never the scan itself.
fn register_scan_tree_identity(
    workspace: &WorkspaceTarget,
    on_files_hashed: &mut dyn FnMut(usize),
) -> Option<String> {
    crate::incremental_index::register_workspace_tree_identity_with_observer(
        workspace,
        on_files_hashed,
    )
    .err()
    .map(|error| format!("workspace tree identity unavailable for this scan: {error:#}"))
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

    #[cfg(unix)]
    #[test]
    fn identity_loss_degrades_to_a_warning_instead_of_aborting_the_scan() {
        use std::os::unix::fs::PermissionsExt;
        let target = tempfile::tempdir().unwrap();
        let workspace = workspace_with_source(&target);
        let unreadable = target.path().join("src/secret.rs");
        std::fs::write(&unreadable, "pub fn hidden() {}\n").unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();

        let preparation = prepare_scan_workspace_state(&workspace, &store).unwrap();

        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(preparation.suppressions.is_noop());
        let warning = preparation.tree_identity_warning.expect("warning");
        assert!(warning.contains("workspace tree identity unavailable"));
    }
}
