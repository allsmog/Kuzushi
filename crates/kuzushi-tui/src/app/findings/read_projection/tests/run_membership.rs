use super::*;

#[test]
fn middle_run_membership_matches_authoritative_observations() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    record_repeated_finding(&store, root.path());
    for policy in [
        IdentityFoldPolicy::Legacy,
        IdentityFoldPolicy::Safe,
        IdentityFoldPolicy::Aggressive,
    ] {
        let authoritative = store
            .list_distinct_findings_for_scan_ids_with_identity_policy(&["run-middle"], policy)
            .unwrap();
        assert_eq!(authoritative.len(), 1);
        let (corpus, issue) =
            read_corpus(&store, root.path(), policy, Some(&["run-middle".into()])).unwrap();
        assert!(issue.is_none(), "{issue:?}");
        assert_eq!(
            corpus.len(),
            1,
            "{policy:?}: selected middle observation disappeared"
        );
    }
}

fn record_repeated_finding(store: &FindingStore, root: &Path) {
    let finding = Finding::new_tool(
        "owned",
        "repeat",
        "owned.rs",
        1,
        None,
        kuzushi_core::Severity::Low,
        "Repeated inert source observation",
    );
    for run in ["run-first", "run-middle", "run-last"] {
        store.record_run_started(run, root, "running").unwrap();
        store.insert_finding(run, &finding).unwrap();
        store.record_run_finished(run, "completed", 1).unwrap();
    }
}
