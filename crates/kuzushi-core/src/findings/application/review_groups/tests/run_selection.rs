use super::*;

#[test]
fn selected_middle_run_keeps_reobserved_identity_and_excludes_unrelated_history() {
    let (root, workspace, store, rows) = fixture();
    let mut latest_id = 0;
    for run in ["middle", "latest"] {
        store
            .record_run_started(run, root.path(), "completed")
            .unwrap();
        latest_id = store.insert_finding(run, &rows[0]).unwrap();
    }
    let page = read_finding_groups(
        &store,
        &workspace,
        &FindingGroupsRequest {
            run_ids: vec!["middle".into()],
            ..FindingGroupsRequest::first_page()
        },
    )
    .unwrap();
    assert_eq!((page.total_findings, page.total_groups), (1, 1));
    assert_eq!(page.groups[0].representative.finding_id, latest_id);
    assert_eq!(
        page.groups[0].representative.run_id.as_deref(),
        Some("latest")
    );
    assert!(store.list_all_review_decisions().unwrap().is_empty());
    assert_eq!(page.selected_run_ids, vec!["middle"]);
    assert_eq!(
        page.groups[0].representative.matching_run_ids,
        vec!["middle"]
    );
}

#[test]
fn selected_membership_is_sorted_unique_and_only_includes_requested_runs() {
    let (root, workspace, store, rows) = fixture();
    for run in ["middle", "latest"] {
        store
            .record_run_started(run, root.path(), "completed")
            .unwrap();
        store.insert_finding(run, &rows[0]).unwrap();
    }
    let page = read_finding_groups(
        &store,
        &workspace,
        &FindingGroupsRequest {
            run_ids: vec!["middle".into(), "latest".into(), "middle".into()],
            ..FindingGroupsRequest::first_page()
        },
    )
    .unwrap();
    assert_eq!(page.selected_run_ids, vec!["latest", "middle"]);
    assert_eq!(
        page.groups[0].representative.matching_run_ids,
        vec!["latest", "middle"]
    );
    assert_eq!(page.total_findings, 1);
}
