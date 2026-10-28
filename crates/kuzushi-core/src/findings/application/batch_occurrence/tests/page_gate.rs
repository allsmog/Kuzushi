use super::*;
use crate::findings::{read_finding_page_snapshot, FindingListFilter, FindingPageRequest};

fn fixture() -> (tempfile::TempDir, FindingStore) {
    let target = tempfile::tempdir().unwrap();
    let sarif = target.path().join("owned.sarif");
    let policy = gate_policy(sarif.clone());
    seed_batch_documents_with_policy(target.path(), policy.clone());
    let store = gate_fixture_store(target.path());
    std::fs::write(sarif, b"owned receipt fixture").unwrap();
    persist_current_gate(target.path(), &store, &policy);
    (target, store)
}

fn snapshot(
    target: &Path,
    store: &FindingStore,
    cursor: Option<String>,
) -> crate::findings::FindingPageSnapshot {
    let workspace = crate::WorkspaceTarget::new(target).unwrap();
    let filter =
        FindingListFilter::from_tool_input(&json!({"batchId":"batch-test","limit":1})).unwrap();
    read_finding_page_snapshot(
        store,
        &workspace,
        &filter,
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest {
            cursor,
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn an_authenticated_severity_receipt_survives_a_finding_membership_read() {
    let (target, store) = fixture();
    let strict = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap();
    let read = snapshot(target.path(), &store, None);
    assert_eq!(read.study.unwrap().gate, strict.gate);
    assert!(read.study_gate_error.is_none());
}

#[test]
fn a_queue_update_between_membership_and_assessment_requests_one_fresh_read() {
    let (target, store) = fixture();
    let mut earlier =
        derive_batch_occurrence_report_for_controller(target.path(), "batch-test", &store).unwrap();
    let path =
        crate::capabilities::campaign::campaign_dir(target.path(), "batch-test").join("queue.json");
    let mut queue: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    queue["jobs"]["trial-003"]["state"] = json!("completed");
    std::fs::write(path, serde_json::to_vec(&queue).unwrap()).unwrap();
    let policy = gate_policy(target.path().join("owned.sarif"));
    persist_current_gate(target.path(), &store, &policy);

    let error = hydrate_report_gate(target.path(), &store, &mut earlier).unwrap_err();
    assert!(error.is::<BatchReceiptPending>(), "{error:#}");
    assert!(earlier.gate.is_none());
    let fresh = snapshot(target.path(), &store, None);
    assert!(fresh.study_gate_error.is_none());
    let report = fresh.study.unwrap();
    assert_eq!(report.completed, 3);
    assert!(report.gate.is_some());
}

#[test]
fn a_completed_queue_waits_for_its_owned_assessment_publication() {
    let (target, store) = fixture();
    let _lease =
        crate::capabilities::campaign::acquire_batch_controller_lease(target.path(), "batch-test")
            .unwrap();
    let path =
        crate::capabilities::campaign::campaign_dir(target.path(), "batch-test").join("queue.json");
    let mut queue: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    queue["jobs"]["trial-003"]["state"] = json!("completed");
    std::fs::write(path, serde_json::to_vec(&queue).unwrap()).unwrap();
    let mut current =
        derive_batch_occurrence_report_for_controller(target.path(), "batch-test", &store).unwrap();
    let error = hydrate_report_gate(target.path(), &store, &mut current).unwrap_err();
    assert!(error.is::<BatchReceiptPending>(), "{error:#}");
    assert!(current.gate.is_none());
    let policy = gate_policy(target.path().join("owned.sarif"));
    persist_current_gate(target.path(), &store, &policy);
    let fresh = snapshot(target.path(), &store, None);
    assert!(fresh.study_gate_error.is_none());
    assert_eq!(fresh.study.unwrap().completed, 3);
}

#[test]
fn stale_assessment_is_explicit_without_blocking_authenticated_finding_triage() {
    let (target, store) = fixture();
    let finding = Finding::new_tool(
        "owned",
        "policy",
        "owned.rs",
        1,
        None,
        Severity::High,
        "Owned marker",
    );
    store.insert_finding("run-trial-1-a2", &finding).unwrap();
    let read = snapshot(target.path(), &store, None);
    assert_eq!(read.page.page.total, 1);
    assert!(read.study.unwrap().gate.is_none());
    assert!(read
        .study_gate_error
        .unwrap()
        .contains("batch gate is stale"));
    assert!(derive_batch_occurrence_report(target.path(), "batch-test", &store).is_err());
}

#[test]
fn malformed_and_absent_receipts_remain_distinct_and_never_reuse_an_old_assessment() {
    let (target, store) = fixture();
    let _lease =
        crate::capabilities::campaign::acquire_batch_controller_lease(target.path(), "batch-test")
            .unwrap();
    let path =
        crate::capabilities::campaign::campaign_dir(target.path(), "batch-test").join("gate.json");
    std::fs::write(&path, b"not json").unwrap();
    let malformed = snapshot(target.path(), &store, None);
    assert!(malformed.study.unwrap().gate.is_none());
    assert!(malformed
        .study_gate_error
        .unwrap()
        .contains("assessment unavailable"));
    assert!(derive_batch_occurrence_report(target.path(), "batch-test", &store).is_err());
    std::fs::remove_file(path).unwrap();
    let absent = snapshot(target.path(), &store, None);
    assert!(absent.study.unwrap().gate.is_none());
    assert!(absent.study_gate_error.is_none());
}

#[test]
fn receipt_metadata_does_not_invalidate_an_unchanged_membership_cursor() {
    let (target, store) = fixture();
    for index in 0..3 {
        let finding = Finding::new_tool(
            "owned",
            &format!("policy-{index}"),
            "owned.rs",
            index + 1,
            None,
            Severity::Info,
            "Owned marker",
        );
        store.insert_finding("run-trial-1-a2", &finding).unwrap();
    }
    let first = snapshot(target.path(), &store, None);
    let mut gate = first.study.unwrap().gate.unwrap();
    gate.recorded_at_ms += 1;
    crate::capabilities::campaign::persist_batch_gate_outcome(target.path(), &gate).unwrap();
    let second = snapshot(target.path(), &store, first.page.page.next_cursor);
    assert_eq!(second.page.page.total, 3);
    assert_eq!(second.page.page.offset, 1);
    assert_eq!(second.study.unwrap().gate.unwrap(), gate);
    assert!(second.study_gate_error.is_none());
}
