use super::*;
use crate::findings::{FindingStore, TriageAuthor, TriageOutcome, TriageVerdict};
use crate::run_lifecycle::RunItemStatus;
use crate::{ScanCancellation, V2Config, WorkspaceTarget};

fn context<'a>(
    workspace: &'a WorkspaceTarget,
    store: &'a FindingStore,
    config: &'a V2Config,
    cancellation: Option<&'a ScanCancellation>,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: None,
        cancellation,
        authorization: Default::default(),
    }
}

fn observation() -> Finding {
    Finding::new_tool(
        "taint-iris-next",
        "owned-metadata-rule",
        "owned-metadata.rs",
        1,
        None,
        Severity::Info,
        "Labeled owned observation. No defect is claimed.",
    )
}

#[test]
fn canceled_discovery_cannot_publish_observations_or_start_a_finding_run() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    let ctx = context(&workspace, &store, &config, Some(&cancellation));
    let error = persist_taint_iris_next_findings(
        root.path(),
        &[observation()],
        &ctx,
        RunItemStatus::Completed,
    )
    .unwrap_err();
    assert!(error.to_string().contains("canceled"));
    assert!(store.list_findings(10).unwrap().is_empty());
    assert_eq!(store.latest_run_id().unwrap(), None);
}

#[test]
fn canceled_discovery_stops_before_target_resolution_or_evidence_collection() {
    let config = V2Config::default();
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: Some(&cancellation),
        authorization: Default::default(),
    };
    let error = run_taint_iris_next_report(&json!({}), &ctx, None).unwrap_err();
    assert!(error.to_string().contains("canceled"));
    assert!(!error.to_string().contains("target"));
}

#[test]
fn importing_unverified_observations_retains_history_without_carrying_a_current_fp() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("owned-baseline", root.path(), "running")
        .unwrap();
    let finding = observation();
    let id = store.insert_finding("owned-baseline", &finding).unwrap();
    store
        .record_triage_with_author(
            id,
            &TriageOutcome {
                verdict: TriageVerdict::FalsePositive,
                rationale: "Owned human decision".into(),
                confidence: 1.0,
                ..Default::default()
            },
            TriageAuthor::Human,
        )
        .unwrap();
    let before = store.list_all_review_decisions().unwrap();
    assert_eq!(before.len(), 1);
    let config = V2Config::default();
    let ctx = context(&workspace, &store, &config, None);
    let receipt =
        persist_taint_iris_next_findings(root.path(), &[finding], &ctx, RunItemStatus::Completed)
            .unwrap()
            .unwrap();
    assert!(!receipt.run_id.is_empty());
    let after = store.list_findings(10).unwrap().pop().unwrap();
    assert_eq!(store.list_all_review_decisions().unwrap(), before);
    assert_eq!(after.triage, None);
    assert_eq!(after.triaged_by, None);
}

#[test]
fn failed_model_attempt_retains_candidates_without_a_completed_finding_run() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &store, &config, None);
    let receipt = persist_taint_iris_next_findings(
        root.path(),
        &[observation()],
        &ctx,
        RunItemStatus::Failed,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        store.run_status(&receipt.run_id).unwrap().as_deref(),
        Some("failed")
    );
    assert_eq!(store.list_findings(10).unwrap().len(), 1);
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn failed_empty_attempt_stays_failed_without_observations() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &store, &config, None);
    let receipt = persist_taint_iris_next_findings(root.path(), &[], &ctx, RunItemStatus::Failed)
        .unwrap()
        .unwrap();
    assert_eq!(
        store.run_status(&receipt.run_id).unwrap().as_deref(),
        Some("failed")
    );
    assert!(store.list_findings(10).unwrap().is_empty());
}
