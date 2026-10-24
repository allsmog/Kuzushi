use super::*;

fn partial_fixture(root: &Path) -> Fixture {
    std::fs::write(root.join("main.rs"), "fn main() { println!(\"hello\"); }\n").unwrap();
    std::fs::write(root.join("oversized.txt"), vec![b'a'; 262_145]).unwrap();
    let workspace = WorkspaceTarget::new(root).unwrap();
    let config = V2Config::default();
    let snapshot = ModuleRegistry::with_v2_builtins()
        .execute_tool(
            "context:build",
            json!({"enrichment":false}),
            &context(&workspace, &config),
        )
        .unwrap();
    assert_eq!(snapshot["status"], "partial");
    let fixture = generate(root);
    failed_queue(root);
    fixture
}

fn failed_queue(root: &Path) {
    write_json_atomic(&campaign_queue_path(root, "context-draft"),
        &json!({"jobs":{"context-001":{"state":"failed","runId":"context-result","attempts":1,"exitCode":4}}})).unwrap();
}

#[test]
fn partial_campaign_output_recovers_its_exact_revision_without_retry_or_activation() {
    let root = tempfile::tempdir().unwrap();
    let fixture = partial_fixture(root.path());
    let output = fixture
        .receipt
        .generated_context_document(root.path())
        .unwrap()
        .unwrap();
    assert_eq!(output.reference, fixture.generated);
    assert_eq!(output.document["verification"]["verdict"], "partial");
    assert!(load_active_threat_model(root.path()).unwrap().is_none());
    assert_eq!(
        fixture
            .receipt
            .load_allowance(root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        1
    );
    let queue = read_json_file(&campaign_queue_path(root.path(), "context-draft")).unwrap();
    assert_eq!(queue["jobs"]["context-001"]["state"], "failed");
    assert_eq!(queue["jobs"]["context-001"]["attempts"], 1);
}

#[test]
fn partial_campaign_map_requires_acknowledgment_and_retains_shared_context() {
    let root = tempfile::tempdir().unwrap();
    let fixture = partial_fixture(root.path());
    let reviewed = fixture.review(root.path()).unwrap();
    assert_eq!(
        fixture.review(root.path()).unwrap()["data"],
        reviewed["data"]
    );
    assert_eq!(reviewed["data"]["mapOutcome"], "partial");
    let ledger = load_phase_attempt_ledger(root.path()).unwrap();
    assert_eq!(ledger.attempts().count(), 1);
    assert_eq!(
        ledger.attempts().next().unwrap().completed.outcome,
        PhaseAttemptOutcome::Partial
    );
    let decision = |acknowledged_partial| {
        PhaseAttemptDispositionRecorded::new(
            reviewed["data"]["attemptId"].as_str().unwrap(),
            PhaseAttemptDisposition::Selected {
                acknowledged_partial,
            },
        )
    };
    assert!(append_phase_attempt_disposition(root.path(), decision(false)).is_err());
    append_phase_attempt_disposition(root.path(), decision(true)).unwrap();
    let scan = scan_draft(&fixture, root.path(), json!({})).unwrap();
    let scan: StudyPlanReceipt = serde_json::from_value(scan["data"].clone()).unwrap();
    assert_eq!(scan.scan_input["threatModelRef"], json!(fixture.generated));
    assert_eq!(
        scan.investigation_id.as_deref(),
        Some(fixture.receipt.investigation_id.as_str())
    );
    assert_eq!(
        fixture
            .receipt
            .load_allowance(root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        1
    );
}

#[test]
fn failed_queue_cannot_relabel_a_completed_run_as_partial_context() {
    let root = tempfile::tempdir().unwrap();
    let fixture = generate(root.path());
    failed_queue(root.path());
    assert!(fixture
        .receipt
        .generated_context_document(root.path())
        .is_err());
    assert!(fixture.review(root.path()).is_err());
}

#[test]
fn partial_campaign_recovery_rejects_a_different_frozen_input() {
    let root = tempfile::tempdir().unwrap();
    let fixture = partial_fixture(root.path());
    let mut changed = fixture.receipt.clone();
    changed.input["maxSourceBytes"] = json!(1);
    let error = changed.generated_context_document(root.path()).unwrap_err();
    assert!(
        format!("{error:#}").contains("differs from its frozen context plan"),
        "{error:#}"
    );
}

#[test]
fn partial_campaign_recovery_and_map_reject_changed_input_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let fixture = partial_fixture(root.path());
    let mut changed = fixture.receipt.input.clone();
    changed["maxSourceBytes"] = json!(1);
    write_run_artifact_json(
        root.path(),
        "context-result",
        "input.json",
        "Labeled changed input",
        &changed,
    )
    .unwrap();
    assert!(fixture
        .receipt
        .generated_context_document(root.path())
        .is_err());
    assert!(fixture.review(root.path()).is_err());
}
