use super::*;
use crate::findings::{Finding, PersistedSandboxBackend, Severity, TriageOutcome, TriageVerdict};
use crate::run_artifacts::{
    run_artifact_path, try_record_tool_run_complete,
    try_record_tool_run_started_with_reproducibility, ToolRunRecord,
};
use serde_json::json;

#[test]
fn selected_model_proof_materializes_and_survives_reopen() {
    let (_target, workspace, finding) = proof_fixture("scan-current");
    let run_id = "tool-proof-model-current";
    record_model_proof_run(&workspace, run_id, &finding, "scan-current");
    let attempt = prove_attempt(&workspace, run_id);

    assert_eq!(
        materialize_selected_proof_attempt(&workspace, &attempt).unwrap(),
        1
    );
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let restored = store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap();
    let proof = restored.verification.unwrap();
    assert_eq!(proof.backend, PersistedSandboxBackend::Model);
    assert_eq!(proof.verification_run_id.as_deref(), Some(run_id));
    assert_eq!(proof.verified_scan_id.as_deref(), Some("scan-current"));
    assert!(proof.is_current_for_scan(restored.scan_id.as_deref()));
}

#[test]
fn stale_finding_generation_is_rejected_without_a_verification_event() {
    let (_target, workspace, finding) = proof_fixture("scan-current");
    let run_id = "tool-proof-model-stale";
    record_model_proof_run(&workspace, run_id, &finding, "scan-previous");
    let error = materialize_selected_proof_attempt(&workspace, &prove_attempt(&workspace, run_id))
        .unwrap_err()
        .to_string();

    assert!(error.contains("stale finding generation"));
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert!(store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap()
        .verification
        .is_none());
}

#[test]
fn multi_run_proof_set_materializes_every_valid_candidate() {
    let (_target, workspace, finding) = proof_fixture("scan-current");
    let first = "tool-proof-set-first";
    let second = "tool-proof-set-second";
    record_model_proof_run(&workspace, first, &finding, "scan-current");
    record_model_proof_run(&workspace, second, &finding, "scan-current");
    let mut attempt = prove_attempt(&workspace, first);
    attempt.run_refs.push(second.to_string());

    assert_eq!(
        materialize_selected_proof_attempt(&workspace, &attempt).unwrap(),
        2
    );
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let proof = store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap()
        .verification
        .unwrap();
    assert_eq!(proof.verification_run_id.as_deref(), Some(second));
}

#[test]
fn multi_run_proof_set_validates_all_candidates_before_writing_any() {
    let (_target, workspace, finding) = proof_fixture("scan-current");
    let valid = "tool-proof-set-valid";
    let stale = "tool-proof-set-stale";
    record_model_proof_run(&workspace, valid, &finding, "scan-current");
    record_model_proof_run(&workspace, stale, &finding, "scan-previous");
    let mut attempt = prove_attempt(&workspace, valid);
    attempt.run_refs.push(stale.to_string());

    assert!(materialize_selected_proof_attempt(&workspace, &attempt).is_err());
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert!(store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap()
        .verification
        .is_none());
}

#[test]
fn changed_result_artifact_is_rejected_by_terminal_digest() {
    let (_target, workspace, finding) = proof_fixture("scan-current");
    let run_id = "tool-proof-model-tampered";
    record_model_proof_run(&workspace, run_id, &finding, "scan-current");
    std::fs::write(
        run_artifact_path(workspace.root(), run_id, "result.json"),
        "{\"ok\":true,\"status\":\"completed\"}",
    )
    .unwrap();

    let error = materialize_selected_proof_attempt(&workspace, &prove_attempt(&workspace, run_id))
        .unwrap_err()
        .to_string();
    assert!(error.contains("result digest does not match"));
}

fn proof_fixture(scan_id: &str) -> (tempfile::TempDir, WorkspaceTarget, Finding) {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started(scan_id, workspace.root(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "proof-test",
        "proof-test/rule",
        "src/main.rs",
        1,
        None,
        Severity::High,
        "proof candidate",
    );
    let finding_id = store.insert_finding(scan_id, &finding).unwrap();
    store
        .record_auto_triage(
            finding_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 1.0,
                rationale: "confirmed".to_string(),
                ..TriageOutcome::default()
            },
        )
        .unwrap();
    let finding = store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap();
    (target, workspace, finding)
}

fn record_model_proof_run(
    workspace: &WorkspaceTarget,
    run_id: &str,
    finding: &Finding,
    verified_scan_id: &str,
) {
    let record = ToolRunRecord::new(workspace.root(), run_id, "tool", "verify:finding");
    let input = json!({"fingerprint": finding.fingerprint.clone()});
    try_record_tool_run_started_with_reproducibility(record, &input, None, None, Vec::new())
        .unwrap();
    try_record_tool_run_complete(record, &model_proof_result(finding, verified_scan_id)).unwrap();
}

fn model_proof_result(finding: &Finding, verified_scan_id: &str) -> Value {
    let candidate = json!({
        "fingerprint": finding.fingerprint.clone(),
        "verifiedScanId": verified_scan_id,
        "identityId": finding.identity_id.clone(),
        "exploitable": true,
        "confidence": 0.99,
        "proofLevel": 3,
        "proofVerdict": "exploited"
    });
    let mut data = candidate.clone();
    data["verification"] = candidate.clone();
    data["proof"] = candidate.clone();
    json!({
        "ok": true,
        "status": "completed",
        "summary": "verify:finding complete (VULNERABLE)",
        "output": "verified",
        "data": data,
        "proof": candidate,
        "errors": [],
        "warnings": [],
        "artifacts": [],
        "costUsd": 0.125
    })
}

fn prove_attempt(workspace: &WorkspaceTarget, run_id: &str) -> PhaseAttemptCompleted {
    PhaseAttemptCompleted::new(
        WorkflowPhase::Prove,
        vec![run_id.to_string()],
        PhaseTargetSnapshot::capture(workspace.root()),
        PhaseAttemptOutcome::Completed,
    )
}
