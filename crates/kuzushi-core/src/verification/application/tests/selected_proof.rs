use super::*;
use crate::findings::{
    Finding, PersistedProofVerdict, PersistedSandboxBackend, Severity, TriageOutcome, TriageVerdict,
};
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
    assert_eq!(proof.proof_verdict, PersistedProofVerdict::NotAttempted);
    assert_eq!(proof.verification_run_id.as_deref(), Some(run_id));
    assert_eq!(proof.verified_scan_id.as_deref(), Some("scan-current"));
    assert!(matches!(
        proof.provenance.as_ref().unwrap().source_identity,
        crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
            tree_hash: Some(_),
            ..
        }
    ));
    assert!(proof
        .notes
        .iter()
        .any(|note| note.contains("assessment=likely_exploitable")));
    assert!(proof.is_current_for_scan(restored.scan_id.as_deref()));
}

#[test]
fn selected_model_proof_rejects_empirical_level_claim() {
    let (_target, workspace, finding) = proof_fixture("scan-current");
    let run_id = "tool-proof-model-level-four";
    record_model_proof_run_at_level(&workspace, run_id, &finding, "scan-current", 4);

    let error = materialize_selected_proof_attempt(&workspace, &prove_attempt(&workspace, run_id))
        .unwrap_err()
        .to_string();

    assert!(error.contains("static model proof level is outside 1..=3"));
    let finding = FindingStore::open(workspace.findings_db_path())
        .unwrap()
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap();
    assert!(finding.verification.is_none());
}

#[test]
fn model_proof_rejects_conflicting_repeated_source_identity() {
    let finding = Finding::new_tool(
        "proof-test",
        "proof-test/rule",
        "src/main.rs",
        1,
        None,
        Severity::High,
        "proof candidate",
    );
    let mut result = model_proof_result(&finding, "scan-current", 3);
    result["data"]["proof"]["sourceIdentity"]["tree_hash"] = json!("c".repeat(64));

    let error = ModelProofCandidate::from_result(&result)
        .unwrap_err()
        .to_string();

    assert!(error.contains("conflicting candidate identities"));
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
fn changed_workspace_tree_rejects_model_proof_selection() {
    let (_target, workspace, finding) = proof_fixture("scan-current");
    let run_id = "tool-proof-model-source-stale";
    record_model_proof_run(&workspace, run_id, &finding, "scan-current");
    std::fs::write(workspace.root().join("late-change.rs"), "fn changed() {}\n").unwrap();

    let error = materialize_selected_proof_attempt(&workspace, &prove_attempt(&workspace, run_id))
        .unwrap_err()
        .to_string();

    assert!(error.contains("source identity is stale"));
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
    record_model_proof_run_at_level(workspace, run_id, finding, verified_scan_id, 3);
}

fn record_model_proof_run_at_level(
    workspace: &WorkspaceTarget,
    run_id: &str,
    finding: &Finding,
    verified_scan_id: &str,
    proof_level: u8,
) {
    let record = ToolRunRecord::new(workspace.root(), run_id, "tool", "verify:finding");
    let input = json!({"fingerprint": finding.fingerprint.clone()});
    try_record_tool_run_started_with_reproducibility(record, &input, None, None, Vec::new())
        .unwrap();
    let source_identity =
        crate::verification::capture_verification_source_identity(workspace.root()).unwrap();
    try_record_tool_run_complete(
        record,
        &model_proof_result_with_identity(finding, verified_scan_id, proof_level, source_identity),
    )
    .unwrap();
}

#[test]
fn stage_blocks_are_carried_outside_the_compared_candidate_fields() {
    // The real invariant: `ModelProofCandidate` deserializes only the eight
    // verdict/identity fields, so the gate/escalation stage blocks are NOT part
    // of the 4-way equality (data == verification == proof-snapshot). The stage
    // note is likewise carried separately as `data.stageNote` and read by
    // `append_stage_note`. Therefore a stage-block disagreement across the four
    // copies can never fire the 4-way trap — this test pins that fact so the
    // "mirror the stage blocks" comment cannot silently start claiming
    // otherwise.
    let finding = Finding::new_tool(
        "proof-test",
        "proof-test/rule",
        "src/main.rs",
        1,
        None,
        Severity::High,
        "proof candidate",
    );
    let mut result = model_proof_result(&finding, "scan-current", 3);
    // Deliberately DISAGREEING escalation blocks + a stageNote on only one copy.
    result
        .pointer_mut("/data")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap()
        .insert(
            "escalation".to_string(),
            json!({"stage": "tie-break", "model": "openai:bigger", "attempted": true, "panelPasses": 2}),
        );
    result
        .pointer_mut("/data")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap()
        .insert("stageNote".to_string(), json!("stages: panel(2) split · tie-break openai:bigger"));
    result
        .pointer_mut("/proof")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap()
        .insert(
            "escalation".to_string(),
            json!({"stage": "tie-break", "attempted": false, "refusedToken": "invalid-spec"}),
        );

    ModelProofCandidate::from_result(&result).expect(
        "stage blocks live outside the 4-way-compared fields, so a disagreement there never traps",
    );

    // A genuine candidate-field disagreement DOES break binding — proving the
    // 4-way trap still guards the fields that actually matter.
    result
        .pointer_mut("/proof")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap()
        .insert("exploitable".to_string(), json!(false));
    let error = ModelProofCandidate::from_result(&result)
        .unwrap_err()
        .to_string();
    assert!(error.contains("conflicting candidate identities"), "{error}");
}

fn model_proof_result(finding: &Finding, verified_scan_id: &str, proof_level: u8) -> Value {
    model_proof_result_with_identity(
        finding,
        verified_scan_id,
        proof_level,
        model_source_identity(),
    )
}

fn model_proof_result_with_identity(
    finding: &Finding,
    verified_scan_id: &str,
    proof_level: u8,
    source_identity: crate::workflow_attempts::TargetContentIdentity,
) -> Value {
    let candidate = json!({
        "fingerprint": finding.fingerprint.clone(),
        "verifiedScanId": verified_scan_id,
        "identityId": finding.identity_id.clone(),
        "sourceIdentity": source_identity,
        "exploitable": true,
        "confidence": 0.99,
        "proofLevel": proof_level,
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

fn model_source_identity() -> crate::workflow_attempts::TargetContentIdentity {
    crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
        snapshot_hash: crate::run_lifecycle::SafeText::operator_visible("a".repeat(64)),
        tree_hash: Some(crate::run_lifecycle::SafeText::operator_visible(
            "b".repeat(64),
        )),
    }
}

fn prove_attempt(workspace: &WorkspaceTarget, run_id: &str) -> PhaseAttemptCompleted {
    PhaseAttemptCompleted::new(
        WorkflowPhase::Prove,
        vec![run_id.to_string()],
        PhaseTargetSnapshot::capture(workspace.root()),
        PhaseAttemptOutcome::Completed,
    )
}
