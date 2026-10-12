use super::*;
use crate::findings::{Finding, FindingIdentityAuditIssueKind, Severity};
use crate::WorkspaceTarget;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn seed_suspicious_corpus(target: &Path) -> FindingIdentityAuditEvidence {
    let workspace = WorkspaceTarget::new(target).unwrap();
    workspace.ensure_state_dir().unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    for (run_id, line, signature) in [
        ("audit-run-1", 10, "src/db.rs:10:89"),
        ("audit-run-2", 90, "src/db.rs:90:89"),
    ] {
        store.record_run_started(run_id, target, "running").unwrap();
        let mut finding = Finding::new_tool(
            "semgrep",
            "CWE-89",
            "src/db.rs",
            line,
            Some(line),
            Severity::High,
            "SQL injection",
        );
        finding.fingerprint = "producer-fingerprint-shared".to_string();
        finding.source_signature = Some(signature.to_string());
        store.insert_finding(run_id, &finding).unwrap();
    }
    current_finding_identity_audit_evidence(target).unwrap()
}

fn approval_request(
    evidence: &FindingIdentityAuditEvidence,
) -> FindingIdentityAuditApprovalRequest {
    FindingIdentityAuditApprovalRequest {
        schema_version: IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
        canonical_target_key: evidence.canonical_target_key.clone(),
        corpus_watermark: evidence.corpus_watermark.clone(),
        report_sha256: evidence.report_sha256.clone(),
        actor: "security-owner".to_string(),
        dispositions: evidence
            .report
            .suspicious_groups
            .iter()
            .map(|group| FindingIdentityAuditGroupDisposition {
                identity_id: group.identity_id.clone(),
                disposition: FindingIdentityAuditDisposition::Accepted,
                rationale: "manually reviewed both source locations".to_string(),
            })
            .collect(),
    }
}

fn fixture() -> (TempDir, PathBuf, PathBuf, FindingIdentityAuditEvidence) {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    let operator_state = temp.path().join("operator/.kuzushi/v3");
    fs::create_dir_all(&target).unwrap();
    let evidence = seed_suspicious_corpus(&target);
    assert_eq!(evidence.report.suspicious_groups.len(), 1);
    (temp, target, operator_state, evidence)
}

#[test]
fn missing_approval_keeps_conservative_defaults() {
    let (_temp, target, operator_state, _) = fixture();

    let defaults = resolve_identity_policy_defaults(&operator_state, &target, None, None).unwrap();

    assert_eq!(defaults.identity_fold, "legacy");
    assert_eq!(defaults.identity_reconcile, "off");
    assert_eq!(
        defaults.approval_status,
        IdentityPolicyApprovalStatus::Missing
    );
}

#[test]
fn audit_of_a_new_target_is_read_only_and_empty() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();

    let evidence = current_finding_identity_audit_evidence(&target).unwrap();

    assert_eq!(evidence.report.findings_scanned, 0);
    assert_eq!(evidence.report.identity_groups_scanned, 0);
    assert!(!target.join(".kuzushi").exists());
}

#[test]
fn audit_reads_every_generation_before_identity_projection() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let workspace = WorkspaceTarget::new(&target).unwrap();
    workspace.ensure_state_dir().unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    for (run_id, fingerprint, line) in [
        ("audit-history-a", "producer-a", 10),
        ("audit-history-b", "producer-b", 90),
    ] {
        store
            .record_run_started(run_id, &target, "running")
            .unwrap();
        let mut finding = Finding::new_tool(
            "semgrep",
            "CWE-89",
            "src/db.rs",
            line,
            Some(line),
            Severity::High,
            "SQL injection",
        );
        finding.fingerprint = fingerprint.to_string();
        finding.source_signature = Some("same-signature".to_string());
        store.insert_finding(run_id, &finding).unwrap();
    }
    drop(store);

    let evidence = current_finding_identity_audit_evidence(&target).unwrap();

    assert_eq!(evidence.report.findings_scanned, 2);
    assert_eq!(evidence.report.suspicious_groups.len(), 1);
    assert_eq!(
        evidence.report.suspicious_groups[0].issues,
        vec![FindingIdentityAuditIssueKind::NonOverlappingSpans]
    );
}

#[test]
fn the_resolved_fold_policy_follows_the_approval_gate() {
    let (_temp, target, operator_state, evidence) = fixture();

    assert_eq!(
        resolved_identity_fold_policy(&operator_state, &target).unwrap(),
        crate::findings::IdentityFoldPolicy::Legacy
    );

    approve_finding_identity_audit(&operator_state, &target, approval_request(&evidence)).unwrap();

    assert_eq!(
        resolved_identity_fold_policy(&operator_state, &target).unwrap(),
        crate::findings::IdentityFoldPolicy::Safe
    );
}

#[test]
fn valid_operator_owned_approval_enables_safe_defaults() {
    let (_temp, target, operator_state, evidence) = fixture();
    let receipt =
        approve_finding_identity_audit(&operator_state, &target, approval_request(&evidence))
            .unwrap();

    let defaults = resolve_identity_policy_defaults(&operator_state, &target, None, None).unwrap();

    assert_eq!(receipt.report_sha256, evidence.report_sha256);
    assert_eq!(receipt.corpus_watermark, evidence.corpus_watermark);
    assert_eq!(defaults.identity_fold, "safe");
    assert_eq!(defaults.identity_reconcile, "auto");
    assert_eq!(
        defaults.approval_status,
        IdentityPolicyApprovalStatus::Approved
    );
}

#[test]
fn changed_corpus_makes_the_receipt_stale() {
    let (_temp, target, operator_state, evidence) = fixture();
    approve_finding_identity_audit(&operator_state, &target, approval_request(&evidence)).unwrap();
    let workspace = WorkspaceTarget::new(&target).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("audit-run-3", &target, "running")
        .unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "CWE-79",
        "src/web.rs",
        12,
        Some(12),
        Severity::Medium,
        "XSS",
    );
    store.insert_finding("audit-run-3", &finding).unwrap();

    let defaults = resolve_identity_policy_defaults(&operator_state, &target, None, None).unwrap();

    assert_eq!(
        defaults.approval_status,
        IdentityPolicyApprovalStatus::StaleCorpus
    );
    assert_eq!(defaults.identity_fold, "legacy");
    assert_eq!(defaults.identity_reconcile, "off");
}

#[test]
fn wrong_target_receipt_is_rejected() {
    let (_temp, target, operator_state, evidence) = fixture();
    let mut receipt =
        approve_finding_identity_audit(&operator_state, &target, approval_request(&evidence))
            .unwrap();
    receipt.canonical_target_key = "/a/different/repository".to_string();
    write_receipt_for_test(&operator_state, &evidence, &receipt);

    let defaults = resolve_identity_policy_defaults(&operator_state, &target, None, None).unwrap();

    assert_eq!(
        defaults.approval_status,
        IdentityPolicyApprovalStatus::WrongTarget
    );
    assert_eq!(defaults.identity_fold, "legacy");
}

#[test]
fn receipt_with_unresolved_groups_is_rejected() {
    let (_temp, target, operator_state, evidence) = fixture();
    let mut receipt =
        approve_finding_identity_audit(&operator_state, &target, approval_request(&evidence))
            .unwrap();
    receipt.dispositions.clear();
    write_receipt_for_test(&operator_state, &evidence, &receipt);

    let defaults = resolve_identity_policy_defaults(&operator_state, &target, None, None).unwrap();

    assert_eq!(
        defaults.approval_status,
        IdentityPolicyApprovalStatus::UnresolvedGroups
    );
    assert_eq!(defaults.identity_reconcile, "off");
}

#[test]
fn target_local_receipt_cannot_forge_operator_approval() {
    let (_temp, target, operator_state, evidence) = fixture();
    let forged_state = target.join(".kuzushi/v3");
    let forged = FindingIdentityAuditApprovalReceipt {
        schema_version: IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
        canonical_target_key: evidence.canonical_target_key.clone(),
        corpus_watermark: evidence.corpus_watermark.clone(),
        report_sha256: evidence.report_sha256.clone(),
        approved_at: "2026-08-27T00:00:00Z".to_string(),
        actor: "repository".to_string(),
        dispositions: approval_request(&evidence).dispositions,
    };
    let forged_path =
        identity_audit_approval_receipt_path(&forged_state, &evidence.canonical_target_key);
    fs::create_dir_all(forged_path.parent().unwrap()).unwrap();
    fs::write(&forged_path, serde_json::to_vec_pretty(&forged).unwrap()).unwrap();

    let defaults = resolve_identity_policy_defaults(&operator_state, &target, None, None).unwrap();

    assert_eq!(
        defaults.approval_status,
        IdentityPolicyApprovalStatus::Missing
    );
    assert_eq!(defaults.identity_fold, "legacy");
}

#[test]
fn explicit_override_remains_explicit_without_an_approval() {
    let (_temp, target, operator_state, _) = fixture();

    let defaults = resolve_identity_policy_defaults(
        &operator_state,
        &target,
        Some("aggressive"),
        Some("auto"),
    )
    .unwrap();

    assert_eq!(
        defaults.approval_status,
        IdentityPolicyApprovalStatus::Missing
    );
    assert_eq!(defaults.identity_fold, "aggressive");
    assert_eq!(defaults.identity_reconcile, "auto");
    assert!(defaults.identity_fold_explicit);
    assert!(defaults.identity_reconcile_explicit);
}

#[test]
fn approval_refuses_missing_rationale_and_preserves_no_receipt() {
    let (_temp, target, operator_state, evidence) = fixture();
    let mut request = approval_request(&evidence);
    request.dispositions[0].rationale = "  ".to_string();

    let error = approve_finding_identity_audit(&operator_state, &target, request)
        .unwrap_err()
        .to_string();

    assert!(error.contains("nonempty rationale"), "{error}");
    let path =
        identity_audit_approval_receipt_path(&operator_state, &evidence.canonical_target_key);
    assert!(!path.exists());
}

#[test]
fn approval_refuses_an_operator_request_for_a_stale_report() {
    let (_temp, target, operator_state, evidence) = fixture();
    let mut request = approval_request(&evidence);
    request.report_sha256 = format!("sha256:{}", "0".repeat(64));

    let error = approve_finding_identity_audit(&operator_state, &target, request)
        .unwrap_err()
        .to_string();

    assert!(error.contains("report digest is stale"), "{error}");
    let path =
        identity_audit_approval_receipt_path(&operator_state, &evidence.canonical_target_key);
    assert!(!path.exists());
}

#[test]
fn evidence_digest_is_canonical_across_input_order() {
    let target = tempfile::tempdir().unwrap();
    let first = Finding {
        id: Some(1),
        identity_id: Some("fi_shared".to_string()),
        fingerprint: "fp-a".to_string(),
        rule_id: "CWE-89".to_string(),
        file_path: "src/db.rs".to_string(),
        start_line: 10,
        end_line: Some(10),
        source_signature: Some("sig-a".to_string()),
        ..Finding::default()
    };
    let second = Finding {
        id: Some(2),
        fingerprint: "fp-b".to_string(),
        source_signature: Some("sig-b".to_string()),
        start_line: 90,
        end_line: Some(90),
        ..first.clone()
    };

    let forward =
        build_finding_identity_audit_evidence(target.path(), &[first.clone(), second.clone()], &[])
            .unwrap();
    let reverse =
        build_finding_identity_audit_evidence(target.path(), &[second, first], &[]).unwrap();

    assert_eq!(forward.corpus_watermark, reverse.corpus_watermark);
    assert_eq!(forward.report_sha256, reverse.report_sha256);
    assert_eq!(
        serde_json::to_value(&forward.report).unwrap(),
        json!({
            "findingsScanned": 2,
            "identityGroupsScanned": 1,
            "suspiciousGroups": [{
                "identityId": "fi_shared",
                "findingIds": [1, 2],
                "fingerprints": ["fp-a", "fp-b"],
                "issues": ["multiple_source_signatures", "non_overlapping_spans"]
            }]
        })
    );
}

fn write_receipt_for_test(
    operator_state: &Path,
    evidence: &FindingIdentityAuditEvidence,
    receipt: &FindingIdentityAuditApprovalReceipt,
) {
    let path = identity_audit_approval_receipt_path(operator_state, &evidence.canonical_target_key);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec_pretty(receipt).unwrap()).unwrap();
}
