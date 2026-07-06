use super::*;
use crate::findings::{
    FindingEvidence, ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor, TriageOutcome,
    TriageVerdict,
};
use std::collections::HashMap;

#[test]
fn export_record_separates_review_proof_and_evidence_fields() {
    let mut finding = reviewed_source_linked_finding();
    finding.identity_id = Some("fi_0123456789abcdef0123456789abcdef".to_string());
    finding.evidence.push(FindingEvidence {
        kind: "sink".to_string(),
        file_path: "src/app.ts".to_string(),
        line: 12,
        snippet: "db.query(q)".to_string(),
        rationale: "query sink".to_string(),
        confidence: 91,
        ..Default::default()
    });

    let records = workspace_finding_export_records_with_reviews(&[finding], &[]);

    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.alias, "F-0001");
    assert_eq!(
        record.identity_id.as_deref(),
        Some("fi_0123456789abcdef0123456789abcdef")
    );
    assert_eq!(record.review_decision, "confirmed");
    assert_eq!(record.triage_verdict.as_deref(), Some("true_positive"));
    assert_eq!(record.static_proof_state, "source_sink_linked");
    assert_eq!(record.evidence.state, "observed");
    assert!(record.evidence.observed_evidence_present);
    assert_eq!(record.evidence.observed_count, 1);
    assert_eq!(record.evidence.observed_code_count, 1);
    assert_eq!(record.evidence.observed_capture_count, 0);
    assert_eq!(record.evidence.observed_other_count, 0);
    assert!(!record.evidence.model_generated_reasoning_present);
    assert_eq!(record.evidence.model_generated_reasoning_count, 0);
    assert!(record.evidence.derived_source_present);
    assert!(record.analysis.static_proof_recorded);
    assert!(!record.analysis.automated_reasoning_present);
    assert!(record.analysis.human_review_present);
    assert_eq!(record.priority, "review-order:1");
    assert_eq!(record.lifecycle_status, "statically_supported");
}

#[test]
fn export_record_lifecycle_does_not_duplicate_static_proof_state() {
    let mut finding = basic_finding(Severity::Medium);
    finding.static_proof_state = Some(StaticProofState::StaticallyConfirmed);

    let records = workspace_finding_export_records_with_reviews(&[finding], &[]);

    assert_eq!(records[0].static_proof_state, "statically_confirmed");
    assert_eq!(records[0].lifecycle_status, "verified_static");
}

#[test]
fn export_record_does_not_serialize_raw_http_blobs() {
    let mut finding = Finding::new_tool(
        "burp",
        "http-request",
        "captures/login.har",
        1,
        None,
        Severity::Info,
        "captured request",
    );
    finding.evidence.push(FindingEvidence {
        kind: "http-request".to_string(),
        request_blob: Some("RAW REQUEST".to_string()),
        response_blob: Some("RAW RESPONSE".to_string()),
        ..Default::default()
    });

    let records = workspace_finding_export_records_with_reviews(&[finding], &[]);
    let body = serde_json::to_string(&records[0]).unwrap();

    assert!(records[0].evidence.raw_http_blob_present);
    assert!(!body.contains("RAW REQUEST"));
    assert!(!body.contains("RAW RESPONSE"));
}

#[test]
fn export_record_labels_automated_reasoning_without_calling_it_observed_evidence() {
    let mut finding = basic_finding(Severity::High);
    finding.triage = Some(TriageOutcome {
        verdict: TriageVerdict::NeedsReview,
        confidence: 0.6,
        rationale: "automated review needs operator validation".to_string(),
        cost_usd: 0.01,
    });
    finding.triaged_by = Some(TriageAuthor::Auto);

    let records = workspace_finding_export_records_with_reviews(&[finding], &[]);

    assert!(!records[0].evidence.observed_evidence_present);
    assert!(records[0].evidence.derived_source_present);
    assert!(records[0].analysis.automated_reasoning_present);
    assert!(!records[0].analysis.human_review_present);
}

#[test]
fn export_record_excludes_model_generated_reasoning_from_observed_evidence_count() {
    let mut finding = basic_finding(Severity::High);
    finding.evidence.push(FindingEvidence {
        kind: "reasoning".to_string(),
        snippet: "model compared source and sink context".to_string(),
        rationale: "LLM analysis only; not observed runtime evidence".to_string(),
        confidence: 67,
        ..Default::default()
    });

    let records = workspace_finding_export_records_with_reviews(&[finding], &[]);
    let evidence = &records[0].evidence;

    assert_eq!(evidence.state, "model_generated_reasoning");
    assert!(!evidence.observed_evidence_present);
    assert_eq!(evidence.observed_count, 0);
    assert_eq!(evidence.model_generated_reasoning_count, 1);
    assert!(evidence.model_generated_reasoning_present);
    assert!(records[0].analysis.automated_reasoning_present);
}

#[test]
fn export_record_counts_capture_evidence_separately_from_code_evidence() {
    let mut finding = basic_finding(Severity::Medium);
    finding.evidence.push(FindingEvidence {
        kind: "code".to_string(),
        file_path: "src/app.ts".to_string(),
        line: 12,
        snippet: "db.query(input)".to_string(),
        ..Default::default()
    });
    finding.evidence.push(FindingEvidence {
        kind: "http-request".to_string(),
        request_blob: Some("RAW REQUEST".to_string()),
        ..Default::default()
    });

    let records = workspace_finding_export_records_with_reviews(&[finding], &[]);
    let evidence = &records[0].evidence;

    assert_eq!(evidence.observed_count, 2);
    assert_eq!(evidence.observed_code_count, 1);
    assert_eq!(evidence.observed_capture_count, 1);
    assert_eq!(evidence.observed_other_count, 0);
    assert!(evidence.raw_http_blob_present);
}

#[test]
fn export_record_keeps_sparse_non_reasoning_evidence_in_observed_other_bucket() {
    let mut finding = basic_finding(Severity::Info);
    finding.evidence.push(FindingEvidence {
        kind: "note".to_string(),
        confidence: 40,
        ..Default::default()
    });

    let records = workspace_finding_export_records_with_reviews(&[finding], &[]);
    let evidence = &records[0].evidence;

    assert_eq!(evidence.observed_count, 1);
    assert_eq!(evidence.observed_code_count, 0);
    assert_eq!(evidence.observed_capture_count, 0);
    assert_eq!(evidence.observed_other_count, 1);
}

#[test]
fn export_record_does_not_project_non_triage_decision_as_triage() {
    let finding = basic_finding(Severity::Low);
    let review = WorkspaceFindingReviewContext::from_decision(
        ReviewDecision {
            verdict: ReviewDecisionVerdict::Suppressed,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "reviewed under approved suppression policy".to_string(),
        },
        ReviewDecisionVerdict::Suppressed.to_triage_verdict(),
    );

    let records = workspace_finding_export_records_with_reviews(&[finding], &[Some(review)]);

    assert_eq!(records[0].review_decision, "suppressed");
    assert_eq!(
        records[0].review_decision_reason.as_deref(),
        Some("reviewed under approved suppression policy")
    );
    assert_eq!(records[0].review_decision_author.as_deref(), Some("human"));
    assert_eq!(records[0].confidence, Some(1.0));
    assert_eq!(records[0].triage_verdict, None);
}

#[test]
fn export_record_uses_run_context_when_available() {
    let mut finding = basic_finding(Severity::High);
    finding.scan_id = Some("run-ctx".to_string());
    let mut contexts = HashMap::new();
    contexts.insert(
        "run-ctx".to_string(),
        WorkspaceRunExportContext {
            status: Some("completed".to_string()),
            kuzushi_version: Some("0.24.0-test".to_string()),
            model: Some("openai:gpt-test".to_string()),
            runtime_platform: Some("darwin-arm64".to_string()),
        },
    );

    let records = workspace_finding_export_records_with_context(&[finding], &[], &contexts);

    assert_eq!(records[0].provenance.run_id.as_deref(), Some("run-ctx"));
    assert_eq!(records[0].provenance.run_status.as_deref(), Some("completed"));
    assert_eq!(
        records[0].provenance.kuzushi_version.as_deref(),
        Some("0.24.0-test")
    );
    assert_eq!(
        records[0].provenance.model.as_deref(),
        Some("openai:gpt-test")
    );
    assert_eq!(
        records[0].provenance.runtime_platform.as_deref(),
        Some("darwin-arm64")
    );
}

fn reviewed_source_linked_finding() -> Finding {
    let mut finding = basic_finding(Severity::High);
    finding.scan_id = Some("run-1".to_string());
    finding.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.9,
        rationale: "operator reviewed source-linked evidence".to_string(),
        cost_usd: 0.0,
    });
    finding.triaged_by = Some(TriageAuthor::Human);
    finding.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    finding
}

fn basic_finding(severity: Severity) -> Finding {
    Finding::new_tool(
        "semgrep",
        "demo/sql",
        "src/app.ts",
        12,
        Some(13),
        severity,
        "user input reaches SQL",
    )
}
