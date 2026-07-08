use super::*;
use kuzushi_core::findings::{
    ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict, TriageAuthor,
};
use kuzushi_core::{
    Finding, FindingEvidence, Severity, StaticProofState, TriageOutcome, TriageVerdict, V2Config,
};

fn finding(rule: &str, severity: Severity, line: u32) -> Finding {
    Finding::new_tool("semgrep", rule, "src/lib.rs", line, None, severity, rule)
}

fn confirmed(mut finding: Finding) -> Finding {
    finding.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.93,
        rationale: "reviewed".to_string(),
        cost_usd: 0.0,
    });
    finding
}

fn human_confirmed(mut finding: Finding, confidence: f32) -> Finding {
    finding.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence,
        rationale: "human reviewed".to_string(),
        cost_usd: 0.0,
    });
    finding.triaged_by = Some(TriageAuthor::Human);
    finding
}

fn open_finding_with_evidence() -> Finding {
    let mut finding = finding("path-traversal", Severity::High, 20);
    finding.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    finding.evidence.push(FindingEvidence {
        kind: "code".to_string(),
        file_path: "src/lib.rs".to_string(),
        line: 20,
        snippet: "join(user_path)".to_string(),
        rationale: "untrusted path reaches file open".to_string(),
        confidence: 80,
        request_blob: None,
        response_blob: None,
    });
    finding
}

#[test]
fn review_queue_model_separates_open_and_terminal_decisions() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut open = open_finding_with_evidence();
    open.identity_id = Some("fi_0123456789abcdef0123456789abcdef".to_string());
    let done = confirmed(finding("sql-injection", Severity::Medium, 40));
    *app.selected_finding_mut() = Some(open.clone());
    *app.findings_mut() = vec![open, done];

    let open_model = review_queue_model(&app, ReviewQueueMode::Open);
    assert_eq!(open_model.total_count, 2);
    assert_eq!(open_model.visible_count, 1);
    assert_eq!(open_model.open_count, 1);
    assert_eq!(open_model.complete_count, 1);
    assert_eq!(open_model.filter_label, "decision:open");
    assert_eq!(
        open_model.header,
        "REVIEW QUEUE - showing 1 of 2 - 1 open - 1 complete"
    );
    assert!(open_model.empty_reason.is_none());
    assert_eq!(open_model.rows[0].decision, "needs_review");
    assert_eq!(open_model.rows[0].identity_label, "FI-01234567");
    assert!(!open_model.rows[0].decision_complete);
    assert_eq!(open_model.rows[0].confidence_label, "-");
    assert_eq!(open_model.rows[0].lifecycle_status, "statically_supported");
    assert_eq!(open_model.rows[0].evidence_state, "evidence:1");
    assert!(open_model.rows[0].selected);

    let complete_model = review_queue_model(&app, ReviewQueueMode::Complete);
    assert_eq!(complete_model.visible_count, 1);
    assert_eq!(complete_model.rows[0].decision, "confirmed");
    assert!(complete_model.rows[0].decision_complete);
    assert_eq!(complete_model.rows[0].confidence_label, "93%");
    assert_eq!(complete_model.rows[0].next_action, "decision_complete");
}

#[test]
fn review_queue_model_keeps_projected_duplicate_semantics() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let semgrep = finding("semgrep/cwe-89", Severity::Medium, 12);
    let systems = finding("systems/cwe-89", Severity::High, 14);
    assert_eq!(semgrep.dedup_key, systems.dedup_key);
    *app.findings_mut() = vec![semgrep, systems];

    let model = review_queue_model(&app, ReviewQueueMode::All);

    assert_eq!(model.total_count, 1);
    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].severity_label, "HIGH");
}

#[test]
fn review_queue_model_marks_cursor_row_when_no_finding_is_pinned() {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![
        finding("first", Severity::High, 1),
        finding("second", Severity::Medium, 2),
    ];
    app.router.findings_mut().set_cursor(1);
    *app.selected_finding_mut() = None;

    let model = review_queue_model(&app, ReviewQueueMode::All);

    assert!(!model.rows[0].selected);
    assert!(model.rows[1].selected);
}

#[test]
fn review_queue_model_applies_loaded_identity_review_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let reviewed = human_confirmed(
        identity_finding("semgrep/cwe-79", Severity::High, 12, 1, &identity_id),
        0.86,
    );
    let rerun = identity_finding(
        "semgrep/cwe-79-rerun",
        Severity::Medium,
        18,
        2,
        &identity_id,
    );
    assert!(rerun.triage.is_none());
    *app.findings_mut() = vec![reviewed, rerun];

    let all_model = review_queue_model(&app, ReviewQueueMode::All);
    assert_eq!(all_model.total_count, 2);
    assert_eq!(all_model.open_count, 0);
    assert_eq!(all_model.complete_count, 2);
    assert!(all_model.rows.iter().all(|row| row.decision == "confirmed"));
    assert!(all_model
        .rows
        .iter()
        .all(|row| row.decision_author == "human"));
    assert!(all_model
        .rows
        .iter()
        .all(|row| row.confidence_label == "86%"));

    let open_model = review_queue_model(&app, ReviewQueueMode::Open);
    assert_eq!(open_model.visible_count, 0);
    assert_eq!(
        open_model.empty_reason.as_deref(),
        Some("all visible findings have terminal decisions")
    );
}

#[test]
fn review_queue_model_applies_loaded_append_only_decisions() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let finding = identity_finding("semgrep/suppressed", Severity::High, 12, 1, &identity_id);
    assert!(finding.triage.is_none());
    *app.findings_mut() = vec![finding];
    app.set_review_decisions(vec![ReviewDecisionRecord {
        id: 3,
        finding_id: 1,
        identity_id: Some(identity_id),
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::Suppressed,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "suppressed by approved review policy".to_string(),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: None,
        created_at: "2026-07-02T00:00:00Z".to_string(),
    }]);

    let complete_model = review_queue_model(&app, ReviewQueueMode::Complete);
    assert_eq!(complete_model.visible_count, 1);
    assert_eq!(complete_model.open_count, 0);
    assert_eq!(complete_model.complete_count, 1);
    assert_eq!(complete_model.rows[0].decision, "suppressed");
    assert_eq!(complete_model.rows[0].decision_author, "human");
    assert_eq!(complete_model.rows[0].confidence_label, "100%");

    let open_model = review_queue_model(&app, ReviewQueueMode::Open);
    assert_eq!(open_model.visible_count, 0);
    assert_eq!(
        open_model.empty_reason.as_deref(),
        Some("all visible findings have terminal decisions")
    );
}

#[test]
fn review_queue_keeps_reappeared_rejected_identity_open() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let reviewed = human_rejected(identity_finding(
        "semgrep/cwe-79",
        Severity::Medium,
        12,
        1,
        &identity_id,
    ));
    let mut rerun = identity_finding("semgrep/cwe-79", Severity::High, 12, 2, &identity_id);
    rerun.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    *app.findings_mut() = vec![reviewed, rerun];

    let open_model = review_queue_model(&app, ReviewQueueMode::Open);

    assert_eq!(open_model.visible_count, 1);
    assert_eq!(open_model.open_count, 1);
    assert_eq!(open_model.complete_count, 0);
    assert_eq!(open_model.rows[0].decision, "rejected_false_positive");
    assert_eq!(open_model.rows[0].decision_author, "human");
    assert_eq!(
        open_model.rows[0].decision_conflict.as_deref(),
        Some("reappeared_after_rejection")
    );
    assert!(!open_model.rows[0].decision_complete);
}

fn identity_finding(
    rule: &str,
    severity: Severity,
    line: u32,
    id: i64,
    identity_id: &str,
) -> Finding {
    let mut finding = finding(rule, severity, line);
    finding.identity_id = Some(identity_id.to_string());
    finding.id = Some(id);
    finding.created_at = format!("2026-07-{id:02}T00:00:00Z");
    finding
}

fn human_rejected(mut finding: Finding) -> Finding {
    finding.triage = Some(TriageOutcome {
        verdict: TriageVerdict::FalsePositive,
        confidence: 0.91,
        rationale: "operator rejected prior occurrence".to_string(),
        cost_usd: 0.0,
    });
    finding.triaged_by = Some(TriageAuthor::Human);
    finding
}
