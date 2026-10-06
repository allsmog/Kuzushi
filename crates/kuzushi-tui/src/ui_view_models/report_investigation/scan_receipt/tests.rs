use super::*;
use crate::ui_view_models::{ScanAttemptModel, ScanEngineOutcomeModel};

#[test]
fn missing_scan_never_manufactures_a_coverage_receipt() {
    assert!(receipt_lines(&scan(None)).is_empty());
}

#[test]
fn canceled_scan_receipt_keeps_source_disposition_and_unstarted_scope_visible() {
    let mut scan = scan(Some("canceled"));
    scan.engine_outcomes = vec![engine(
        "stopped",
        "Not started: scope c. No automatic retry.",
    )];
    let lines = receipt_lines(&scan).join("\n");
    assert!(lines.contains("Displayed Scan: canceled · awaiting disposition · stopped-run"));
    assert!(lines.contains("Recorded Scan source: source changed · scope a, b, c"));
    assert!(lines.contains("Semgrep: stopped · Not started: scope c"));
    assert!(lines.contains("does not establish complete repository coverage"));
}

#[test]
fn report_bounds_engine_preview_and_discloses_remaining_outcomes() {
    let mut scan = scan(Some("partial"));
    scan.engine_outcomes = vec![engine("skipped", "not started"); 5];
    let lines = incomplete_engine_lines(&scan);
    assert_eq!(lines.len(), 4);
    assert!(lines[3].contains("2 more engine outcomes in Scan"));
    scan.engine_outcomes = vec![engine("complete", "")];
    assert!(incomplete_engine_lines(&scan).is_empty());
}

#[test]
fn multi_run_attempt_names_its_additional_runs() {
    let mut scan = scan(Some("completed"));
    let lines = receipt_lines(&scan).join("\n");
    assert!(lines.contains("· stopped-run\n"), "{lines}");
    scan.attempt.as_mut().unwrap().run_refs = vec!["stopped-run".into(), "b".into(), "c".into()];
    let lines = receipt_lines(&scan).join("\n");
    assert!(lines.contains("· stopped-run +2 more run(s)"), "{lines}");
}

fn scan(outcome: Option<&str>) -> ScanPhaseModel {
    ScanPhaseModel {
        scope: "a, b, c".into(),
        plan: "fixed three-scope plan".into(),
        attempt: outcome.map(attempt),
        engine_outcomes: Vec::new(),
        empty_hint: None,
        live: None,
    }
}

fn attempt(outcome: &str) -> ScanAttemptModel {
    ScanAttemptModel {
        attempt_id: Some("stopped-attempt".into()),
        run_id: "stopped-run".into(),
        run_refs: vec!["stopped-run".into()],
        outcome: outcome.into(),
        disposition: "awaiting disposition".into(),
        freshness: "source changed".into(),
        findings: Some(1),
        findings_observed: None,
        findings_added: Some(1),
        findings_updated: Some(0),
        severity_counts: Vec::new(),
        artifact_count: 1,
        artifact_paths: Vec::new(),
        duration_secs: Some(1),
        cost_usd: None,
        cost_complete: None,
        error: None,
    }
}

fn engine(outcome: &str, detail: &str) -> ScanEngineOutcomeModel {
    ScanEngineOutcomeModel {
        engine: "Semgrep".into(),
        tool_key: Some("semgrep".into()),
        outcome: outcome.into(),
        run_ref: Some("stopped-run".into()),
        detail: Some(detail.into()),
    }
}
