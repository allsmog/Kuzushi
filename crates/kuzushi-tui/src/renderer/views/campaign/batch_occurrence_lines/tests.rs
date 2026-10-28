use super::*;

fn completed_report(
    threshold: Option<kuzushi_core::Severity>,
    blocking: usize,
) -> BatchOccurrenceReport {
    use kuzushi_core::capabilities::campaign::{
        ScanBatchGateBinding, ScanBatchGateCounts, ScanBatchGateOutcome, ScanBatchGatePolicy,
    };
    let policy = ScanBatchGatePolicy {
        fail_on: threshold,
        sarif: None,
    };
    let counts = ScanBatchGateCounts {
        planned_trials: 3,
        completed_trials: 3,
        failed_trials: 0,
        pending_trials: 0,
        completed_run_ids: vec!["run-1".into()],
        blocking_safe_fold_count: blocking,
        sarif_written: false,
    };
    let binding = ScanBatchGateBinding {
        logical_terminal_state_sha256: "state".into(),
        blocking_findings_sha256: "findings".into(),
        sarif_path: None,
        sarif_sha256: None,
    };
    let gate = ScanBatchGateOutcome::new(
        "owned-study",
        "sha256:recorded-conditions",
        &policy,
        counts,
        binding,
    );
    let mut row = long_row();
    row.planned = 3;
    row.failed = 0;
    BatchOccurrenceReport {
        schema_version: 1,
        batch_id: "owned-study".into(),
        equivalence_key: "sha256:recorded-conditions".into(),
        identity_fold: kuzushi_core::findings::IdentityFoldPolicy::Safe,
        planned: 3,
        completed: 3,
        failed: 0,
        pending: 0,
        gate: Some(gate),
        trials: vec![],
        rows: vec![row],
    }
}

fn report_text(report: &BatchOccurrenceReport, width: u16) -> String {
    let mut lines = Vec::new();
    append_batch_occurrence(&mut lines, report, Rect::new(0, 0, width, 36));
    assert!(lines.iter().all(|line| line.width() <= width as usize));
    lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn an_optional_severity_cutoff_does_not_claim_security_is_disabled() {
    let text = report_text(&completed_report(None, 0), 120);
    assert!(text.contains("Severity cutoff: not configured"), "{text}");
    assert!(
        !text.contains("security disabled") && !text.contains("blocking 0"),
        "{text}"
    );
    assert!(!text.contains("SARIF not written"), "{text}");
}

#[test]
fn configured_cutoffs_describe_observed_findings_without_a_security_verdict() {
    for (blocking, result) in [(0, "not reached"), (1, "reached")] {
        let text = report_text(
            &completed_report(Some(kuzushi_core::Severity::High), blocking),
            120,
        );
        assert!(
            text.contains(&format!("Severity cutoff high: {result}")),
            "{text}"
        );
        assert!(
            text.contains(&format!("{blocking} qualifying finding")),
            "{text}"
        );
        assert!(text.contains("does not establish proof"), "{text}");
    }
}

#[test]
fn finding_claims_precede_receipt_identifiers_without_dropping_provenance() {
    let report = completed_report(None, 0);
    for width in [40, 60, 80, 96, 120, 160] {
        let text = report_text(&report, width);
        assert!(
            text.find("Untrusted").unwrap() < text.find("Equivalence:").unwrap(),
            "{width}: {text}"
        );
        let compact = text.split_whitespace().collect::<String>();
        for value in [
            &report.equivalence_key,
            &report.rows[0].representative_fingerprint,
            &report.rows[0].run_ids[0],
        ] {
            assert!(compact.contains(value), "{width}: {text}");
        }
    }
}

#[test]
fn a_missing_gate_receipt_does_not_invent_an_unconfigured_policy() {
    let mut report = completed_report(None, 0);
    report.gate = None;
    let text = report_text(&report, 120);
    assert!(text.contains("Severity assessment: unavailable"), "{text}");
    assert!(!text.contains("not configured"), "{text}");
}

#[test]
fn empty_results_keep_equivalence_and_show_only_requested_sarif_receipts() {
    let mut report = completed_report(None, 0);
    report.rows.clear();
    for width in [40, 60, 80, 96, 120, 160] {
        let text = report_text(&report, width);
        assert!(text.contains("Equivalence:"), "{text}");
        assert!(!text.contains("SARIF"), "{text}");
    }
    let gate = report.gate.as_mut().unwrap();
    gate.policy.sarif = Some("owned.sarif".into());
    assert!(report_text(&report, 80).contains("SARIF: not saved"));
    report.gate.as_mut().unwrap().sarif_written = true;
    assert!(report_text(&report, 80).contains("SARIF: saved"));
}

fn long_row() -> BatchOccurrenceRow {
    BatchOccurrenceRow {
        fold_key: "fold-key".into(), identity_id: None, identity_basis: None,
        seen: 2, completed: 3, planned: 5, failed: 1,
        severities: vec!["high".into()], locations: vec![], titles: vec![],
        fingerprints: vec!["finding-exact-identity".into()],
        run_ids: vec!["run-discovery-exact-reference-1".into(), "run-discovery-exact-reference-2".into()],
        representative_fingerprint: "finding-exact-identity".into(),
        representative_title: "Untrusted repository paths escape the configured workspace boundary".into(),
        representative_severity: "high".into(),
        representative_location: "packages/server/src/components/very-long-subsystem-name/handlers/workspace-path-handler.rs:137".into(),
    }
}

#[test]
fn title_leads_and_complete_location_identity_and_runs_survive_narrow_columns() {
    let row = long_row();
    for width in [60, 80, 120] {
        let lines = batch_occurrence_row(&row, width);
        assert!(lines[1]
            .to_string()
            .contains("high · Untrusted repository paths"));
        assert!(lines.iter().all(|line| line.width() <= width));
        let text = lines
            .iter()
            .map(|line| line.to_string().trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains(&row.representative_title));
        assert!(text.contains("found in 2 of 3 completed passes"));
        assert!(text.contains("5 planned · 1 failed"));
        assert!(text.contains(&row.representative_fingerprint));
        for run in &row.run_ids {
            assert!(text.contains(run));
        }
        // A long path can wrap inside a token; every character must remain.
        assert!(text.replace(' ', "").contains(&row.representative_location));
    }
}

#[test]
fn terminal_buffer_keeps_the_title_visible_before_occurrence_metadata() {
    let row = long_row();
    let lines = batch_occurrence_row(&row, 80);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 20)).unwrap();
    terminal
        .draw(|frame| frame.render_widget(Paragraph::new(lines), frame.area()))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let rendered = format!("{buffer:?}");
    assert!(rendered.contains("high · Untrusted repository paths"));
    assert!(
        rendered.find("high ·").unwrap()
            < rendered.find("found in 2 of 3 completed passes").unwrap()
    );
    assert!(rendered.contains("finding-exact-identity"));
    assert!(rendered.contains("run-discovery-exact-reference-2"));
    assert!(!rendered.contains("..."));
}

#[test]
fn retained_only_observations_keep_guidance_and_provenance_at_every_width() {
    let mut row = long_row();
    row.seen = 0;
    for width in [40, 60, 80, 96, 120, 160] {
        let lines = batch_occurrence_row(&row, width);
        assert!(lines.iter().all(|line| line.width() <= width));
        let text = lines
            .iter()
            .map(|line| line.to_string().trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("Retained outside completed passes"));
        assert!(text.contains("found in 0 of 3 completed passes"));
        assert!(text.contains("run-discovery-exact-reference-1"));
    }
}
