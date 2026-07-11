use super::*;
use kuzushi_core::findings::{
    ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict, TriageAuthor,
};
use kuzushi_core::{
    write_run_summary, Finding, RunSummary, Severity, StaticProofState, TriageOutcome,
    TriageVerdict, V2Config, WorkspaceTarget,
};

fn finding(rule: &str, severity: Severity, line: u32) -> Finding {
    Finding::new_tool("semgrep", rule, "src/lib.rs", line, None, severity, rule)
}

fn confirmed(mut finding: Finding) -> Finding {
    finding.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.88,
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

#[test]
fn report_preview_model_uses_export_projection_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    kuzushi_core::write_run_summary(
        workspace.root(),
        &kuzushi_core::RunSummary::running(
            "run-123",
            "tool",
            None,
            workspace.root().display().to_string(),
        )
        .complete(),
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let mut open = finding("path-traversal", Severity::High, 20);
    open.identity_id = Some("fi_0123456789abcdef0123456789abcdef".to_string());
    *app.findings_mut() = vec![
        open,
        confirmed(finding("sql-injection", Severity::Medium, 40)),
    ];
    app.hydrate_all_view_data_for_test();

    let model = report_preview_model(&app, WorkspaceExportFormat::Csv, ReviewQueueMode::All);

    assert_eq!(model.format, "csv");
    assert_eq!(model.completeness, "all");
    assert_eq!(model.latest_run_id.as_deref(), Some("run-123"));
    assert!(model.generated_at.starts_with("unix:"));
    assert!(model.generated_at["unix:".len()..].parse::<u64>().is_ok());
    assert_eq!(
        model.preview_metadata,
        "preview-only; export projection; writes no review state"
    );
    assert_eq!(model.counts.total_findings, 2);
    assert_eq!(model.counts.included_findings, 2);
    assert_eq!(model.counts.open_decisions, 1);
    assert_eq!(model.counts.terminal_decisions, 1);
    assert_eq!(model.counts.included_open_decisions, 1);
    assert_eq!(model.counts.included_terminal_decisions, 1);
    assert_eq!(model.counts.high, 1);
    assert_eq!(model.counts.medium, 1);
    assert!(model.omitted_fields.contains(&"reviewDecisionReason"));
    assert!(model
        .omitted_fields
        .contains(&"evidence.rawHttpBlobPresent"));
    assert!(model
        .rows
        .iter()
        .any(|row| row.identity_label == "FI-01234567"));
    assert!(model.rows.iter().any(|row| row.decision == "confirmed"));
    assert!(model.rows.iter().any(|row| row.decision == "needs_review"));
}

#[test]
fn report_preview_open_mode_includes_only_open_decisions() {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![
        finding("path-traversal", Severity::High, 20),
        confirmed(finding("sql-injection", Severity::Medium, 40)),
    ];

    let model = report_preview_model(&app, WorkspaceExportFormat::Sarif, ReviewQueueMode::Open);

    assert_eq!(model.completeness, "open");
    assert_eq!(model.counts.total_findings, 2);
    assert_eq!(model.counts.included_findings, 1);
    assert_eq!(model.counts.open_decisions, 1);
    assert_eq!(model.counts.terminal_decisions, 1);
    assert_eq!(model.counts.included_open_decisions, 1);
    assert_eq!(model.counts.included_terminal_decisions, 0);
    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].decision, "needs_review");
    assert!(model.omitted_fields.contains(&"references"));
}

#[test]
fn report_preview_open_mode_uses_identity_review_state() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = finding("sql-injection", Severity::High, 40);
    reviewed.identity_id = Some(identity_id.clone());
    reviewed.id = Some(1);
    reviewed.created_at = "2026-07-01T00:00:00Z".to_string();

    let mut rerun = finding("sql-injection-rerun", Severity::Medium, 42);
    rerun.identity_id = Some(identity_id);
    rerun.id = Some(2);
    assert!(rerun.triage.is_none());

    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![human_confirmed(reviewed, 0.87), rerun];

    let model = report_preview_model(&app, WorkspaceExportFormat::Json, ReviewQueueMode::Open);

    assert_eq!(model.counts.total_findings, 2);
    assert_eq!(model.counts.included_findings, 0);
    assert_eq!(model.counts.open_decisions, 0);
    assert_eq!(model.counts.terminal_decisions, 2);
    assert_eq!(model.counts.included_open_decisions, 0);
    assert_eq!(model.counts.included_terminal_decisions, 0);
    assert!(model.rows.is_empty());
}

#[test]
fn report_preview_counts_deferred_decision_as_terminal() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut finding = finding("manual-defer", Severity::High, 55);
    finding.id = Some(1);
    finding.identity_id = Some(identity_id.clone());

    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![finding];
    app.set_review_decisions(vec![ReviewDecisionRecord {
        id: 9,
        finding_id: 1,
        identity_id: Some(identity_id),
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::Deferred,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "deferred for owner review".to_string(),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: None,
        created_at: "2026-07-03T00:00:00Z".to_string(),
    }]);

    let all_model = report_preview_model(&app, WorkspaceExportFormat::Json, ReviewQueueMode::All);
    assert_eq!(all_model.counts.total_findings, 1);
    assert_eq!(all_model.counts.open_decisions, 0);
    assert_eq!(all_model.counts.terminal_decisions, 1);
    assert_eq!(all_model.counts.included_open_decisions, 0);
    assert_eq!(all_model.counts.included_terminal_decisions, 1);
    assert_eq!(all_model.rows[0].decision, "deferred");

    let open_model = report_preview_model(&app, WorkspaceExportFormat::Json, ReviewQueueMode::Open);
    assert_eq!(open_model.counts.included_findings, 0);
    assert_eq!(open_model.counts.included_open_decisions, 0);
    assert_eq!(open_model.counts.included_terminal_decisions, 0);
    assert!(open_model.rows.is_empty());
}

#[test]
fn report_preview_keeps_reappeared_rejected_identity_open() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = finding("manual-reject", Severity::High, 55);
    reviewed.id = Some(1);
    reviewed.identity_id = Some(identity_id.clone());

    let mut rerun = finding("manual-reject", Severity::High, 55);
    rerun.id = Some(2);
    rerun.identity_id = Some(identity_id.clone());
    rerun.scan_id = Some("run-rerun".to_string());
    rerun.static_proof_state = Some(StaticProofState::SourceSinkLinked);

    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![reviewed, rerun];
    app.set_review_decisions(vec![ReviewDecisionRecord {
        id: 10,
        finding_id: 1,
        identity_id: Some(identity_id),
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::RejectedFalsePositive,
            author: TriageAuthor::Human,
            confidence: 0.91,
            rationale: "operator rejected prior occurrence".to_string(),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: Some(TriageVerdict::FalsePositive),
        created_at: "2026-07-03T00:00:00Z".to_string(),
    }]);

    let open_model = report_preview_model(&app, WorkspaceExportFormat::Json, ReviewQueueMode::Open);

    assert_eq!(open_model.counts.total_findings, 2);
    assert_eq!(open_model.counts.open_decisions, 1);
    assert_eq!(open_model.counts.terminal_decisions, 1);
    assert_eq!(open_model.counts.included_findings, 1);
    assert_eq!(open_model.rows[0].decision, "rejected_false_positive");
    assert_eq!(
        open_model.rows[0].decision_conflict.as_deref(),
        Some("reappeared_after_rejection")
    );
    assert_eq!(open_model.rows[0].lifecycle_status, "statically_supported");
}

#[test]
fn report_preview_rows_come_from_export_projection() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut finding = human_confirmed(finding("sql-injection", Severity::High, 40), 0.87);
    finding.identity_id = Some("fi_0123456789abcdef0123456789abcdef".to_string());
    finding.evidence.push(kuzushi_core::FindingEvidence {
        kind: "sink".to_string(),
        file_path: "src/lib.rs".to_string(),
        line: 40,
        snippet: "db.query(q)".to_string(),
        rationale: "query sink".to_string(),
        confidence: 91,
        ..Default::default()
    });
    *app.findings_mut() = vec![finding];

    let model = report_preview_model(&app, WorkspaceExportFormat::Json, ReviewQueueMode::All);

    assert_eq!(model.rows.len(), 1);
    let row = &model.rows[0];
    assert_eq!(row.identity_label, "FI-01234567");
    assert_eq!(row.severity, "HIGH");
    assert_eq!(row.confidence, "87%");
    assert_eq!(row.decision, "confirmed");
    assert_eq!(row.evidence_state, "observed");
    assert_eq!(row.location, "src/lib.rs:40");
    assert_eq!(row.provenance, "-");
}

#[test]
fn report_preview_rows_include_run_summary_provenance() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut summary = RunSummary::running(
        "run-preview",
        "scan",
        Some("sast:scan".to_string()),
        workspace.root().display().to_string(),
    )
    .complete();
    summary.findings = Some(1);
    summary.model = Some("openai:gpt-test".to_string());
    summary.platform = Some("codex".to_string());
    write_run_summary(workspace.root(), &summary).unwrap();

    let mut finding = human_confirmed(finding("sql-injection", Severity::High, 40), 0.87);
    finding.scan_id = Some("run-preview".to_string());
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    *app.findings_mut() = vec![finding];

    let model = report_preview_model(&app, WorkspaceExportFormat::Json, ReviewQueueMode::All);

    assert_eq!(model.rows.len(), 1);
    let provenance = &model.rows[0].provenance;
    assert!(provenance.contains("run:run-preview"), "{provenance}");
    assert!(provenance.contains("status:completed"), "{provenance}");
    assert!(provenance.contains("model:openai:gpt-test"), "{provenance}");
    assert!(provenance.contains("runtime:codex"), "{provenance}");
}
