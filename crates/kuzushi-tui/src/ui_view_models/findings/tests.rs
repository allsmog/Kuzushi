use super::*;
use kuzushi_core::{
    Finding, FindingEvidence, RunSummary, RunTargetGitMetadata, Severity, TriageOutcome,
    TriageVerdict, V2Config,
};
use std::collections::BTreeMap;

#[test]
fn findings_model_projects_counts_rows_and_selection() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut high = Finding::new_semgrep(
        "demo.sql",
        "src/search.ts",
        12,
        Some(14),
        Severity::High,
        "SQL injection\nEvidence: query reaches db.query\nCWE: CWE-89",
    );
    high.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "source and sink are linked".to_string(),
        cost_usd: 0.0,
    });
    let medium = Finding::new_tool(
        "codeql",
        "js/path-injection",
        "src/files.ts",
        22,
        None,
        Severity::Medium,
        "Path traversal candidate",
    );
    app.selected_finding = Some(high.clone());
    app.findings = vec![high, medium];

    let model = findings_model(&app);

    assert_eq!(model.total, 2);
    assert_eq!(model.triaged, 1);
    assert_eq!(model.pending, 1);
    assert_eq!(model.counts.high, 1);
    assert_eq!(model.counts.medium, 1);
    assert_eq!(model.header, "FINDINGS · 2 · 1 triaged · 1 pending");
    assert_eq!(model.rows[0].alias, "F-0001");
    assert_eq!(model.rows[0].severity_label, "HIGH");
    assert_eq!(model.rows[0].location, "src/search.ts:12-14");
    assert_eq!(model.rows[0].run_label, "run:unknown");
    assert_eq!(model.rows[0].revision_label, "rev:unknown");
    assert_eq!(model.rows[0].verdict, "tp");
    assert_eq!(model.rows[0].confidence, "91%");
    assert_eq!(model.rows[0].source, "semgrep:demo.sql");
    assert!(model.rows[0].selected);
    assert_eq!(model.preview.header, "FINDINGS · 1 triaged · 1 pending");
    assert_eq!(model.preview.rows.len(), 2);
    assert!(model.preview.overflow.is_none());
}

#[test]
fn finding_run_provenance_uses_run_summary_target_revision() {
    let mut finding = Finding::new_tool(
        "demo",
        "demo.rule",
        "src/lib.rs",
        7,
        None,
        Severity::Medium,
        "finding with run provenance",
    );
    finding.scan_id = Some("scan-run-provenance-123456".to_string());
    let summary = RunSummary::running(
        "scan-run-provenance-123456",
        "scan",
        Some("sast:scan".to_string()),
        ".",
    )
    .with_target_git(Some(RunTargetGitMetadata {
        sha: "abcdef1234567890".to_string(),
        branch: Some("main".to_string()),
        dirty: true,
    }));
    let runs = BTreeMap::from([(summary.run_id.clone(), summary)]);

    let provenance = finding_run_provenance(&finding, &runs);

    assert_eq!(provenance.run_label, "run:scan-r..3456");
    assert_eq!(provenance.revision_label, "rev:abcdef1*");
}

#[test]
fn findings_model_describes_context_prereq_when_empty() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = findings_model(&app);

    assert_eq!(model.total, 0);
    assert!(model.rows.is_empty());
    assert_eq!(
        model.empty.context_cta,
        Some((
            "context build",
            "optional: index the repo first for richer analysis."
        ))
    );
}

#[test]
fn findings_model_surfaces_malformed_context_prereq_when_empty() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.context_view.status = "malformed context snapshot. Next: context build".to_string();

    let model = findings_model(&app);

    assert_eq!(
        model.empty.hint,
        "context snapshot is malformed; rebuild it before scanning."
    );
    assert_eq!(
        model.empty.context_cta,
        Some(("context build", "rewrite the malformed snapshot first"))
    );
}

#[test]
fn findings_model_caps_module_preview_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.findings = (0..10)
        .map(|index| {
            Finding::new_tool(
                "semgrep",
                &format!("rule-{index}"),
                &format!("src/file_{index}.rs"),
                index + 1,
                None,
                Severity::Low,
                "preview finding",
            )
        })
        .collect();

    let model = findings_model(&app);

    assert_eq!(model.preview.header, "FINDINGS · 0 triaged · 10 pending");
    assert_eq!(model.preview.rows.len(), 8);
    assert_eq!(
        model.preview.overflow,
        Some(FindingsPreviewOverflow {
            label: "… 2 more · ".to_string(),
            command: "/findings",
            suffix: " to drill in",
        })
    );
}

#[test]
fn selected_finding_detail_model_bounds_evidence_and_message() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let finding = Finding::new_semgrep(
        "demo.rule",
        "src/app.ts",
        8,
        Some(8),
        Severity::High,
        "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9",
    )
    .with_evidence(
        (0..10)
            .map(|index| FindingEvidence {
                kind: "filesystem_sink".to_string(),
                file_path: "src/app.ts".to_string(),
                line: 8 + index,
                snippet: "file.save(filepath)".to_string(),
                rationale: "Raw upload path reaches a filesystem write".to_string(),
                confidence: 92,
                ..Default::default()
            })
            .collect(),
    );
    app.findings = vec![finding.clone()];
    app.selected_finding = Some(finding);

    let model = selected_finding_detail_model(&app).expect("selected finding");

    assert_eq!(model.alias.as_deref(), Some("F-0001"));
    assert_eq!(model.severity_label, "high");
    assert_eq!(model.location, "src/app.ts:8");
    assert_eq!(
        model.evidence[0].header,
        "filesystem_sink · conf 92 · src/app.ts:8"
    );
    assert_eq!(model.message_lines.len(), 8);
    assert_eq!(model.message_overflow, 1);
    assert_eq!(model.evidence.len(), 8);
    assert_eq!(model.evidence_overflow, 2);
}

#[test]
fn selected_out_of_window_finding_drives_detail_with_notice() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let visible = Finding::new_tool(
        "demo",
        "visible.rule",
        "src/visible.rs",
        3,
        None,
        Severity::Medium,
        "visible finding",
    );
    let opened = Finding::new_tool(
        "demo",
        "opened.rule",
        "src/opened.rs",
        9,
        None,
        Severity::High,
        "opened outside loaded list",
    );
    app.findings = vec![visible];
    app.findings_cursor = 0;
    app.selected_finding = Some(opened.clone());

    let list = findings_model(&app);
    let detail = selected_finding_detail_model(&app).expect("opened detail");

    assert!(list.selected_out_of_window.is_some());
    assert!(!list.rows[0].selected);
    assert_eq!(detail.alias, None);
    assert_eq!(detail.title, opened.title);
    assert_eq!(detail.location, "src/opened.rs:9");
}
