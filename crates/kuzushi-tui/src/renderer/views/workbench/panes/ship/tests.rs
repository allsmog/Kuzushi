use super::*;
use crate::ui_view_models::ReportPreviewRow;

#[test]
fn report_preview_row_names_decision_conflict() {
    let row = ReportPreviewRow {
        alias: "F-0001".to_string(),
        identity_label: "FI-01234567".to_string(),
        severity: "HIGH".to_string(),
        confidence: "91%".to_string(),
        decision: "rejected_false_positive".to_string(),
        decision_conflict: Some("reappeared_after_rejection".to_string()),
        lifecycle_status: "statically_supported".to_string(),
        evidence_state: "observed".to_string(),
        provenance: "run:run-rerun".to_string(),
        tool: "semgrep".to_string(),
        title: "reappeared finding".to_string(),
        location: "src/lib.rs:55".to_string(),
    };

    let text = line_text(report_preview_row_line(&row, 220));

    assert!(
        text.contains("decision:rejected_false_positive conflict:reappeared_after_rejection"),
        "{text}"
    );
    assert!(text.contains("status:statically_supported"), "{text}");
}

#[test]
fn patch_empty_state_names_runtime_verification_not_exploit() {
    let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let text = lines_text(ship_patch_lines(&app, 120));

    assert!(
        text.contains("run runtime verification for selected finding"),
        "{text}"
    );
    assert!(!text.contains("verify:exploit"), "{text}");
}

#[test]
fn export_preview_uses_active_review_completeness_filter() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_active_findings_filter(Some("completeness:open".to_string()));
    *app.findings_mut() = vec![
        kuzushi_core::Finding::new_tool(
            "semgrep",
            "demo/open",
            "src/app.rs",
            12,
            None,
            kuzushi_core::Severity::High,
            "needs review",
        ),
        confirmed_finding(),
    ];

    let text = lines_text(ship_export_lines(&app, 180));

    assert!(text.contains("1 of 2 findings in preview"), "{text}");
    assert!(text.contains("format:sarif completeness:open"), "{text}");
    assert!(
        text.contains("findings export report.sarif sarif --completeness open"),
        "{text}"
    );
    assert!(
        text.contains(
            "workspace export findings report-bundle markdown-bundle --completeness open"
        ),
        "{text}"
    );
    assert!(!text.contains("report.md"), "{text}");
    assert!(text.contains("decision:needs_review"), "{text}");
    assert!(!text.contains("decision:confirmed"), "{text}");
}

fn confirmed_finding() -> kuzushi_core::Finding {
    let mut finding = kuzushi_core::Finding::new_tool(
        "semgrep",
        "demo/confirmed",
        "src/app.rs",
        24,
        None,
        kuzushi_core::Severity::Medium,
        "confirmed finding",
    );
    finding.triage = Some(kuzushi_core::TriageOutcome {
        verdict: kuzushi_core::TriageVerdict::TruePositive,
        confidence: 0.9,
        rationale: "operator confirmed".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
    });
    finding.triaged_by = Some(kuzushi_core::findings::TriageAuthor::Human);
    finding
}

fn line_text(line: Line<'static>) -> String {
    line.spans
        .into_iter()
        .map(|span| span.content.into_owned())
        .collect()
}

fn lines_text(lines: Vec<Line<'static>>) -> String {
    lines
        .into_iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n")
}
