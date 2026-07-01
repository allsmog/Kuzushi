use super::*;
use crate::app::ScanPanelState;
use kuzushi_core::{Finding, Severity, TriageOutcome, TriageVerdict, V2Config};
use std::path::PathBuf;

fn app() -> ShellApp {
    ShellApp::new(V2Config::default(), None)
}

#[test]
fn workbench_context_includes_focus_selected_item_and_visible_rows() {
    let mut app = app();
    let mut finding = Finding::new_tool(
        "demo-tool",
        "demo.rule",
        "src/lib.rs",
        42,
        None,
        Severity::High,
        "screen context item",
    );
    finding.triage = Some(TriageOutcome {
        verdict: TriageVerdict::NeedsReview,
        confidence: 0.75,
        rationale: "needs human review".to_string(),
        cost_usd: 0.0,
    });
    app.findings = vec![finding.clone()];
    app.selected_finding = Some(finding);
    app.shell_view = ShellView::Workbench;
    app.workbench_focus = WorkbenchPane::Details;
    app.scan = Some(ScanPanelState {
        run_id: Some("scan-run-1".to_string()),
        target: PathBuf::from("."),
        stage: "done".to_string(),
        findings_count: 1,
        running: false,
        abort_requested: false,
        error: None,
    });

    let context = screen_context_model(&app);

    assert_eq!(context.view, "Workbench");
    assert_eq!(context.focused_pane.as_deref(), Some("Details"));
    assert_eq!(context.selected_run.as_deref(), Some("scan-run-1"));
    assert_eq!(context.visible_rows.len(), 1);
    let selected = context.selected_item.unwrap();
    assert_eq!(selected.file, "src/lib.rs");
    assert_eq!(selected.line, 42);
    assert_eq!(selected.rank, "high");
    assert_eq!(selected.state, "needs_review");
    assert_eq!(selected.confirmation, "unconfirmed");
}

#[test]
fn prompt_json_is_structured_and_bounded() {
    let context = ScreenContext {
        view: "Workbench".to_string(),
        focused_pane: Some("Findings".to_string()),
        selected_item: None,
        selected_run: Some("run-1".to_string()),
        selected_revision: Some(ScreenRevision {
            sha: "abc123".to_string(),
            branch: Some("main".to_string()),
            dirty: true,
        }),
        active_phase: Some("hunt".to_string()),
        active_filters: vec!["state:new".to_string()],
        selected_scope: Some("repo".to_string()),
        visible_rows: vec!["visible row".to_string()],
        cursor: ScreenCursor { row: 2, col: 5 },
    };

    let json = context.to_prompt_json();

    assert!(json.contains("\"view\": \"Workbench\""));
    assert!(json.contains("\"focusedPane\": \"Findings\""));
    assert!(json.contains("\"selectedRun\": \"run-1\""));
    assert!(json.contains("\"dirty\": true"));
    assert!(json.contains("\"cursor\""));
}

#[test]
fn screen_context_prefers_active_nested_scope() {
    let mut app = app();
    app.active_scope = Some(crate::app::TargetCandidateScope {
        id: "submodule-libs-parser".to_string(),
        kind: kuzushi_core::NestedProjectKind::Submodule,
        rel_path: "libs/parser".to_string(),
    });

    let model = screen_context_model(&app);

    assert_eq!(model.selected_scope.as_deref(), Some("libs/parser"));
}
