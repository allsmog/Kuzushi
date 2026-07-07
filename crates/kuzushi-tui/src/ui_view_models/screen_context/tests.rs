use super::*;
use crate::app::ScanPanelState;
use kuzushi_core::{
    Finding, FindingEvidence, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, Severity, StaticProofState, TriageOutcome, TriageVerdict, V2Config,
};
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
    finding.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    finding.verification = Some(PersistedVerification {
        proof_level: 2,
        proof_verdict: PersistedProofVerdict::NotReproduced,
        backend: PersistedSandboxBackend::Plain,
        language: Some("rust".to_string()),
        harness_path: Some(".kuzushi/harness.rs".to_string()),
        crash_evidence: Some("harness ran without reproducing the crash".to_string()),
        duration_ms: 42,
        cost_usd: 0.0,
        notes: vec!["runtime path did not reach the sink".to_string()],
        created_at: "2026-07-02T00:00:00Z".to_string(),
    });
    finding.evidence = vec![FindingEvidence {
        kind: "code".to_string(),
        file_path: "src/lib.rs".to_string(),
        line: 42,
        snippet: "sink(user_input);".to_string(),
        rationale: "untrusted input reaches the sink".to_string(),
        confidence: 99,
        request_blob: None,
        response_blob: None,
    }];
    *app.findings_mut() = vec![finding.clone()];
    *app.selected_finding_mut() = Some(finding);
    app.set_shell_view(ShellView::Workbench);
    app.router.workbench_mut().set_focus(WorkbenchPane::Details);
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("scan-run-1".to_string()),
        target: PathBuf::from("."),
        stage: "done".to_string(),
        findings_count: 1,
        running: false,
        abort_requested: false,
        error: None,
    }));

    let context = screen_context_model(&app);

    assert_eq!(context.view, "Workbench");
    assert_eq!(context.focused_pane.as_deref(), Some("Details"));
    assert_eq!(context.selected_run.as_deref(), Some("scan-run-1"));
    assert_eq!(context.visible_rows.len(), 1);
    let selected = context.selected_item.as_ref().expect("selected item");
    assert_eq!(selected.file, "src/lib.rs");
    assert_eq!(selected.line, 42);
    assert_eq!(selected.rank, "high");
    assert_eq!(selected.state, "needs_review");
    assert_eq!(selected.runtime_verification, "not_reproduced");
    let triage = selected.triage.as_ref().expect("triage context");
    assert_eq!(triage.confidence, "0.75");
    assert_eq!(triage.rationale, "needs human review");
    assert_eq!(selected.proof.static_label, "path-linked");
    assert_eq!(selected.proof.runtime_label, "not reproduced");
    assert_eq!(
        selected.proof.next_command.as_deref(),
        Some("verify F-0001")
    );
    let verification = selected
        .proof
        .verification
        .as_ref()
        .expect("verification context");
    assert_eq!(verification.verdict, "not_reproduced");
    assert_eq!(verification.backend, "plain");
    assert_eq!(
        verification.notes,
        vec!["runtime path did not reach the sink"]
    );
    assert_eq!(selected.evidence.len(), 1);
    assert_eq!(
        selected.evidence[0].rationale,
        "untrusted input reaches the sink"
    );
    let summary = context.finding_summary.expect("finding summary");
    assert_eq!(summary.total, 1);
    assert_eq!(summary.by_severity[0].label, "high");
    assert_eq!(summary.by_proof_state[0].label, "not_reproduced");
    assert!(summary.runtime_proof_by_severity.is_empty());
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
        finding_summary: None,
        visible_rows: vec!["visible row".to_string()],
        cursor: ScreenCursor { row: 2, col: 5 },
    };

    let json = context.to_prompt_json();

    assert!(json.contains("\"view\": \"Workbench\""));
    assert!(json.contains("\"focusedPane\": \"Findings\""));
    assert!(json.contains("\"selectedRun\": \"run-1\""));
    assert!(json.contains("\"dirty\": true"));
    assert!(json.contains("\"scopeLabel\": \"scope: repo · 崩 hunt · abc123-dirty\""));
    assert!(json.contains("\"cursor\""));
}

#[test]
fn scope_chip_prefers_selected_finding_then_phase_and_revision() {
    let context = ScreenContext {
        view: "AgentChat".to_string(),
        focused_pane: None,
        selected_item: Some(ScreenSelectedItem {
            alias: Some("F-0001".to_string()),
            fingerprint: "fp-demo".to_string(),
            title: "demo".to_string(),
            file: "src/lib.rs".to_string(),
            line: 1,
            rank: "high".to_string(),
            state: "true_positive".to_string(),
            runtime_verification: "not_verified".to_string(),
            triage: None,
            proof: ScreenProofContext {
                static_label: "not recorded".to_string(),
                static_explanation: "no static proof recorded".to_string(),
                runtime_label: "not verified".to_string(),
                runtime_explanation: "runtime verification has not run".to_string(),
                verification: None,
                next_action: "validate".to_string(),
                next_command: Some("verify F-0001".to_string()),
                next_detail: "collect runtime proof".to_string(),
            },
            evidence: Vec::new(),
        }),
        selected_run: None,
        selected_revision: Some(ScreenRevision {
            sha: "abc1234fedcba".to_string(),
            branch: Some("main".to_string()),
            dirty: true,
        }),
        active_phase: Some("confirm".to_string()),
        active_filters: Vec::new(),
        selected_scope: Some("repo".to_string()),
        finding_summary: None,
        visible_rows: Vec::new(),
        cursor: ScreenCursor { row: 0, col: 0 },
    };

    assert_eq!(
        context.scope_chip().as_deref(),
        Some("scope: F-0001 · 作 confirm · abc1234-dirty")
    );
}

#[test]
fn screen_context_prefers_active_nested_scope() {
    let mut app = app();
    app.set_active_scope(Some(crate::app::TargetCandidateScope {
        id: "submodule-libs-parser".to_string(),
        kind: kuzushi_core::NestedProjectKind::Submodule,
        rel_path: "libs/parser".to_string(),
    }));

    let model = screen_context_model(&app);

    assert_eq!(model.selected_scope.as_deref(), Some("libs/parser"));
}
