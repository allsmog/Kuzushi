use super::*;
use kuzushi_core::capabilities::trace_expansion::{
    append_trace_expansion_evidence, list_operator_trace_steps, TraceExpansionResult,
};
use kuzushi_core::static_evidence::StaticEvidenceStore;
use std::path::Path;

fn claim(symbol: &str) -> TraceStep {
    TraceStep {
        symbol: symbol.into(),
        file_path: "hello.txt".into(),
        line: 1,
        annotation: "Labeled synthetic source claim. No defect is asserted.".into(),
    }
}

fn append_claims(root: &Path, fingerprint: &str, steps: Vec<TraceStep>) {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let store = StaticEvidenceStore::open(&workspace).unwrap();
    append_trace_expansion_evidence(
        &store,
        &TraceExpansionResult {
            version: 1,
            finding_fingerprint: fingerprint.into(),
            steps,
            evidence_deltas: Vec::new(),
            open_questions: Vec::new(),
        },
    )
    .unwrap();
}

fn save_claims(root: &Path, run_id: &str, fingerprint: &str, steps: Vec<TraceStep>) {
    let record = ToolRunRecord::new(root, run_id, "tool", "trace:expand");
    let input = json!({"fingerprint":fingerprint});
    record_tool_run_started(record, &input);
    let tree = kuzushi_core::incremental_index::current_workspace_tree_hash(root).unwrap();
    let summary = format!(
        "Labeled synthetic trace receipt: {}",
        steps
            .iter()
            .map(|step| step.symbol.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let result = json!({"ok":true,"summary":summary,"output":summary,"data":{
        "tool":"trace:expand","version":1,"findingFingerprint":fingerprint,
        "steps":steps,"openQuestions":["Independent source review remains open"],
        "evidenceDeltas":["Labeled synthetic trace receipt"],"treeHash":tree
    }});
    let observation =
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(record.target, record.run_id)
            .unwrap();
    let call = kuzushi_core::modules::ApplicationToolCall::start(
        observation.clone(),
        "trace:expand",
        &input,
        None,
        None,
    )
    .unwrap();
    let completion = call.completion_from_result(&Ok(result.clone()));
    try_record_tool_run_complete_settled(record, &result, &observation, completion).unwrap();
}

#[test]
fn latest_zero_step_receipt_does_not_republish_earlier_steps() {
    let root = tempfile::tempdir().unwrap();
    append_claims(root.path(), "finding", vec![claim("earlier")]);
    save_claims(root.path(), "tool-1001-latest", "finding", vec![]);
    let snapshot = load_trace_snapshot(root.path(), "finding")
        .unwrap()
        .unwrap();
    assert!(snapshot.steps.is_empty());
    assert!(snapshot.last_outcome.unwrap().contains("0 new steps"));
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = StaticEvidenceStore::open(&workspace).unwrap();
    assert_eq!(
        list_operator_trace_steps(&store, "finding").unwrap().len(),
        1
    );
}

#[test]
fn latest_receipt_keeps_its_exact_steps_instead_of_a_historical_union() {
    let root = tempfile::tempdir().unwrap();
    append_claims(root.path(), "finding", vec![claim("earlier")]);
    save_claims(
        root.path(),
        "tool-1001-latest",
        "finding",
        vec![claim("current")],
    );
    let snapshot = load_trace_snapshot(root.path(), "finding")
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.steps.len(), 1);
    assert_eq!(snapshot.steps[0].symbol, "current");
    assert!(snapshot.last_outcome.unwrap().contains("source unchanged"));
}

#[test]
fn source_change_keeps_the_recorded_claim_and_requires_reassessment() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("hello.txt"), "Owned first revision\n").unwrap();
    save_claims(
        root.path(),
        "tool-1001-latest",
        "finding",
        vec![claim("recorded")],
    );
    std::fs::write(root.path().join("hello.txt"), "Owned second revision\n").unwrap();
    let snapshot = load_trace_snapshot(root.path(), "finding")
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.steps[0].symbol, "recorded");
    assert!(snapshot.last_outcome.unwrap().contains("source changed"));
}

#[test]
fn legacy_steps_are_disclosed_without_a_current_source_receipt() {
    let root = tempfile::tempdir().unwrap();
    append_claims(root.path(), "finding", vec![claim("legacy")]);
    let snapshot = load_trace_snapshot(root.path(), "finding")
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.steps[0].symbol, "legacy");
    assert!(snapshot.last_outcome.is_none());
    assert!(snapshot.evidence_deltas[0].contains("no per-run source binding"));
}

#[test]
fn review_opens_the_trace_and_back_restores_its_exact_focus_without_work() {
    use crate::ui_view_models::{Composition, PhaseSurfaceId};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    *app.findings_mut() = vec![kuzushi_core::Finding::new_tool(
        "owned-fixture",
        "greeting",
        "hello.txt",
        1,
        None,
        kuzushi_core::Severity::Info,
        "Labeled owned greeting. No defect is claimed.",
    )];
    app.set_shell_view(crate::app::ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewDetail);
    app.set_input_mode(crate::InputMode::Navigate);
    app.reduce_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::empty()));
    assert!(app.router.workbench().trace_view_open());
    let plan = crate::renderer::workbench_phase_plan_for_app(
        &app,
        ratatui::layout::Rect::new(0, 0, 120, 36),
    )
    .unwrap();
    assert!(matches!(
        plan.composition,
        Composition::FullScreen(PhaseSurfaceId::ReviewTrace)
    ));
    assert!(!app.tool_is_running());
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!app.router.workbench().trace_view_open());
    assert_eq!(
        app.router
            .workbench()
            .focus_for(crate::app::WorkbenchPage::Review),
        PhaseSurfaceId::ReviewDetail
    );
    assert!(app.input().is_empty());
}

fn prepare_source_history(root: &Path, fingerprint: &str) -> (String, String) {
    let earlier_run = kuzushi_core::run_artifacts::new_run_id("tool-earlier-trace");
    std::fs::write(
        root.join("hello.txt"),
        "Owned first greeting revision. Never executed.\n",
    )
    .unwrap();
    let earlier = vec![claim("EARLIER GREETING CLAIM")];
    append_claims(root, fingerprint, earlier.clone());
    save_claims(root, &earlier_run, fingerprint, earlier);
    std::fs::write(
        root.join("hello.txt"),
        "Owned second greeting revision. Never executed.\n",
    )
    .unwrap();
    let current = vec![claim("CURRENT GREETING CLAIM")];
    let current_run = kuzushi_core::run_artifacts::new_run_id("tool-current-trace");
    append_claims(root, fingerprint, current.clone());
    save_claims(root, &current_run, fingerprint, current);
    (earlier_run, current_run)
}

#[test]
fn prepare_native_trace_history_fixture() {
    let owned = tempfile::tempdir().unwrap();
    prepare_source_history(owned.path(), "finding");
    let snapshot = load_trace_snapshot(owned.path(), "finding")
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.steps.len(), 1);
    assert_eq!(snapshot.steps[0].symbol, "CURRENT GREETING CLAIM");
    let Some(root) = std::env::var_os("KUZUSHI_TRACE_FIXTURE_OUT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(".kuzushi/lesson-fixture.json")).unwrap())
            .unwrap();
    assert_eq!(receipt["findingsAreSynthetic"], true);
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = kuzushi_core::findings::FindingStore::open(workspace.findings_db_path()).unwrap();
    let rows = store.list_all_findings().unwrap();
    assert_eq!(rows.len(), 1);
    let (earlier_run, current_run) = prepare_source_history(workspace.root(), &rows[0].fingerprint);
    std::fs::write(
        root.join(".kuzushi/trace-fixture.json"),
        serde_json::to_vec_pretty(&json!({
            "findingsAreSynthetic":true,"providerRequests":0,"sourceExecuted":false,
            "fingerprint":rows[0].fingerprint,"earlierRun":earlier_run,
            "currentRun":current_run
        }))
        .unwrap(),
    )
    .unwrap();
}
