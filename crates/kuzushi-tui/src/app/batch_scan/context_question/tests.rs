use super::*;
use crate::app::{InputMode, ShellView};
use crate::test_support::{append_typed_attempt, record_indexed_run, select_typed_attempt};
use kuzushi_core::{ToolExecutionContext, V2Config, WorkspaceTarget};

fn fixture() -> (tempfile::TempDir, ShellApp, serde_json::Value) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("note.md"),
        "Owned inert architecture example.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..Default::default()
        },
        None,
    );
    app.set_target(Some(root.path().into()));
    app.set_shell_view(ShellView::Workbench);
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let output=app.registry().execute_tool("threat-model:import",json!({"document":{"version":"1","methodology":"stride","systemContext":"Owned app formats greetings","dfd":{"nodes":[{"id":"app","name":"App","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}}),&ctx).unwrap();
    record_indexed_run(
        root.path(),
        "accepted-question-map",
        "threat-model:import",
        output.clone(),
    );
    let completed = append_typed_attempt(
        root.path(),
        kuzushi_core::WorkflowPhase::Map,
        "accepted-question-map",
        kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
    );
    select_typed_attempt(root.path(), &completed);
    app.refresh_phase_attempt_projection();
    app.hydrate_all_view_data_for_test();
    (root, app, output["data"]["modelRef"].clone())
}

#[test]
fn planning_question_preserves_text_and_context_without_starting_a_worker() {
    let (_root, mut app, reference) = fixture();
    app.plan_context_question("Explain app\nPreserve α", "Captured operator notes")
        .unwrap();
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.input_mode(), InputMode::Navigate);
    let generation = app.context_generation().unwrap();
    assert!(generation.is_question());
    assert!(generation.receipt.is_none());
    assert_eq!(generation.context_input["threatModelRef"], reference);
    assert_eq!(
        generation.context_input["question"],
        "Explain app\nPreserve α"
    );
    assert!(!app.has_running_work());
}

#[test]
fn question_editor_keeps_question_separate_from_model_guidance() {
    let (_root, mut app, _) = fixture();
    app.plan_context_question("Original question", "").unwrap();
    app.edit_regeneration_guidance();
    app.capture_regeneration_guidance_paste("\nAdditional α");
    app.handle_regeneration_guidance_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('s'),
        crossterm::event::KeyModifiers::CONTROL,
    ));
    let generation = app.context_generation().unwrap();
    assert!(generation.context_input["question"]
        .as_str()
        .unwrap()
        .contains("Additional α"));
    assert!(generation.context_input.get("guidance").is_none());
    assert!(generation.receipt.is_none());
}

#[test]
fn question_without_accepted_context_provides_recovery_without_work() {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    assert!(app
        .plan_context_question("Where does input go?", "")
        .unwrap_err()
        .to_string()
        .contains("Accept a current Map"));
    assert!(!app.has_running_work());
    assert!(app.router.campaign().batch_scan_config.is_none());
}

#[test]
fn failed_question_plan_keeps_inputs_and_discloses_no_request_started() {
    let (_root, mut app, reference) = fixture();
    app.plan_context_question("Explain app\nKeep α", "Owned operator notes")
        .unwrap();
    app.study_preparation_failed(
        "campaign:context-study",
        "Source changed before preparation",
    );
    let generation = app.context_generation().unwrap();
    assert_eq!(generation.context_input["question"], "Explain app\nKeep α");
    assert_eq!(generation.context_input["threatModelRef"], reference);
    assert!(generation.receipt.is_none());
    let notice = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_ref()
        .unwrap();
    assert!(notice.contains("Plan preparation blocked"));
    assert!(notice.contains("No model request started"));
    assert!(!app.has_running_work());
}
