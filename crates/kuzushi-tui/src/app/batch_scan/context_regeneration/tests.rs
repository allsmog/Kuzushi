use super::*;
use crate::app::{ContextEditMode, EffectRuntime, ShellEffect};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{ThreatModelRef, ToolExecutionContext, V2Config, WorkspaceTarget};

fn dispatch(app: &ShellApp, root: &std::path::Path, tool: &str, input: Value) -> Value {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = app
        .registry()
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap();
    app.registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

fn fixture() -> (tempfile::TempDir, ShellApp, ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned fixture, never executed.\nfn main() {}\n",
    )
    .unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..Default::default()
        },
        None,
    );
    app.set_target(Some(root.path().into()));
    let document = json!({"version":"1","methodology":"stride","systemContext":"Operator overview","dfd":{"nodes":[{"id":"app","name":"App","type":"process","trustZone":"internal","description":"Operator description","purpose":"Original purpose"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}});
    let output = dispatch(
        &app,
        root.path(),
        "threat-model:import",
        json!({"document":document,"label":"Original","activate":false}),
    );
    let reference: ThreatModelRef =
        serde_json::from_value(output["data"]["modelRef"].clone()).unwrap();
    app.open_batch_scan_config(None);
    app.open_study_context_picker();
    app.edit_context_picker(|config| {
        config.context_picker.as_mut().unwrap().selected = Some(reference.clone())
    });
    let read = dispatch(
        &app,
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":reference}),
    );
    app.cache_study_context_preview(&read["data"]);
    app.open_context_editor();
    (root, app, reference)
}

fn key(app: &mut ShellApp, code: KeyCode) {
    let update = app
        .handle_context_edit_key(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap();
    EffectRuntime::execute(app, update.effects);
}

#[test]
fn regenerated_draft_does_not_dispatch_map_and_keeps_its_exact_selection() {
    let (_root, mut app, reference) = fixture();
    key(&mut app, KeyCode::Char('g'));
    app.edit_context_picker(|config| {
        config.context_generation.as_mut().unwrap().generated = Some(reference.clone());
    });
    let update = app.handle_context_generation_key(KeyCode::Char('m'));
    assert!(update.effects.is_empty());
    assert_eq!(
        app.context_generation().unwrap().generated.as_ref(),
        Some(&reference)
    );
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_deref()
        .unwrap()
        .contains("c checks the exact revision"));
}

#[test]
fn selected_field_plans_one_unstarted_regeneration_and_back_restores_editor_cursor() {
    let (root, mut app, reference) = fixture();
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    assert!(app.context_edit_draft().unwrap().entries[3]
        .label
        .contains("Purpose"));
    key(&mut app, KeyCode::Char('g'));
    let generation = app.context_generation().unwrap();
    assert!(generation.is_regeneration());
    assert_eq!(generation.context_input["threatModelRef"], json!(reference));
    assert_eq!(
        generation.context_input["fields"],
        json!(["/dfd/nodes/0/purpose"])
    );
    assert!(app.context_edit_draft().is_none());
    let update = app.handle_context_generation_key(KeyCode::Enter);
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("Shared context study dispatch required")
    };
    let receipt = dispatch(
        &app,
        root.path(),
        &request.tool_name,
        serde_json::from_str(request.input.as_ref().unwrap()).unwrap(),
    );
    app.cache_study_result("campaign:context-study", &receipt["data"]);
    assert_eq!(
        app.context_generation()
            .unwrap()
            .receipt
            .as_ref()
            .unwrap()
            .job_count(),
        1
    );
    app.handle_context_generation_key(KeyCode::Esc);
    assert!(app.context_generation().is_none());
    assert_eq!(app.context_edit_draft().unwrap().cursor, 3);
}

#[test]
fn unsaved_operator_edits_are_kept_and_refuse_regeneration_planning() {
    let (_root, mut app, _) = fixture();
    key(&mut app, KeyCode::Enter);
    assert!(app.capture_context_edit_paste("Unpublished operator addition"));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('g'));
    assert!(app.context_generation().is_none());
    let draft = app.context_edit_draft().unwrap();
    assert_eq!(draft.mode, ContextEditMode::Fields);
    assert!(draft.entries[1]
        .text()
        .contains("Unpublished operator addition"));
    assert!(draft
        .notice
        .as_deref()
        .unwrap()
        .contains("Save or explicitly discard"));
}

#[test]
fn guidance_owns_multiline_input_keeps_cursor_and_only_saved_guidance_enters_plan() {
    let (_root, mut app, _) = fixture();
    key(&mut app, KeyCode::Char('g'));
    app.handle_context_generation_key(KeyCode::Char('G'));
    assert!(app.capture_regeneration_guidance_paste("Clarify ownership\nUnicode α"));
    let cursor = app
        .context_generation()
        .unwrap()
        .guidance_editor
        .as_ref()
        .unwrap()
        .cursor();
    app.handle_regeneration_guidance_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.context_generation().unwrap().context_input["guidance"].is_null());
    assert!(app
        .handle_context_generation_key(KeyCode::Enter)
        .effects
        .is_empty());
    app.handle_context_generation_key(KeyCode::Char('G'));
    assert_eq!(
        app.context_generation()
            .unwrap()
            .guidance_editor
            .as_ref()
            .unwrap()
            .cursor(),
        cursor
    );
    app.handle_regeneration_guidance_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert_eq!(
        app.context_generation().unwrap().context_input["guidance"],
        "Clarify ownership\nUnicode α"
    );
    assert!(!app.context_generation().unwrap().guidance_editing);
}

fn edited_candidate(
    app: &mut ShellApp,
    root: &std::path::Path,
    parent: ThreatModelRef,
) -> ThreatModelRef {
    let output = dispatch(
        app,
        root,
        "threat-model:revise",
        json!({"threatModelRef":parent,
        "edits":[{"pointer":"/dfd/nodes/0/purpose","text":"Proposed purpose α"}]}),
    );
    let reference: ThreatModelRef =
        serde_json::from_value(output["data"]["modelRef"].clone()).unwrap();
    key(app, KeyCode::Esc);
    app.edit_context_picker(|config| {
        let picker = config.context_picker.as_mut().unwrap();
        picker.selected = Some(reference.clone());
        picker.preview = None;
    });
    let read = dispatch(
        app,
        root,
        "threat-model:read",
        json!({"threatModelRef":reference}),
    );
    app.cache_study_context_preview(&read["data"]);
    reference
}

#[test]
fn parent_comparison_preserves_candidate_and_only_loaded_comparison_can_select_it() {
    let (root, mut app, parent) = fixture();
    let candidate = edited_candidate(&mut app, root.path(), parent.clone());
    let update = app.compare_study_context();
    assert!(matches!(
        update.effects.as_slice(),
        [ShellEffect::PrepareRunTool(_)]
    ));
    let preview = app.study_context_picker().unwrap().preview.clone().unwrap();
    app.handle_context_comparison_key(KeyCode::Char('a'));
    assert!(app.study_context_picker().unwrap().comparison.is_some());
    let read = dispatch(
        &app,
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":parent}),
    );
    assert!(app.cache_study_context_preview(&read["data"]));
    assert_eq!(
        app.study_context_picker().unwrap().preview.as_ref(),
        Some(&preview)
    );
    let comparison = app
        .study_context_picker()
        .unwrap()
        .comparison
        .as_ref()
        .unwrap();
    assert_eq!(
        comparison.differences.as_ref().unwrap()[0].before,
        "Original purpose"
    );
    assert_eq!(
        comparison.differences.as_ref().unwrap()[0].after,
        "Proposed purpose α"
    );
    app.handle_context_comparison_key(KeyCode::Char('a'));
    assert!(app.study_context_picker().is_none());
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .scan_input
            .as_ref()
            .unwrap()["threatModelRef"],
        json!(candidate)
    );
}

#[test]
fn malformed_or_failed_parent_read_is_visible_and_retry_is_local() {
    let (root, mut app, parent) = fixture();
    edited_candidate(&mut app, root.path(), parent.clone());
    app.compare_study_context();
    let mut read = dispatch(
        &app,
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":parent}),
    );
    read["data"]["document"] = Value::Null;
    app.cache_study_context_preview(&read["data"]);
    assert!(app
        .study_context_picker()
        .unwrap()
        .comparison
        .as_ref()
        .unwrap()
        .error
        .is_some());
    let update = app.handle_context_comparison_key(KeyCode::Enter).unwrap();
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("local read expected")
    };
    assert_eq!(request.tool_name, "threat-model:read");
    app.context_comparison_failed("threat-model:read", "Parent object unavailable");
    let lines = crate::ui_view_models::study_context::comparison_lines(
        app.study_context_picker()
            .unwrap()
            .comparison
            .as_ref()
            .unwrap(),
        34,
    );
    assert!(lines.iter().any(|line| line.contains("Parent unavailable")));
    assert!(lines.iter().all(|line| line.chars().count() <= 34));
    app.handle_context_comparison_key(KeyCode::Esc);
    assert!(app.study_context_picker().unwrap().comparison.is_none());
    assert!(app.study_context_picker().unwrap().preview.is_some());
}

#[test]
fn comparison_rejects_foreign_receipts_and_closed_reader_completions() {
    let (root, mut app, parent) = fixture();
    edited_candidate(&mut app, root.path(), parent.clone());
    app.compare_study_context();
    let mut read = dispatch(
        &app,
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":parent}),
    );
    read["data"]["target"] = json!("/foreign-target");
    app.cache_study_context_preview(&read["data"]);
    assert!(app
        .study_context_picker()
        .unwrap()
        .comparison
        .as_ref()
        .unwrap()
        .differences
        .is_none());
    app.handle_context_comparison_key(KeyCode::Esc);
    read["data"]["target"] = json!(app.target_owned());
    app.cache_study_context_preview(&read["data"]);
    assert!(app.study_context_picker().unwrap().comparison.is_none());
}

#[test]
fn regeneration_paging_reaches_the_last_allowance_line_at_every_viewport() {
    use ratatui::{backend::TestBackend, Terminal};
    let (_root, mut app, _) = fixture();
    key(&mut app, KeyCode::Char('g'));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        for _ in 0..40 {
            app.scroll_context_generation(KeyCode::PageDown);
        }
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert!(
            screen.contains("Allowance not approved"),
            "{width}x{height}: {screen}"
        );
        assert!(
            screen.contains("Tab options") && screen.contains("PgUp/Dn"),
            "{screen}"
        );
    }
}

#[test]
fn model_picker_cancel_restores_exact_regeneration_draft_and_guidance_cursor() {
    let (_root, mut app, _) = fixture();
    key(&mut app, KeyCode::Char('g'));
    app.handle_context_generation_key(KeyCode::Char('G'));
    app.capture_regeneration_guidance_paste("Kept guidance α");
    app.handle_regeneration_guidance_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    let generation = app.context_generation().unwrap().clone();
    app.open_model_picker();
    assert_eq!(app.shell_view(), crate::app::ShellView::Setup);
    assert!(app.restore_model_picker_config_origin());
    assert_eq!(app.shell_view(), crate::app::ShellView::Campaign);
    assert_eq!(app.context_generation(), Some(&generation));
}

#[test]
fn explicit_model_change_invalidates_frozen_plan_and_keeps_parent_guidance_and_allowance() {
    let (root, mut app, reference) = fixture();
    key(&mut app, KeyCode::Char('g'));
    let update = app.handle_context_generation_key(KeyCode::Enter);
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("context plan expected")
    };
    let output = dispatch(
        &app,
        root.path(),
        &request.tool_name,
        serde_json::from_str(request.input.as_ref().unwrap()).unwrap(),
    );
    app.cache_study_result("campaign:context-study", &output["data"]);
    let before = app.router.campaign().batch_scan_config.clone().unwrap();
    app.open_model_picker();
    app.config_mut().model = Some("openai-codex:gpt-6-luna".into());
    assert!(app.restore_model_picker_config_origin());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    let generation = config.context_generation.as_ref().unwrap();
    assert!(generation.receipt.is_none() && generation.campaign_id.is_none());
    assert_eq!(generation.context_input["model"], "openai-codex:gpt-6-luna");
    assert_eq!(generation.context_input["threatModelRef"], json!(reference));
    assert_eq!(
        generation.context_input["fields"],
        before.context_generation.unwrap().context_input["fields"]
    );
    assert_eq!(config.study.allowance, before.study.allowance);
    assert!(config
        .notice
        .as_deref()
        .unwrap()
        .contains("approve a new plan"));
}
