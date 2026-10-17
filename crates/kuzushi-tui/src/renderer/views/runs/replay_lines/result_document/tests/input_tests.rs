use super::*;

fn owned_input_reader(input: Value) -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let record = ToolRunRecord::new(root.path(), RUN, "tool", "fixture:inputs");
    record_tool_run_started(record, &json!({"fixture":"owned reader metadata"}));
    let observation =
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(root.path(), RUN).unwrap();
    let call = kuzushi_core::modules::ApplicationToolCall::start(
        observation.clone(),
        "fixture:inputs",
        &json!({}),
        None,
        None,
    )
    .unwrap();
    let result = json!({"ok":true,"status":"completed","summary":"Owned result","output":"Retained owned observation",
        "data":{"inputDocument":input}});
    let completion = call.completion_from_result(&Ok(result.clone()));
    try_record_tool_run_complete_settled(record, &result, &observation, completion).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Report);
    app.open_replay_for_test(RUN);
    for _ in 0..3 {
        app.hydrate_active_view_blocking();
    }
    app.set_input_mode(InputMode::Navigate);
    assert!(crate::ui_view_models::replay_has_inputs(&app));
    (root, app)
}

fn input_document() -> Value {
    let rows = (0..40)
        .map(|index| format!("  OwnedInput{index:02} café"))
        .collect::<Vec<_>>()
        .join("\n");
    json!({"schemaVersion":1,"text":format!("Historical owned input\n\n{rows}")})
}

#[test]
fn three_pages_keep_independent_scrolls_draft_and_workflow_origin() {
    let (_root, mut app) = owned_input_reader(input_document());
    app.set_input("held café\nmultiline draft");
    let cursor = app.cursor();
    app.router.default_scroll_mut().set(5);
    press(&mut app, KeyCode::Tab);
    assert!(app.router.replay().inputs());
    assert_eq!(app.router.default_scroll().offset(), 0);
    app.router.default_scroll_mut().set(7);
    press(&mut app, KeyCode::Tab);
    assert!(app.router.replay().full_receipt());
    app.router.default_scroll_mut().set(11);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.router.default_scroll().offset(), 5);
    press(&mut app, KeyCode::BackTab);
    assert_eq!(app.router.default_scroll().offset(), 11);
    press(&mut app, KeyCode::BackTab);
    assert!(app.router.replay().inputs());
    assert_eq!(app.router.default_scroll().offset(), 7);
    press(&mut app, KeyCode::BackTab);
    assert_eq!(app.router.default_scroll().offset(), 5);
    assert_eq!(app.input(), "held café\nmultiline draft");
    assert_eq!(app.cursor(), cursor);
    assert!(!app.has_running_work());
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Report);
}

#[test]
fn inputs_are_explicit_keyboard_readable_at_every_size_and_complete_in_plain_output() {
    let (_root, mut app) = owned_input_reader(input_document());
    let plain = crate::renderer::render_plain_app(&app, 120);
    assert!(plain.contains("Retained owned observation") && plain.contains("OwnedInput39"));
    assert!(!frame_text(&app, 120, 36).contains("OwnedInput00"));
    press(&mut app, KeyCode::Tab);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        press(&mut app, KeyCode::Home);
        let first = frame_text(&app, width, height);
        assert!(first.contains("REPLAY · Inputs"), "{first}");
        assert!(first.contains("Tab receipt"), "{first}");
        press(&mut app, KeyCode::End);
        let mut found = frame_text(&app, width, height).contains("OwnedInput39");
        for _ in 0..3 {
            press(&mut app, KeyCode::PageUp);
            found |= frame_text(&app, width, height).contains("OwnedInput39");
        }
        assert!(found, "{width}x{height}: last historical line unreachable");
        assert!(!app.has_running_work());
    }
    assert_eq!(crate::renderer::render_plain_app(&app, 120), plain);
}

#[test]
fn malformed_inputs_do_not_hide_the_result_or_invent_an_empty_input() {
    let (_root, mut app) = owned_input_reader(json!({"schemaVersion":99,"text":"owned"}));
    assert!(frame_text(&app, 120, 36).contains("Retained owned observation"));
    press(&mut app, KeyCode::Tab);
    let text = frame_text(&app, 120, 36);
    assert!(
        text.contains("Supplied input unavailable") && text.contains("unsupported"),
        "{text}"
    );
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    assert!(frame_text(&app, 120, 36).contains("Retained owned observation"));
    app.set_input_mode(InputMode::Prompt);
    app.set_input("held multiline\nowned café");
    app.reduce_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert!(!app.router.replay().inputs());
    assert_eq!(app.input(), "held multiline\nowned café");
    assert!(!app.has_running_work());
}

#[test]
fn changed_saved_bytes_show_a_read_error_without_leaving_inputs_or_reusing_old_text() {
    let (root, mut app) = owned_input_reader(input_document());
    press(&mut app, KeyCode::Tab);
    let projection = kuzushi_core::run_lifecycle::load_run_projection(root.path(), RUN)
        .unwrap()
        .projection;
    let (_, _, reference) =
        kuzushi_core::run_artifacts::single_result_artifact(&projection).unwrap();
    let path = kuzushi_core::run_dir(root.path(), RUN).join(reference.path.as_str());
    std::fs::write(path, "changed owned artifact bytes").unwrap();
    let target = app.target().unwrap().to_path_buf();
    app.workbench_cache()
        .borrow_mut()
        .invalidate_one_run_cache(&target, RUN);
    for _ in 0..3 {
        app.hydrate_active_view_blocking();
    }
    assert!(app.router.replay().inputs());
    let text = frame_text(&app, 120, 36);
    assert!(
        text.contains("Supplied input unavailable") || text.contains("receipt needs attention"),
        "{text}"
    );
    assert!(!text.contains("OwnedInput00"), "{text}");
    assert!(!app.has_running_work());
}
