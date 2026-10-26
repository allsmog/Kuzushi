use super::*;

fn candidate() -> Value {
    json!({"schemaVersion":1,"scopes":[{"id":"app","name":"Application","paths":["main.rs"],
        "rationale":"LABELED_PRIVATE_SCOPE_JSON","sharedDependencies":["contracts"],"openQuestions":[]}],
        "sharedScope":null,"sharedDiscovery":false,"exclusions":[]})
}

fn scope_fixture() -> (tempfile::TempDir, ShellApp, ContextStudyReceipt) {
    let (root, mut app) = fixture();
    let review = dispatch(&app, root.path(), "pack:scopes", json!({}), false);
    let reference = serde_json::from_value(review["data"]["reference"].clone()).unwrap();
    app.open_scope_proposal_study(reference, "Owned correction fixture".into(), true)
        .unwrap();
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &result);
    let receipt = app.context_generation().unwrap().receipt.clone().unwrap();
    let path = root
        .path()
        .join(".kuzushi/v3/campaigns")
        .join(&receipt.campaign_id)
        .join("queue.json");
    std::fs::write(
        path,
        json!({"jobs":{"context-001":{"state":"failed","attempts":1,"runId":"rejected-scope"}}})
            .to_string(),
    )
    .unwrap();
    let raw = serde_json::to_string(&candidate()).unwrap();
    for (leaf, value) in [
        ("input.json", receipt.input.clone()),
        (
            "result.json",
            json!({"status":"failed","data":{"tool":"pack:suggest-scopes","error":"undeclared contracts"}}),
        ),
        (
            "rejected-scope-output.json",
            json!({"schemaVersion":1,"candidate":raw,"originalBytes":raw.len(),"complete":true,"reason":"undeclared contracts"}),
        ),
    ] {
        let label = match leaf {
            "input.json" => "tool input",
            "result.json" => "tool result",
            _ => "Unaccepted scope output: may contain source text",
        };
        kuzushi_core::run_artifacts::write_run_artifact_json(
            root.path(),
            "rejected-scope",
            leaf,
            label,
            &value,
        )
        .unwrap();
    }
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap()
        .refresh_result(root.path());
    app.set_input("unfinished operator draft");
    app.set_cursor(5);
    (root, app, receipt)
}

fn open_editor(app: &mut ShellApp) {
    app.handle_context_generation_key(KeyCode::Char('d'));
    app.handle_context_generation_key(KeyCode::Char('e'));
    assert!(
        app.context_generation()
            .unwrap()
            .scope_correction
            .as_ref()
            .unwrap()
            .editing
    );
}

fn edit_key(app: &mut ShellApp, code: KeyCode, modifiers: KeyModifiers) -> InputUpdate {
    app.handle_study_form_key(KeyEvent::new(code, modifiers))
}

fn replace_json(app: &mut ShellApp, value: &Value) {
    edit_key(app, KeyCode::End, KeyModifiers::CONTROL);
    edit_key(app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    assert!(app.capture_study_text_paste(&serde_json::to_string_pretty(value).unwrap()));
}

#[test]
fn scope_correction_owns_input_paste_plain_output_and_cursor_through_all_sizes() {
    let (_root, mut app, _) = scope_fixture();
    assert!(!crate::renderer::render_plain_app(&app, 80).contains("LABELED_PRIVATE_SCOPE_JSON"));
    open_editor(&mut app);
    for code in [
        KeyCode::Enter,
        KeyCode::Char('m'),
        KeyCode::Char('n'),
        KeyCode::Char('t'),
        KeyCode::Char('s'),
        KeyCode::Tab,
    ] {
        assert!(edit_key(&mut app, code, KeyModifiers::NONE)
            .effects
            .is_empty());
    }
    let before = app
        .context_generation()
        .unwrap()
        .scope_correction
        .clone()
        .unwrap();
    app.set_shell_view(ShellView::Report);
    assert!(!app.capture_study_text_paste("belongs to another view"));
    app.set_shell_view(ShellView::Campaign);
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(
            text.contains("CORRECT SCOPE JSON")
                && text.contains("Ctrl+S save")
                && text.contains("Esc kept"),
            "{width}x{height}: {text}"
        );
        assert_eq!(
            app.context_generation()
                .unwrap()
                .scope_correction
                .as_ref()
                .unwrap()
                .editor,
            before.editor
        );
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("CORRECT SCOPE JSON") && plain.contains("LABELED_PRIVATE_SCOPE_JSON"));
    edit_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    app.handle_context_generation_key(KeyCode::Char('e'));
    assert_eq!(
        app.context_generation()
            .unwrap()
            .scope_correction
            .as_ref()
            .unwrap()
            .editor,
        before.editor
    );
    assert_eq!(
        (app.input(), app.cursor()),
        ("unfinished operator draft", 5)
    );
}

#[test]
fn invalid_scope_save_keeps_the_draft_then_valid_save_uses_runtime_free_shared_dispatch() {
    let (root, mut app, receipt) = scope_fixture();
    open_editor(&mut app);
    let update = edit_key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("shared prepared dispatch required")
    };
    assert_eq!(request.tool_name, "pack:scopes");
    app.scope_review_failed("pack:scopes", "undeclared contracts");
    assert!(
        app.context_generation()
            .unwrap()
            .scope_correction
            .as_ref()
            .unwrap()
            .editing
    );
    let mut value = candidate();
    value["scopes"][0]["sharedDependencies"] = json!([]);
    replace_json(&mut app, &value);
    let update = edit_key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("shared prepared dispatch required")
    };
    let input: Value = serde_json::from_str(request.input.as_ref().unwrap()).unwrap();
    assert_eq!(input["operation"], "recover");
    let output = dispatch(&app, root.path(), &request.tool_name, input, false);
    app.set_shell_view(ShellView::Report);
    app.cache_tool_snapshot("pack:scopes", &output);
    assert_eq!(
        app.shell_view(),
        ShellView::Report,
        "background completion cannot steal focus"
    );
    assert!(app.context_generation().unwrap().has_corrected_scopes());
    assert!(app.context_generation().unwrap().result_error.is_some());
    assert!(
        receipt.generated_scopes(root.path()).is_err(),
        "original producer remains failed"
    );
    app.restore_context_generation(root.path(), &receipt.campaign_id);
    assert!(app.context_generation().unwrap().has_corrected_scopes());
    app.handle_context_generation_key(KeyCode::Enter);
    assert!(app.scope_review_is_visible());
    assert!(app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .record
        .acceptance
        .is_none());
    assert_eq!(
        (app.input(), app.cursor()),
        ("unfinished operator draft", 5)
    );
}

#[test]
fn unsaved_scope_correction_cannot_be_lost_to_a_new_proposal_or_oversized_paste() {
    let (_root, mut app, receipt) = scope_fixture();
    open_editor(&mut app);
    app.capture_study_text_paste("\n");
    let before = app
        .context_generation()
        .unwrap()
        .scope_correction
        .as_ref()
        .unwrap()
        .editor
        .clone();
    app.capture_study_text_paste(&"界".repeat(6000));
    assert_eq!(
        app.context_generation()
            .unwrap()
            .scope_correction
            .as_ref()
            .unwrap()
            .editor,
        before
    );
    edit_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    app.handle_context_generation_key(KeyCode::Esc);
    app.handle_context_generation_key(KeyCode::Char('n'));
    assert_eq!(
        app.context_generation().unwrap().receipt.as_ref(),
        Some(&receipt)
    );
    app.handle_context_generation_key(KeyCode::Char('d'));
    app.handle_context_generation_key(KeyCode::Char('e'));
    assert_eq!(
        app.context_generation()
            .unwrap()
            .scope_correction
            .as_ref()
            .unwrap()
            .editor,
        before
    );
    edit_key(&mut app, KeyCode::Char('r'), KeyModifiers::CONTROL);
    let state = app
        .context_generation()
        .unwrap()
        .scope_correction
        .as_ref()
        .unwrap();
    assert_eq!(state.editor.text(), state.original);
}

#[test]
fn unrelated_scope_result_cannot_complete_or_clear_a_pending_correction() {
    let (_root, mut app, _) = scope_fixture();
    open_editor(&mut app);
    edit_key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    let before = app.context_generation().unwrap().clone();
    app.cache_tool_snapshot("pack:scopes", &json!({"data":{"review":null}}));
    assert_eq!(app.context_generation().unwrap(), &before);
}

#[test]
fn partial_scope_text_is_readable_but_correction_explains_its_read_only_state() {
    let (root, mut app, receipt) = scope_fixture();
    let raw = serde_json::to_string(&candidate()).unwrap();
    kuzushi_core::run_artifacts::write_run_artifact_json(root.path(), "rejected-scope",
        "rejected-scope-output.json", "Unaccepted scope output: may contain source text",
        &json!({"schemaVersion":1,"candidate":raw,"originalBytes":raw.len(),"complete":false,"reason":"partial output"})).unwrap();
    app.handle_context_generation_key(KeyCode::Char('d'));
    assert!(crate::renderer::render_plain_app(&app, 80).contains("LABELED_PRIVATE_SCOPE_JSON"));
    app.handle_context_generation_key(KeyCode::Char('e'));
    assert!(app.context_generation().unwrap().scope_correction.is_none());
    let plain = crate::renderer::render_plain_app(&app, 80);
    assert!(plain.contains("Correction unavailable") && plain.contains("read-only"));
    assert_eq!(
        app.context_generation().unwrap().receipt.as_ref(),
        Some(&receipt)
    );
}
