use super::*;

fn model_fixture() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture();
    app.config_mut().model = Some("openai-codex:gpt-5.5".into());
    app.config_mut().runtime.thinking_level = Some("medium".into());
    (root, app)
}

fn open_ai_action(app: &mut ShellApp) -> InputUpdate {
    let index = SCOPE_ACTIONS
        .iter()
        .position(|action| *action == "Suggest scan scopes with AI")
        .unwrap();
    app.apply_scope_menu(index)
}

#[test]
fn visible_ai_action_preserves_multiline_priorities_and_opens_only_budget_review() {
    let (_root, mut app) = model_fixture();
    let original = app.scope_review().unwrap().review.clone();
    let input = (app.input().to_owned(), app.editor().cursor());
    assert!(open_ai_action(&mut app).effects.is_empty());
    fill_form(
        &mut app,
        &["Prioritize coherent services\nPreserve loose files"],
    );
    let update = press(&mut app, KeyCode::Enter);
    assert!(update.effects.is_empty());
    assert!(app.scope_review().unwrap().form.as_ref().unwrap().fields[0]
        .1
        .text()
        .contains('\n'));
    let update = press(&mut app, KeyCode::F(2));
    assert!(update.effects.is_empty());
    let generation = app.context_generation().unwrap();
    assert!(generation.is_scope_proposal());
    assert!(generation.receipt.is_none());
    assert!(generation.context_input["priorities"]
        .as_str()
        .unwrap()
        .contains("loose files"));
    assert_eq!(app.scope_review().unwrap().review, original);
    assert_eq!((app.input().to_owned(), app.editor().cursor()), input);
    assert!(!app.scope_review_is_visible());
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    discard_unprepared_study(&mut app);
    assert!(app.scope_review_is_visible());
    assert!(app.scope_review().unwrap().form.as_ref().unwrap().fields[0]
        .1
        .text()
        .contains("loose files"));
}

#[test]
fn scope_model_picker_cancel_restores_budget_origin_and_exact_draft() {
    let (_root, mut app) = model_fixture();
    open_ai_action(&mut app);
    fill_form(&mut app, &["Operator priority"]);
    press(&mut app, KeyCode::F(2));
    let generation = app.context_generation().unwrap().clone();
    app.open_model_picker();
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert!(app.restore_model_picker_config_origin());
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.context_generation().unwrap(), &generation);
    assert!(app.scope_review().unwrap().form.as_ref().unwrap().fields[0]
        .1
        .text()
        .contains("Operator priority"));
}

#[test]
fn scope_budget_and_priorities_controls_render_at_all_sizes_without_creating_work() {
    let (root, mut app) = model_fixture();
    open_ai_action(&mut app);
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
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
            text.contains("F2 next · F3 context · Esc cancel"),
            "{width}x{height}"
        );
    }
    press(&mut app, KeyCode::F(3));
    assert!(
        app.scope_review()
            .unwrap()
            .form
            .as_ref()
            .unwrap()
            .omit_context
    );
    press(&mut app, KeyCode::F(2));
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
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
        assert!(text.contains("SUGGEST SCAN SCOPES"), "{width}x{height}");
        assert!(text.contains("PgUp/Dn 1/"), "{width}x{height}");
        let area = crate::ui_view_models::study_config::study_config_area(width, height);
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer[(area.x, area.bottom() - 1)].symbol(), "└");
        assert_eq!(buffer[(area.right() - 1, area.bottom() - 1)].symbol(), "┘");
        assert!(
            text.contains("Enter next · n new draft · Esc back"),
            "{width}x{height}"
        );
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("One scope proposal job"));
    let text = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(text.contains("No tools, recursive subdivision, output repair or scan jobs"));
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}
