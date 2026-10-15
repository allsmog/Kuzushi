use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;

fn fixture_at(root: &std::path::Path) -> ShellApp {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("note.txt"),
        "Owned inert policy text. Never executed.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root).unwrap();
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    for (run, rule) in [
        ("goal-one", "owner"),
        ("goal-two", "license"),
        ("goal-three", "catalog"),
    ] {
        store.record_run_started(run, root, "running").unwrap();
        store
            .insert_finding(
                run,
                &Finding::new_tool(
                    "labeled-synthetic-fixture",
                    rule,
                    "note.txt",
                    1,
                    None,
                    kuzushi_core::Severity::Info,
                    &format!("Owned {rule} policy observation"),
                ),
            )
            .unwrap();
        store.record_run_finished(run, "completed", 1).unwrap();
    }
    let config = V2Config::default();
    let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
    let ctx = kuzushi_core::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry.prepare_dispatch_input("campaign:brief", json!({"mode":"save","expectedRevision":0,"text":"Goal\nReview owner policy.\n東京 notes remain readable.\nPriorities guide work, never finding verdicts."}), &ctx, None).unwrap();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let mut app = ShellApp::new(config, Some(&workspace));
    app.set_findings(store.list_all_findings().unwrap());
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app
}

fn press(app: &mut ShellApp, code: KeyCode) {
    app.handle_goal_review_key(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap();
}

fn settle(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while app.runtime_state.goal_review_worker.is_some() {
        app.poll_goal_review();
        assert!(
            std::time::Instant::now() < deadline,
            "Goal worker did not complete"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn review_reader_shortcuts_preserve_the_composer_and_open_distinct_views() {
    for modifiers in [KeyModifiers::NONE, KeyModifiers::SHIFT] {
        let root = tempfile::tempdir().unwrap();
        let mut app = fixture_at(root.path());
        app.set_input("Unsent review draft\n東京 cursor evidence");
        app.set_cursor(5);
        app.set_input_mode(InputMode::Navigate);
        app.router.findings_mut().set_cursor(1);
        app.reduce_key(KeyEvent::new(KeyCode::Char('O'), modifiers));
        settle(&mut app);
        assert!(app.goal_review().is_some());
        assert_eq!(app.shell_view(), ShellView::Workbench);
        app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.goal_review().is_none());
        assert_eq!(app.router.findings().cursor(), 1);
        app.reduce_key(KeyEvent::new(KeyCode::Char('G'), modifiers));
        assert_eq!(app.shell_view(), ShellView::Relationships);
        assert!(app.router.relationships.show_groups);
        assert_eq!(app.input(), "Unsent review draft\n東京 cursor evidence");
        assert_eq!(app.cursor(), 5);
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert!(!app.has_running_work());
    }
}

#[test]
fn goal_review_preserves_composer_drafts_and_controls_across_sizes() {
    let root = tempfile::tempdir().unwrap();
    let mut app = fixture_at(root.path());
    app.set_input("unsent\nReview draft");
    app.set_cursor(4);
    app.open_goal_review(None);
    settle(&mut app);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(
            text.contains("GOAL RELEVANCE") && text.contains("Esc return"),
            "{width}x{height}: {text}"
        );
    }
    app.reduce_paste("browse paste belongs to overlay");
    assert_eq!(app.input(), "unsent\nReview draft");
    press(&mut app, KeyCode::Char('1'));
    app.reduce_paste("Owned reason\n東京 text");
    assert!(app.has_goal_assessment_drafts());
    app.set_shell_view(ShellView::QuitConfirm);
    assert!(app.goal_review().is_none());
    assert!(app
        .handle_goal_review_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE))
        .is_none());
    let quit = crate::ui_view_models::quit_confirm_model(&app);
    let text = format!("{quit:?}");
    assert!(text.contains("goal relevance draft") && !text.contains("東京 text"));
    app.set_shell_view(ShellView::Workbench);

    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Esc);
    assert!(app.goal_review().is_none());
    assert_eq!(app.input(), "unsent\nReview draft");
    assert_eq!(app.cursor(), 4);
    app.open_goal_review(Some("other-brief"));
    settle(&mut app);
    assert!(app.runtime_state.goal_review.form.is_none());
    app.open_goal_review(None);
    assert!(app
        .runtime_state
        .goal_review
        .form
        .as_ref()
        .unwrap()
        .reason
        .text()
        .contains("東京 text"));
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('2'));
    assert!(!app.runtime_state.goal_review.editing);
    assert!(app
        .runtime_state
        .goal_review
        .form
        .as_ref()
        .unwrap()
        .reason
        .text()
        .contains("東京 text"));
    press(&mut app, KeyCode::Char('d'));
    assert!(app.runtime_state.goal_review.editing);
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Esc);
    assert!(app.runtime_state.goal_review.form.is_some());
    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Enter);
    assert!(app.runtime_state.goal_review.form.is_none());
    assert!(!app.has_goal_assessment_drafts());
}

#[test]
fn goal_save_clear_and_hidden_completion_preserve_finding_truth() {
    let root = tempfile::tempdir().unwrap();
    let mut app = fixture_at(root.path());
    let original = app.findings().to_vec();
    app.open_goal_review(None);
    settle(&mut app);
    let id = app
        .goal_review()
        .unwrap()
        .selected()
        .unwrap()
        .basis
        .finding_id;
    press(&mut app, KeyCode::Char('1'));
    app.paste_goal_reason("Owner policy is the selected goal");
    app.handle_goal_review_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    press(&mut app, KeyCode::Enter);
    app.runtime_state.goal_review.visible = false;
    settle(&mut app);
    assert!(app.goal_review().is_none());
    assert_eq!(app.shell_view(), ShellView::Workbench);
    app.open_goal_review(None);
    assert_eq!(
        app.goal_review().unwrap().selected().unwrap().relevance(),
        Some(GoalRelevance::Direct)
    );
    press(&mut app, KeyCode::Char('u'));
    app.handle_goal_review_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    press(&mut app, KeyCode::Enter);
    settle(&mut app);
    assert!(app
        .goal_review()
        .unwrap()
        .selected()
        .unwrap()
        .relevance()
        .is_none());
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = kuzushi_core::FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
    assert_eq!(store.finding_goal_history(id).unwrap().len(), 2);
    press(&mut app, KeyCode::Char('h'));
    settle(&mut app);
    assert_eq!(
        app.runtime_state
            .goal_review
            .history
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .len(),
        2
    );
    press(&mut app, KeyCode::Esc);
    assert!(!app.runtime_state.goal_review.show_history);
    assert!(store.list_all_review_decisions().unwrap().is_empty());
    assert_eq!(store.list_all_findings().unwrap(), original);
}

#[test]
fn prepare_native_goal_review_fixture() {
    let Some(root) = std::env::var_os("KUZUSHI_GOAL_FIXTURE_OUT") else {
        return;
    };
    fixture_at(std::path::Path::new(&root));
}
