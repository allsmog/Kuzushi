use super::*;

#[test]
fn paste_normalisation_preserves_cr_only_terminal_line_breaks() {
    assert_eq!(
        normalise_paste_text("alpha\rbeta\r\ngamma"),
        "alpha\nbeta\ngamma"
    );
}

#[test]
fn credential_prompt_focus_routes_paste_to_composer_not_secret_draft() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.open_auth_method_picker("anthropic".to_string());
    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Down,
        crossterm::event::KeyModifiers::NONE,
    ));
    assert!(!app.router.auth_picker().is_api_key_row());
    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char(':'),
        crossterm::event::KeyModifiers::NONE,
    ));

    let update = app.reduce_paste("jobs");

    assert!(update.handled);
    assert_eq!(app.input(), "jobs");
    assert!(app.router.auth_picker().key_draft().is_empty());
}

#[test]
fn picker_list_paste_moves_losslessly_into_the_composer() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::TargetPicker);
    app.router.target_picker_mut().open(Vec::new());

    let update = app.reduce_paste("queue run secret-scan:scan {}");

    assert!(update.handled);
    assert!(app.picker_prompt_focused());
    assert_eq!(app.input(), "queue run secret-scan:scan {}");
}

#[test]
fn navigation_paste_enters_the_composer_without_submitting_or_losing_the_cursor() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::Campaign);
    app.set_input("ac");
    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Left,
        crossterm::event::KeyModifiers::NONE,
    ));
    app.set_input_mode(InputMode::Navigate);

    let update = app.reduce_paste("b");

    assert!(update.handled);
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(app.input(), "abc");
    assert_eq!(app.cursor(), 2);
}

#[test]
fn navigation_multiline_paste_keeps_all_text_for_explicit_submission() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::Campaign);
    app.set_input_mode(InputMode::Navigate);

    let update = app.reduce_paste("first\r\nsecond");

    assert!(update.handled);
    assert!(update.effects.is_empty());
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(app.editor().expanded_input(), "first\nsecond");
    assert!(app.editor().paste_inspection().is_none());
    assert_eq!(app.shell_view(), ShellView::Campaign);
}

#[test]
fn planning_options_paste_moves_losslessly_into_the_composer() {
    let target_dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(target_dir.path().to_path_buf()));
    let task = crate::app::PlanningTaskId::GatherRepoContext;
    let row = crate::app::PlanningTaskRow::for_task(task, target_dir.path());
    app.engagement
        .planning_picker_mut()
        .open(vec![row], [task].into_iter().collect());
    app.engagement
        .planning_picker_mut()
        .set_focus(crate::app::PickerFocus::OptionsPane);
    app.set_shell_view(ShellView::PlanningPicker);

    let update = app.reduce_paste("queue run secret-scan:scan {}");

    assert!(update.handled);
    assert_eq!(
        app.engagement.planning_picker().focus(),
        crate::app::PickerFocus::Prompt
    );
    assert_eq!(app.input(), "queue run secret-scan:scan {}");
}

#[test]
fn picker_editors_keep_paste_ownership() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.open_credential_entry("anthropic".to_string());

    assert!(app.reduce_paste("sk-session").handled);
    assert_eq!(app.router.auth_picker().key_draft(), "sk-session");
    assert!(app.input().is_empty());

    app.router.setup_mut().finish_editor();
    app.router.setup_mut().begin_budget_edit(None);
    assert!(app.reduce_paste("2.50").handled);
    assert_eq!(app.router.setup().budget_draft(), "2.50");
    assert!(app.input().is_empty());
}

#[test]
fn pending_confirm_owns_normal_and_multiline_paste_before_composer() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.advisory_mut().pending_confirm = Some(PendingConfirm {
        kind: ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "https://refund.acme/api".to_string(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    });
    app.set_input("existing draft");

    for text in ["pasted text", "first\r\nsecond"] {
        let update = app.reduce_paste(text);
        assert!(update.handled);
        assert_eq!(app.input(), "existing draft");
        assert!(app.advisory().pending_confirm.is_some());
        assert!(app.advisory().notice.is_none());
    }
}

#[test]
fn activity_clicks_map_to_visible_panes() {
    let frame = crate::ui_view_models::activity_frame_layout(3, 2);
    let split = crate::ui_view_models::ActivityPaneLayout::SideBySide { task_width: 43 };
    assert_eq!(
        activity_pane_for_click(
            4,
            4,
            120,
            40,
            false,
            crate::app::PaneFocus::Left,
            frame,
            split
        ),
        Some(crate::app::PaneFocus::Left)
    );
    assert_eq!(
        activity_pane_for_click(
            80,
            4,
            120,
            40,
            false,
            crate::app::PaneFocus::Left,
            frame,
            split
        ),
        Some(crate::app::PaneFocus::Right)
    );
    assert_eq!(
        activity_pane_for_click(
            4,
            4,
            120,
            40,
            true,
            crate::app::PaneFocus::Left,
            frame,
            split
        ),
        Some(crate::app::PaneFocus::Right)
    );
    assert_eq!(
        activity_pane_for_click(
            4,
            1,
            120,
            40,
            false,
            crate::app::PaneFocus::Left,
            frame,
            split
        ),
        None
    );
}

#[test]
fn activity_clicks_follow_stacked_and_focused_layouts() {
    let frame = crate::ui_view_models::activity_frame_layout(3, 2);
    let stacked = crate::ui_view_models::ActivityPaneLayout::Stacked { task_height: 6 };
    assert_eq!(
        activity_pane_for_click(
            4,
            4,
            60,
            20,
            false,
            crate::app::PaneFocus::Right,
            frame,
            stacked
        ),
        Some(crate::app::PaneFocus::Left)
    );
    assert_eq!(
        activity_pane_for_click(
            4,
            12,
            60,
            20,
            false,
            crate::app::PaneFocus::Left,
            frame,
            stacked
        ),
        Some(crate::app::PaneFocus::Right)
    );
    assert_eq!(
        activity_pane_for_click(
            4,
            4,
            40,
            12,
            false,
            crate::app::PaneFocus::Right,
            frame,
            crate::ui_view_models::ActivityPaneLayout::Focused,
        ),
        Some(crate::app::PaneFocus::Right)
    );
    assert_eq!(
        activity_pane_for_click(
            4,
            4,
            7,
            12,
            false,
            crate::app::PaneFocus::Right,
            frame,
            crate::ui_view_models::ActivityPaneLayout::Focused,
        ),
        None
    );
}
