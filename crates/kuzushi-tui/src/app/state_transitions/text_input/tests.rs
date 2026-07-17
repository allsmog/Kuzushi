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
        crossterm::event::KeyCode::Char(':'),
        crossterm::event::KeyModifiers::NONE,
    ));

    let update = app.reduce_paste("jobs");

    assert!(update.handled);
    assert_eq!(app.input(), "jobs");
    assert!(app.router.auth_picker().key_draft().is_empty());
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
    assert_eq!(
        activity_pane_for_click(4, 4, 120, 40, false, 4, crate::app::PaneFocus::Left, frame,),
        Some(crate::app::PaneFocus::Left)
    );
    assert_eq!(
        activity_pane_for_click(80, 4, 120, 40, false, 4, crate::app::PaneFocus::Left, frame,),
        Some(crate::app::PaneFocus::Right)
    );
    assert_eq!(
        activity_pane_for_click(4, 4, 120, 40, true, 0, crate::app::PaneFocus::Left, frame,),
        Some(crate::app::PaneFocus::Right)
    );
    assert_eq!(
        activity_pane_for_click(4, 1, 120, 40, false, 4, crate::app::PaneFocus::Left, frame,),
        None
    );
}

#[test]
fn activity_clicks_follow_stacked_and_focused_layouts() {
    let frame = crate::ui_view_models::activity_frame_layout(3, 2);
    assert_eq!(
        activity_pane_for_click(4, 4, 60, 20, false, 4, crate::app::PaneFocus::Right, frame,),
        Some(crate::app::PaneFocus::Left)
    );
    assert_eq!(
        activity_pane_for_click(4, 12, 60, 20, false, 4, crate::app::PaneFocus::Left, frame,),
        Some(crate::app::PaneFocus::Right)
    );
    assert_eq!(
        activity_pane_for_click(4, 4, 40, 12, false, 4, crate::app::PaneFocus::Right, frame,),
        Some(crate::app::PaneFocus::Right)
    );
    assert_eq!(
        activity_pane_for_click(4, 4, 7, 12, false, 4, crate::app::PaneFocus::Right, frame,),
        None
    );
}
