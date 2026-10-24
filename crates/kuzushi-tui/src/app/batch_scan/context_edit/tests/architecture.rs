use super::*;
use kuzushi_core::capabilities::threat_model::{ContextEditConstraint, ContextFieldChoice};

fn select(app: &mut ShellApp, pointer: &str) {
    app.open_context_editor();
    let draft = app.context_edit_draft_mut().unwrap();
    draft.cursor = draft
        .entries
        .iter()
        .position(|entry| entry.pointer.as_deref() == Some(pointer))
        .unwrap();
}

#[test]
fn role_choice_requires_explicit_apply_review_and_save_without_changing_active_context() {
    let (root, mut app, original, active) = fixture();
    app.set_input("held operator draft");
    app.set_cursor(4);
    select(&mut app, "/dfd/nodes/0/type");
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        app.context_edit_draft().unwrap().mode,
        ContextEditMode::Choosing
    );
    key(&mut app, KeyCode::Down, KeyModifiers::NONE);
    assert!(app.context_edit_draft().unwrap().edits().is_empty());
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert!(app.context_edit_draft().unwrap().edits().is_empty());
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    key(&mut app, KeyCode::Down, KeyModifiers::NONE);
    key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert_eq!(
        app.context_edit_draft().unwrap().mode,
        ContextEditMode::Choosing
    );
    assert!(app.capture_context_edit_paste("process\nscan batch"));
    assert!(app.context_edit_draft().unwrap().edits().is_empty());
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        app.context_edit_draft().unwrap().edits()[0].text,
        "external-entity"
    );
    key(&mut app, KeyCode::Char('r'), KeyModifiers::NONE);
    assert_eq!(
        app.context_edit_draft().unwrap().mode,
        ContextEditMode::Review
    );
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    settle_tool(&mut app);
    let selected = app
        .study_context_picker()
        .unwrap()
        .selected
        .clone()
        .unwrap();
    assert_ne!(selected, original);
    assert_eq!(
        read(&mut app, root.path(), &selected)["dfd"]["nodes"][0]["type"],
        "external-entity"
    );
    assert_eq!(
        read(&mut app, root.path(), &original)["dfd"]["nodes"][0]["type"],
        "process"
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
    assert_eq!((app.input(), app.cursor()), ("held operator draft", 4));
}

#[test]
fn architecture_field_cannot_open_model_regeneration_and_hints_match_the_local_action() {
    let (_root, mut app, _, _) = fixture();
    select(&mut app, "/dfd/nodes/0/name");
    let draft = app.context_edit_draft().unwrap();
    assert!(
        !crate::ui_view_models::context_edit::context_draft_controls(draft)
            .join(" ")
            .contains("regen")
    );
    key(&mut app, KeyCode::Char('g'), KeyModifiers::NONE);
    assert!(app.context_generation().is_none());
    assert!(app
        .context_edit_draft()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("edited locally"));
    assert!(!app.has_running_work());
}

#[test]
fn names_use_single_line_input_and_review_explains_invalid_values() {
    let (_root, mut app, _, _) = fixture();
    select(&mut app, "/dfd/nodes/0/name");
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert!(app.capture_context_edit_paste("New\nname"));
    let draft = app.context_edit_draft().unwrap();
    assert!(!draft.entries[draft.cursor].changed());
    key(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert!(app
        .context_edit_draft()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("nonempty text"));
    assert!(app.capture_context_edit_paste("Named operator"));
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        app.context_edit_draft().unwrap().mode,
        ContextEditMode::Fields
    );
    assert_eq!(
        app.context_edit_draft().unwrap().edits()[0].text,
        "Named operator"
    );
}

fn frame_text(app: &ShellApp, width: u16, height: u16) -> String {
    use ratatui::{backend::TestBackend, Terminal};
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn choice_details_read_complete_literal_values_and_page_back_at_every_viewport() {
    let (_root, mut app, _, _) = fixture();
    select(&mut app, "/dfd/nodes/0/type");
    let literal = format!("{}FINAL-LITERAL-ID", "literal-/~ 界 ".repeat(700));
    let draft = app.context_edit_draft_mut().unwrap();
    let entry = &mut draft.entries[draft.cursor];
    entry.constraint = ContextEditConstraint::Choice(
        vec![ContextFieldChoice {
            value: literal.clone(),
            label: "Owned long identifier".into(),
        }]
        .into(),
    );
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        let frame = frame_text(&app, width, height);
        assert!(
            frame.contains("Tab details") && frame.contains("Enter apply"),
            "{width}x{height}: {frame}"
        );
        let choice_row = frame
            .lines()
            .position(|line| line.contains("Owned long identifier"))
            .unwrap();
        let controls_row = frame
            .lines()
            .position(|line| line.contains("Enter apply"))
            .unwrap();
        assert!(
            controls_row.saturating_sub(choice_row) <= 6,
            "Choice controls must stay near the choices: {width}x{height}"
        );
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        key(&mut app, KeyCode::End, KeyModifiers::NONE);
        let text = frame_text(&app, width, height);
        let joined: String = text
            .chars()
            .filter(|ch| !ch.is_whitespace() && *ch != '│')
            .collect();
        assert!(joined.contains("FINAL-LITERAL-ID"), "{text}");
        let last = app.context_edit_draft().unwrap().scroll;
        key(&mut app, KeyCode::PageDown, KeyModifiers::NONE);
        assert_eq!(app.context_edit_draft().unwrap().scroll, last);
        key(&mut app, KeyCode::PageUp, KeyModifiers::NONE);
        assert!(app.context_edit_draft().unwrap().scroll < last);
        let plain = crate::renderer::render_plain_app(&app, 40);
        assert!(plain.contains("FINAL-LITERAL-ID") && !plain.contains('\u{1b}'));
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.context_edit_draft().unwrap().choice_cursor, 0);
        let position = app.context_edit_draft().unwrap().scroll;
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert!(position > 0);
        assert_eq!(app.context_edit_draft().unwrap().scroll, position);
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.context_edit_draft().unwrap().edits().is_empty());
    }
}

#[test]
fn fields_page_and_reach_both_ends_without_changing_values() {
    let (_root, mut app, _, _) = fixture();
    app.open_context_editor();
    let original = app.context_edit_draft().unwrap().entries.clone();
    key(&mut app, KeyCode::End, KeyModifiers::NONE);
    assert_eq!(app.context_edit_draft().unwrap().cursor, original.len() - 1);
    key(&mut app, KeyCode::Home, KeyModifiers::NONE);
    assert_eq!(app.context_edit_draft().unwrap().cursor, 0);
    key(&mut app, KeyCode::PageDown, KeyModifiers::NONE);
    assert!(app.context_edit_draft().unwrap().cursor > 0);
    assert_eq!(app.context_edit_draft().unwrap().entries, original);
}

#[test]
fn single_line_fields_keep_controls_near_input_and_preserve_caret_through_resize() {
    let (_root, mut app, _, _) = fixture();
    select(&mut app, "/dfd/nodes/0/name");
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    key(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    app.capture_context_edit_paste("Named operator");
    key(&mut app, KeyCode::Left, KeyModifiers::NONE);
    let draft = app.context_edit_draft().unwrap().clone();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let text = frame_text(&app, width, height);
        let input = text
            .lines()
            .position(|line| line.contains("Named operator"))
            .unwrap();
        let controls = text
            .lines()
            .position(|line| line.contains("Enter done"))
            .unwrap();
        assert!(
            controls.saturating_sub(input) <= 6,
            "{width}x{height}: {text}"
        );
        assert!(text.contains("Ctrl+S review") && text.contains("Esc back"));
        assert_eq!(app.context_edit_draft().unwrap(), &draft);
    }
}
