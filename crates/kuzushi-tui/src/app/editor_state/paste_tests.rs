use super::EditorState;
use crate::app::ShellApp;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;

fn draft() -> EditorState {
    let mut editor = EditorState::default();
    editor.insert_str_at_cursor("before ");
    editor.insert_multiline_paste("long\ndocument 👩‍💻\n");
    editor.insert_str_at_cursor(" after");
    editor
}

#[test]
fn paste_interior_cursor_typing_and_deletion_are_atomic_and_undoable() {
    let mut editor = draft();
    let original = editor.expanded_input();
    editor.set_cursor(12);
    assert_eq!(editor.cursor(), 7);
    editor.insert_str_at_cursor("NEW ");
    assert_eq!(
        editor.expanded_input(),
        format!("before NEW {}", &original[7..])
    );
    editor.delete_forward();
    assert_eq!(editor.input(), "before NEW  after");
    editor.restore_last_cleared_input();
    assert_eq!(
        editor.expanded_input(),
        format!("before NEW {}", &original[7..])
    );
    editor.move_cursor_right();
    editor.backspace();
    assert_eq!(editor.input(), "before NEW  after");
    editor.restore_last_cleared_input();
    assert!(editor.expanded_input().contains("document 👩‍💻\n"));
}

#[test]
fn paste_word_and_kill_operations_preserve_undo_bytes() {
    for operation in [EditorState::delete_word_left, EditorState::kill_to_start] {
        let mut editor = draft();
        let original = editor.expanded_input();
        editor.set_cursor(7);
        editor.move_cursor_right();
        operation(&mut editor);
        assert!(!editor.input().contains("paste #"));
        editor.restore_last_cleared_input();
        assert_eq!(editor.expanded_input(), original);
    }
    let mut editor = draft();
    let original = editor.expanded_input();
    editor.set_cursor(7);
    editor.kill_to_end();
    assert_eq!(editor.input(), "before ");
    editor.restore_last_cleared_input();
    assert_eq!(editor.expanded_input(), original);
}

#[test]
fn paste_payload_identity_uses_spans_instead_of_marker_text() {
    let mut editor = EditorState::default();
    let marker = editor.insert_multiline_paste("actual\npayload\n");
    editor.move_cursor_home();
    editor.insert_str_at_cursor(&format!("{marker} literal "));
    assert_eq!(
        editor.expanded_input(),
        format!("{marker} literal actual\npayload\n")
    );
    editor.move_cursor_end();
    editor.insert_multiline_paste("second\nblock");
    assert!(editor
        .take_input()
        .ends_with("actual\npayload\nsecond\nblock"));
    assert!(editor.paste_undo.is_empty());
}

#[test]
fn paste_expand_clear_and_history_cancel_restore_exact_bytes() {
    let mut editor = draft();
    let original = editor.expanded_input();
    editor.set_cursor(7);
    assert!(editor.expand_paste_at_cursor());
    assert_eq!(editor.input(), original);
    editor.restore_last_cleared_input();
    assert!(editor.has_pasted_blocks());
    editor.enter_history_search();
    editor.history_search_input('x');
    editor.cancel_history_search();
    assert_eq!(editor.expanded_input(), original);
    editor.stash_and_clear_input();
    editor.restore_last_cleared_input();
    assert_eq!(editor.expanded_input(), original);
    editor.clear_input();
    assert!(editor.paste_undo.is_empty());
}

#[test]
fn paste_inspection_keys_own_input_and_cancel_without_changing_the_draft() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.editor_mut().insert_multiline_paste("first\nlast\n");
    let original = app.editor().snapshot_input();
    assert!(
        app.reduce_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL))
            .handled
    );
    assert!(app.editor().paste_inspection().is_some());
    app.reduce_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    app.reduce_paste("ignored\npaste");
    app.reduce_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.editor().input, original.input);
    assert_eq!(app.editor().pasted_blocks, original.pasted_blocks);
    assert!(app.editor().paste_inspection().is_none());
    app.inspect_paste_at_cursor();
    app.reduce_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    assert!(app.editor().input().is_empty());
    app.reduce_key(KeyEvent::new(KeyCode::Char('_'), KeyModifiers::CONTROL));
    assert_eq!(app.editor().expanded_input(), "first\nlast\n");
}

#[test]
fn paste_followed_by_a_combining_mark_does_not_trap_the_cursor() {
    let mut editor = EditorState::default();
    editor.insert_multiline_paste("a\nb");
    editor.insert_str_at_cursor("\u{301}x");
    editor.move_cursor_home();
    editor.move_cursor_right();
    assert_eq!(editor.cursor(), editor.char_count() - 1);
    editor.backspace();
    assert_eq!(editor.input(), "x");
}
