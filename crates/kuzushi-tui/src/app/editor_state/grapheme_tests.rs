use super::EditorState;

#[test]
fn grapheme_movement_and_deletion_preserve_user_characters() {
    for text in ["é", "e\u{301}", "👩‍💻", "👍🏽", "🇺🇳", "東"] {
        let mut editor = EditorState::default();
        editor.set_input(format!("a{text}z"));
        editor.set_cursor(1);
        editor.move_cursor_right();
        assert_eq!(editor.cursor(), 1 + text.chars().count(), "{text}");
        editor.move_cursor_left();
        assert_eq!(editor.cursor(), 1, "{text}");
        editor.delete_forward();
        assert_eq!(editor.input(), "az", "{text}");
        editor.insert_str_at_cursor(text);
        editor.backspace();
        assert_eq!(editor.input(), "az", "{text}");
    }
}

#[test]
fn grapheme_interior_offsets_and_word_edits_never_split_accents() {
    let mut editor = EditorState::default();
    editor.set_input("a e\u{301}clair next");
    editor.set_cursor(3);
    assert_eq!(editor.cursor(), 2);
    editor.move_cursor_word_right();
    assert_eq!(editor.cursor(), "a e\u{301}clair ".chars().count());
    editor.delete_word_left();
    assert_eq!(editor.input(), "a next");
    editor.set_input("eX");
    editor.set_cursor(1);
    editor.insert_char_at_cursor('\u{301}');
    assert_eq!(editor.cursor(), 2);
    editor.backspace();
    assert_eq!(editor.input(), "X");
}

#[test]
fn grapheme_history_search_backspace_removes_the_whole_symbol() {
    let mut editor = EditorState::default();
    editor.enter_history_search();
    for ch in "a👩‍💻".chars() {
        editor.history_search_input(ch);
    }
    editor.history_search_backspace();
    assert_eq!(editor.history_search().unwrap().query, "a");
}
