use super::EditorState;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// Form fields use the composer's Unicode-aware editing operations without
/// exposing command history, completion, or submission to the shell.
#[derive(Debug, Clone, Default)]
pub(crate) struct FieldEditor {
    buffer: EditorState,
}

// Text and cursor are the complete observable state of a field. The private
// composer buffer's history and completion operations are never exposed here.
impl PartialEq for FieldEditor {
    fn eq(&self, other: &Self) -> bool {
        self.text() == other.text() && self.cursor() == other.cursor()
    }
}

impl Eq for FieldEditor {}

impl FieldEditor {
    pub(crate) fn new(text: impl Into<String>) -> Self {
        let mut field = Self::default();
        field.buffer.set_input(text);
        field
    }

    pub(crate) fn text(&self) -> &str {
        self.buffer.input()
    }

    pub(crate) fn cursor(&self) -> usize {
        self.buffer.cursor()
    }

    pub(crate) fn restore_cursor(&mut self, cursor: usize) -> anyhow::Result<()> {
        anyhow::ensure!(
            cursor <= self.text().chars().count(),
            "Saved cursor is outside this field"
        );
        self.buffer.set_cursor(cursor);
        Ok(())
    }

    pub(crate) fn insert(&mut self, text: &str) {
        self.buffer.insert_str_at_cursor(text);
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return self.handle_editing_chord(key);
        }
        if key
            .modifiers
            .intersects(KeyModifiers::SUPER | KeyModifiers::HYPER | KeyModifiers::META)
        {
            return false;
        }
        match key.code {
            KeyCode::Char(ch) if !ch.is_control() => self.buffer.insert_char_at_cursor(ch),
            KeyCode::Left => self.buffer.move_cursor_left(),
            KeyCode::Right => self.buffer.move_cursor_right(),
            KeyCode::Up => self.move_line(-1),
            KeyCode::Down => self.move_line(1),
            KeyCode::Home => self.move_line_edge(false),
            KeyCode::End => self.move_line_edge(true),
            KeyCode::Backspace => self.buffer.backspace(),
            KeyCode::Delete => self.buffer.delete_forward(),
            KeyCode::Tab => self.insert("    "),
            _ => return false,
        }
        true
    }

    fn handle_editing_chord(&mut self, key: KeyEvent) -> bool {
        if key.modifiers == KeyModifiers::ALT {
            return self.handle_word_key(key.code);
        }
        if key.modifiers != KeyModifiers::CONTROL {
            return false;
        }
        match key.code {
            KeyCode::Char('a') => self.move_line_edge(false),
            KeyCode::Char('e') => self.move_line_edge(true),
            KeyCode::Char('u') => self.buffer.kill_to_start(),
            KeyCode::Char('k') => self.buffer.kill_to_end(),
            KeyCode::Char('w') | KeyCode::Backspace => self.buffer.delete_word_left(),
            KeyCode::Home => self.buffer.move_cursor_home(),
            KeyCode::End => self.buffer.move_cursor_end(),
            _ => return self.handle_word_key(key.code),
        }
        true
    }

    fn handle_word_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Left | KeyCode::Char('b') => self.buffer.move_cursor_word_left(),
            KeyCode::Right | KeyCode::Char('f') => self.buffer.move_cursor_word_right(),
            KeyCode::Backspace => self.buffer.delete_word_left(),
            _ => return false,
        }
        true
    }

    fn move_line_edge(&mut self, end: bool) {
        let (line, _) = self.line_position();
        let lines = self.text().split('\n').collect::<Vec<_>>();
        let column = if end { lines[line].width() } else { 0 };
        self.set_line_position(line, column);
    }

    fn move_line(&mut self, delta: isize) {
        let (line, column) = self.line_position();
        let last = self.text().split('\n').count().saturating_sub(1);
        let next = line.saturating_add_signed(delta).min(last);
        self.set_line_position(next, column);
    }

    fn line_position(&self) -> (usize, usize) {
        let before = self.text().chars().take(self.cursor()).collect::<String>();
        let line = before.matches('\n').count();
        let column = before.rsplit('\n').next().unwrap_or_default().width();
        (line, column)
    }

    fn set_line_position(&mut self, line: usize, column: usize) {
        let lines = self.text().split('\n').collect::<Vec<_>>();
        let before: usize = lines
            .iter()
            .take(line)
            .map(|text| text.chars().count() + 1)
            .sum();
        let cursor = before + scalar_at_column(lines[line], column);
        self.buffer.set_cursor(cursor);
    }
}

fn scalar_at_column(line: &str, column: usize) -> usize {
    let mut cells = 0;
    line.graphemes(true)
        .take_while(|grapheme| {
            cells += grapheme.width();
            cells <= column
        })
        .map(|grapheme| grapheme.chars().count())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(field: &mut FieldEditor, code: KeyCode) {
        assert!(field.handle_key(KeyEvent::new(code, KeyModifiers::NONE)));
    }

    #[test]
    fn grapheme_field_navigation_uses_display_columns_and_shared_deletion() {
        let mut field = FieldEditor::new("e\u{301}東x\nab東z");
        field.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::CONTROL));
        press(&mut field, KeyCode::Right);
        press(&mut field, KeyCode::Right);
        assert_eq!(field.cursor(), 3);
        press(&mut field, KeyCode::Down);
        assert_eq!(field.cursor(), 7);
        press(&mut field, KeyCode::Delete);
        assert_eq!(field.text(), "e\u{301}東x\nabz");
        field.insert("👩‍💻");
        press(&mut field, KeyCode::Backspace);
        assert_eq!(field.text(), "e\u{301}東x\nabz");
    }

    #[test]
    fn field_editing_preserves_shifted_unicode_and_inserts_at_the_cursor() {
        let mut field = FieldEditor::new("alpha");
        press(&mut field, KeyCode::Left);
        assert!(field.handle_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::SHIFT)));
        field.insert("東京");
        assert_eq!(field.text(), "alphX東京a");
        press(&mut field, KeyCode::Backspace);
        press(&mut field, KeyCode::Delete);
        assert_eq!(field.text(), "alphX東");
    }

    #[test]
    fn multiline_paste_and_line_navigation_keep_the_entire_text() {
        let mut field = FieldEditor::new("first\nsecond");
        press(&mut field, KeyCode::Home);
        field.insert("Architecture, v2\n");
        assert_eq!(field.text(), "first\nArchitecture, v2\nsecond");
        press(&mut field, KeyCode::Up);
        press(&mut field, KeyCode::End);
        field.insert("!");
        assert_eq!(field.text(), "first\nArchitecture, v2!\nsecond");
    }

    #[test]
    fn unbound_chords_do_not_insert_their_bare_letter() {
        let mut field = FieldEditor::new("kept");
        assert!(!field.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)));
        assert!(!field.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::SUPER)));
        assert_eq!(field.text(), "kept");
    }

    #[test]
    fn editing_chords_reuse_composer_word_and_clear_behavior() {
        let mut field = FieldEditor::new("one two");
        assert!(field.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::ALT)));
        assert_eq!(field.text(), "one ");
        assert!(field.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)));
        assert_eq!(field.text(), "");
    }
}
