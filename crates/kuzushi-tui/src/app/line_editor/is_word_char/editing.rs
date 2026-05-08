use super::*;

impl ShellApp {
    pub fn insert_str_at_cursor(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        let byte = self.cursor_byte();
        self.input.insert_str(byte, s);
        self.cursor += s.chars().count();
        self.history_index = None;
    }

    pub fn insert_char_at_cursor(&mut self, ch: char) {
        let byte = self.cursor_byte();
        self.input.insert(byte, ch);
        self.cursor += 1;
        self.history_index = None;
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let count = self.char_count();
        if self.cursor > count {
            self.cursor = count;
        }
        let new_cursor = self.cursor - 1;
        let start = char_index_to_byte(&self.input, new_cursor);
        let end = char_index_to_byte(&self.input, self.cursor);
        self.input.drain(start..end);
        self.cursor = new_cursor;
        self.history_index = None;
    }

    pub fn delete_forward(&mut self) {
        let count = self.char_count();
        if self.cursor >= count {
            return;
        }
        let start = char_index_to_byte(&self.input, self.cursor);
        let end = char_index_to_byte(&self.input, self.cursor + 1);
        self.input.drain(start..end);
        self.history_index = None;
    }

    pub fn move_cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_cursor_right(&mut self) {
        let count = self.char_count();
        if self.cursor < count {
            self.cursor += 1;
        }
    }

    pub fn move_cursor_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_cursor_end(&mut self) {
        self.cursor = self.char_count();
    }

    pub(super) fn word_boundary_left(&self) -> usize {
        // "Word" = run of alphanumeric chars (incl. underscore). Treat punctuation and
        // whitespace as separators so Ctrl+W on "./path/to/foo" stops at each '/'. Skip
        // separators directly before the cursor first, then the run of word chars.
        let chars: Vec<char> = self.input.chars().collect();
        let mut idx = self.cursor.min(chars.len());
        while idx > 0 && !is_word_char(chars[idx - 1]) {
            idx -= 1;
        }
        while idx > 0 && is_word_char(chars[idx - 1]) {
            idx -= 1;
        }
        idx
    }

    pub(super) fn word_boundary_right(&self) -> usize {
        let chars: Vec<char> = self.input.chars().collect();
        let mut idx = self.cursor.min(chars.len());
        let len = chars.len();
        while idx < len && is_word_char(chars[idx]) {
            idx += 1;
        }
        while idx < len && !is_word_char(chars[idx]) {
            idx += 1;
        }
        idx
    }

    pub fn delete_word_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let target = self.word_boundary_left();
        let start = char_index_to_byte(&self.input, target);
        let end = char_index_to_byte(&self.input, self.cursor);
        self.input.drain(start..end);
        self.cursor = target;
        self.history_index = None;
    }

    pub fn move_cursor_word_left(&mut self) {
        self.cursor = self.word_boundary_left();
    }

    pub fn move_cursor_word_right(&mut self) {
        self.cursor = self.word_boundary_right();
    }

    pub fn kill_to_start(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let end = char_index_to_byte(&self.input, self.cursor);
        self.input.drain(..end);
        self.cursor = 0;
        self.history_index = None;
    }

    pub fn kill_to_end(&mut self) {
        let start = char_index_to_byte(&self.input, self.cursor);
        self.input.truncate(start);
        self.history_index = None;
    }
}
