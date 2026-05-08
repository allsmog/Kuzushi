use super::*;

pub(crate) fn is_word_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

impl ShellApp {
    pub fn set_input(&mut self, value: impl Into<String>) {
        self.input = value.into();
        self.cursor = self.input.chars().count();
        self.history_index = None;
    }

    pub fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
        self.history_index = None;
    }

    /// Esc behavior: clear an in-progress draft, stash it for one-shot undo.
    /// If the draft is already empty, restore the most recently cleared
    /// draft so a single mis-tapped Esc doesn't lose carefully-typed input.
    pub fn esc_clear_or_restore(&mut self) {
        if !self.input.is_empty() {
            self.last_cleared_input = Some(std::mem::take(&mut self.input));
            self.cursor = 0;
            self.history_index = None;
            return;
        }
        if let Some(stashed) = self.last_cleared_input.take() {
            self.input = stashed;
            self.cursor = self.char_count();
            self.history_index = None;
        }
    }

    pub fn take_input(&mut self) -> String {
        self.cursor = 0;
        self.history_index = None;
        std::mem::take(&mut self.input)
    }

    pub(super) fn char_count(&self) -> usize {
        self.input.chars().count()
    }

    pub(super) fn cursor_byte(&self) -> usize {
        char_index_to_byte(&self.input, self.cursor)
    }
}
