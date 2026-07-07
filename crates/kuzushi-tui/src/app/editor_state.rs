use super::*;

mod history;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditorClearResult {
    Ignored,
    CompletionRestored,
    DraftCleared,
}

#[derive(Debug, Clone)]
pub(crate) struct EditorState {
    input: String,
    cursor: usize,
    command_history: Vec<String>,
    history_index: Option<usize>,
    history_draft: String,
    last_cleared_input: Option<String>,
    completion_cycle: Option<CompletionCycle>,
    input_mode: InputMode,
    history_search: Option<HistorySearch>,
}

impl Default for EditorState {
    fn default() -> Self {
        Self {
            input: String::new(),
            cursor: 0,
            command_history: Vec::new(),
            history_index: None,
            history_draft: String::new(),
            last_cleared_input: None,
            completion_cycle: None,
            input_mode: InputMode::Prompt,
            history_search: None,
        }
    }
}

impl EditorState {
    pub(crate) fn input(&self) -> &str {
        &self.input
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn command_history(&self) -> &[String] {
        &self.command_history
    }

    pub(crate) fn replace_command_history(&mut self, history: Vec<String>) {
        self.command_history = history;
        self.history_index = None;
    }

    pub(crate) fn push_command_history(&mut self, command: impl Into<String>, cap: usize) {
        self.command_history.push(command.into());
        if self.command_history.len() > cap {
            let overflow = self.command_history.len() - cap;
            self.command_history.drain(0..overflow);
        }
        self.history_index = None;
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor.min(self.char_count());
    }

    pub(crate) fn input_mode(&self) -> InputMode {
        self.input_mode
    }

    pub(crate) fn set_input_mode(&mut self, mode: InputMode) {
        self.input_mode = mode;
    }

    pub(crate) fn history_search(&self) -> Option<&HistorySearch> {
        self.history_search.as_ref()
    }

    pub(crate) fn completion_cycle(&self) -> Option<&CompletionCycle> {
        self.completion_cycle.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn last_cleared_input(&self) -> Option<&str> {
        self.last_cleared_input.as_deref()
    }

    pub(crate) fn set_last_cleared_input(&mut self, input: Option<String>) {
        self.last_cleared_input = input;
    }

    pub(crate) fn set_input(&mut self, value: impl Into<String>) {
        self.input = value.into();
        self.cursor = self.char_count();
        self.history_index = None;
    }

    pub(crate) fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
        self.history_index = None;
    }

    pub(crate) fn take_input(&mut self) -> String {
        self.cursor = 0;
        self.history_index = None;
        std::mem::take(&mut self.input)
    }

    pub(crate) fn snapshot_input(&self) -> (String, usize) {
        (self.input.clone(), self.cursor)
    }

    pub(crate) fn restore_input_snapshot(&mut self, input: String, cursor: usize) {
        self.input = input;
        self.cursor = cursor.min(self.char_count());
        self.history_index = None;
    }

    pub(crate) fn esc_clear_input_or_completion(&mut self) -> EditorClearResult {
        if self.restore_completion_prefix() {
            return EditorClearResult::CompletionRestored;
        }
        if self.stash_and_clear_input() {
            return EditorClearResult::DraftCleared;
        }
        EditorClearResult::Ignored
    }

    pub(crate) fn stash_and_clear_input(&mut self) -> bool {
        if self.input.is_empty() {
            return false;
        }
        self.last_cleared_input = Some(std::mem::take(&mut self.input));
        self.cursor = 0;
        self.history_index = None;
        true
    }

    pub(crate) fn restore_last_cleared_input(&mut self) {
        if let Some(stashed) = self.last_cleared_input.take() {
            self.input = stashed;
            self.cursor = self.char_count();
            self.history_index = None;
        }
    }

    pub(crate) fn take_completion_cycle(&mut self) -> Option<CompletionCycle> {
        self.completion_cycle.take()
    }

    pub(crate) fn set_completion_cycle(&mut self, cycle: CompletionCycle) {
        self.completion_cycle = Some(cycle);
    }

    pub(crate) fn reset_completion_cycle(&mut self) {
        self.completion_cycle = None;
    }

    pub(crate) fn char_count(&self) -> usize {
        self.input.chars().count()
    }

    pub(crate) fn cursor_byte(&self) -> usize {
        char_index_to_byte(&self.input, self.cursor)
    }

    pub(crate) fn insert_str_at_cursor(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        let byte = self.cursor_byte();
        self.input.insert_str(byte, s);
        self.cursor += s.chars().count();
        self.history_index = None;
    }

    pub(crate) fn insert_char_at_cursor(&mut self, ch: char) {
        let byte = self.cursor_byte();
        self.input.insert(byte, ch);
        self.cursor += 1;
        self.history_index = None;
    }

    pub(crate) fn backspace(&mut self) {
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

    pub(crate) fn delete_forward(&mut self) {
        let count = self.char_count();
        if self.cursor >= count {
            return;
        }
        let start = char_index_to_byte(&self.input, self.cursor);
        let end = char_index_to_byte(&self.input, self.cursor + 1);
        self.input.drain(start..end);
        self.history_index = None;
    }

    pub(crate) fn move_cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub(crate) fn move_cursor_right(&mut self) {
        let count = self.char_count();
        if self.cursor < count {
            self.cursor += 1;
        }
    }

    pub(crate) fn move_cursor_home(&mut self) {
        self.cursor = 0;
    }

    pub(crate) fn move_cursor_end(&mut self) {
        self.cursor = self.char_count();
    }

    pub(crate) fn word_boundary_left(&self) -> usize {
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

    pub(crate) fn word_boundary_right(&self) -> usize {
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

    pub(crate) fn delete_word_left(&mut self) {
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

    pub(crate) fn move_cursor_word_left(&mut self) {
        self.cursor = self.word_boundary_left();
    }

    pub(crate) fn move_cursor_word_right(&mut self) {
        self.cursor = self.word_boundary_right();
    }

    pub(crate) fn kill_to_start(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let end = char_index_to_byte(&self.input, self.cursor);
        self.input.drain(..end);
        self.cursor = 0;
        self.history_index = None;
    }

    pub(crate) fn kill_to_end(&mut self) {
        let start = char_index_to_byte(&self.input, self.cursor);
        self.input.truncate(start);
        self.history_index = None;
    }

    fn restore_completion_prefix(&mut self) -> bool {
        let Some(cycle) = self.completion_cycle.take() else {
            return false;
        };
        if cycle.prefix.is_empty() && self.input.is_empty() {
            return true;
        }
        self.input = cycle.prefix;
        self.cursor = self.char_count();
        self.history_index = None;
        true
    }
}
