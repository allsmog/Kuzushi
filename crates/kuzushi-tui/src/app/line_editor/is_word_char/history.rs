use super::*;

impl ShellApp {
    pub fn history_prev(&mut self) {
        if self.command_history.is_empty() {
            return;
        }
        let next = match self.history_index {
            None => {
                self.history_draft = self.input.clone();
                self.command_history.len() - 1
            }
            Some(0) => 0,
            Some(idx) => idx - 1,
        };
        self.history_index = Some(next);
        self.input = self.command_history[next].clone();
        self.cursor = self.char_count();
    }

    pub fn history_next(&mut self) {
        let Some(idx) = self.history_index else {
            return;
        };
        if idx + 1 < self.command_history.len() {
            let next = idx + 1;
            self.history_index = Some(next);
            self.input = self.command_history[next].clone();
            self.cursor = self.char_count();
        } else {
            self.history_index = None;
            self.input = std::mem::take(&mut self.history_draft);
            self.cursor = self.char_count();
        }
    }
}
