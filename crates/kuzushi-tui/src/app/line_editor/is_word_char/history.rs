use super::*;

impl ShellApp {
    pub fn history_prev(&mut self) {
        self.editor.history_prev();
    }

    pub fn history_next(&mut self) {
        self.editor.history_next();
    }
}
