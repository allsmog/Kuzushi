use super::*;
impl ShellApp {
    /// Begin a Ctrl+R reverse-history search seeded with the current input.
    pub(crate) fn enter_history_search(&mut self) {
        self.editor_mut().enter_history_search();
    }

    pub(crate) fn history_search_input(&mut self, ch: char) {
        self.editor_mut().history_search_input(ch);
    }

    pub(crate) fn history_search_backspace(&mut self) {
        self.editor_mut().history_search_backspace();
    }

    /// Ctrl+R again steps to the next (older) match, wrapping at the end.
    pub(crate) fn history_search_next(&mut self) {
        self.editor.history_search_next();
    }

    /// Accept the highlighted match into the prompt and leave search mode.
    pub(crate) fn accept_history_search(&mut self) {
        self.editor.accept_history_search();
    }

    /// Cancel search, restoring an empty prompt (the pre-search draft was
    /// consumed as the seed query, matching readline's Ctrl+G behavior).
    pub(crate) fn cancel_history_search(&mut self) {
        self.editor_mut().cancel_history_search();
    }

    pub(crate) fn current_history_match(&self) -> Option<&str> {
        self.editor.current_history_match()
    }
}
