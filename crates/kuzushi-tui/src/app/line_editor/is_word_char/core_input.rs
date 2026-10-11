use super::*;

pub(crate) fn is_word_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

impl ShellApp {
    pub fn set_input(&mut self, value: impl Into<String>) {
        self.editor_mut().set_input(value);
    }

    pub fn clear_input(&mut self) {
        self.editor_mut().clear_input();
    }

    /// Esc behavior: progressive draft preservation (M3 §3.3).
    ///   1. If a completion cycle is active, restore the operator's
    ///      original prefix and close the popup.
    ///   2. Otherwise clear an in-progress draft, stashing it for
    ///      explicit undo via Ctrl+_ / Ctrl+/.
    ///   3. Empty-prompt Esc is not consumed here; view navigation owns it.
    pub fn esc_clear_input_or_completion(&mut self) -> bool {
        match self.editor_mut().esc_clear_input_or_completion() {
            EditorClearResult::Ignored => false,
            EditorClearResult::CompletionRestored => true,
            EditorClearResult::DraftCleared => {
                self.log("input", "draft cleared — Ctrl+_ restores; Esc goes back");
                true
            }
        }
    }

    pub fn restore_last_cleared_input(&mut self) {
        let restored = self.editor_mut().restore_last_cleared_input();
        if restored && self.input_mode() == InputMode::Navigate {
            self.log("input", "draft restored; Esc opens the command line");
        }
    }

    pub fn take_input(&mut self) -> String {
        self.editor_mut().take_input()
    }
}
