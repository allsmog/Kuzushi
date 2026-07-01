use super::*;

impl ShellApp {
    pub(super) fn handle_text_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(ch) => self.insert_printable_key(ch),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Tab => self.apply_completion(),
            KeyCode::PageDown if self.input.is_empty() && key.modifiers.is_empty() => {
                self.page_down_current_view();
            }
            KeyCode::PageUp if self.input.is_empty() && key.modifiers.is_empty() => {
                self.page_up_current_view();
            }
            KeyCode::Enter => self.handle_enter_key(),
            KeyCode::Esc => self.esc_clear_or_restore(),
            _ => return false,
        }
        true
    }

    pub(super) fn insert_printable_key(&mut self, ch: char) {
        self.insert_char_at_cursor(ch);
        self.last_char_at = Some(Instant::now());
    }

    pub(super) fn handle_enter_key(&mut self) {
        let raw = self.take_input();
        if self.submit_catalog_cursor_for_empty_enter(&raw) {
            return;
        }
        self.submit_line(&raw);
    }

    pub(super) fn submit_catalog_cursor_for_empty_enter(&mut self, raw: &str) -> bool {
        if !raw.is_empty()
            || !matches!(self.shell_view, ShellView::Catalog)
            || !self.catalog_expanded
        {
            return false;
        }
        let Some(id) = self.catalog_cursor_module_id() else {
            return false;
        };
        self.submit_line(&format!("use {id}"));
        true
    }

    pub(super) fn clear_conversation_preserving_input(&mut self) {
        let saved_input = std::mem::take(&mut self.input);
        let saved_cursor = self.cursor;
        self.clear_conversation();
        self.input = saved_input;
        self.cursor = saved_cursor.min(self.input.chars().count());
    }

    pub fn handle_paste(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let normalised: String = text
            .replace("\r\n", "\n")
            .chars()
            .filter(|ch| *ch != '\r')
            .collect();
        // Multi-line pastes: keep the first line so the user can review and
        // submit explicitly, then warn about the dropped tail. Submitting
        // every \n-separated line as its own command is what bash/zsh do;
        // the kuzushi shell is a single-command-per-Enter prompt and
        // exposing the same behavior runs unintended commands (e.g. pasting
        // a snippet that begins with `rm`).
        if normalised.contains('\n') {
            let first_line = normalised.lines().next().unwrap_or("");
            let total = normalised.chars().count();
            let kept = first_line.chars().count();
            self.insert_str_at_cursor(first_line);
            let dropped_lines = normalised.lines().count().saturating_sub(1);
            self.set_warn_notice(
                "paste",
                format!(
                    "kept first line ({kept}/{total} chars); dropped {dropped_lines} more line(s). Submit, then paste the next part."
                ),
            );
            return;
        }
        self.insert_str_at_cursor(&normalised);
    }

    /// The wheel moves the FINDINGS cursor only when the Workbench has that
    /// pane focused and there are findings; everywhere else it scrolls lines.
    fn mouse_scrolls_findings(&self) -> bool {
        matches!(self.shell_view, ShellView::Workbench)
            && self.workbench_focus == crate::app::WorkbenchPane::Findings
            && !self.findings.is_empty()
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if self.mouse_scrolls_findings() {
                    self.findings_cursor = self.findings_cursor.saturating_sub(1);
                } else {
                    self.scroll_up(1);
                }
            }
            MouseEventKind::ScrollDown => {
                if self.mouse_scrolls_findings() {
                    self.findings_cursor =
                        (self.findings_cursor + 1).min(self.findings.len().saturating_sub(1));
                } else {
                    self.scroll_down(1);
                }
            }
            _ => {}
        }
    }
}
