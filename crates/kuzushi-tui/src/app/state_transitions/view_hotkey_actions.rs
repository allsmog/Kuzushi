use super::*;

impl ShellApp {
    pub(super) fn handle_view_hotkey(&mut self, key: KeyEvent) -> bool {
        let Some(binding) = self
            .view_keybindings()
            .into_iter()
            .find(|binding| binding.matches(key))
        else {
            return self.handle_generic_scroll_hotkey(key);
        };
        let char_trigger = binding.trigger.is_char();
        let handled = self.apply_view_hotkey(binding.action);
        if handled && char_trigger {
            self.last_char_at = Some(Instant::now());
        }
        handled
    }

    pub(super) fn apply_view_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::FindingsNext => {
                let max = self.findings.len().saturating_sub(1);
                self.findings_cursor = (self.findings_cursor + 1).min(max);
            }
            ViewHotkeyAction::FindingsPrevious => {
                self.findings_cursor = self.findings_cursor.saturating_sub(1);
            }
            ViewHotkeyAction::FindingsFirst => {
                self.findings_cursor = 0;
            }
            ViewHotkeyAction::FindingsLast => {
                self.findings_cursor = self.findings.len().saturating_sub(1);
            }
            ViewHotkeyAction::FindingsPageDown => {
                self.page_down_current_view();
            }
            ViewHotkeyAction::FindingsPageUp => {
                self.page_up_current_view();
            }
            ViewHotkeyAction::FindingsOpen => {
                if self.findings.is_empty() {
                    return false;
                }
                self.open_finding_at_cursor();
            }
            ViewHotkeyAction::ThreatView(view) => {
                self.shell_view = ShellView::Threat(view);
            }
            ViewHotkeyAction::ActorDetail(index) => {
                self.shell_view = ShellView::ActorDetail(index);
            }
            ViewHotkeyAction::PauseScan => {
                self.handle_command(ShellCommand::Pause);
            }
            ViewHotkeyAction::ResumeScan => {
                self.handle_command(ShellCommand::Resume(None));
            }
            ViewHotkeyAction::ViewScrollUp => self.scroll_up(1),
            ViewHotkeyAction::ViewScrollDown => self.scroll_down(1),
            ViewHotkeyAction::ViewScrollTop => self.scroll_to_top(),
            ViewHotkeyAction::ViewScrollBottom => self.scroll_to_bottom(),
            ViewHotkeyAction::TuneCursorPrevious => self.move_tune_cursor(-1),
            ViewHotkeyAction::TuneCursorNext => self.move_tune_cursor(1),
            ViewHotkeyAction::TuneActivate => self.activate_tune_action(),
            ViewHotkeyAction::PromptsCursorPrevious => self.move_prompts_cursor(-1),
            ViewHotkeyAction::PromptsCursorNext => self.move_prompts_cursor(1),
            ViewHotkeyAction::PromptsAction(action) => self.activate_prompts_action(action),
            ViewHotkeyAction::ActorDetailFilterCycle => {
                self.actor_detail_filter = self.actor_detail_filter.next();
            }
            ViewHotkeyAction::ActorDetailFilterReset => {
                self.actor_detail_filter = ActorDetailFilter::All;
            }
        }
        true
    }
}
