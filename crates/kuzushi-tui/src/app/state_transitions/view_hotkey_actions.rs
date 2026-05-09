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
        if let Some(handled) = self.apply_findings_hotkey(action) {
            return handled;
        }
        if self.apply_scroll_hotkey(action) {
            return true;
        }
        if self.apply_prompt_or_tune_hotkey(action) {
            return true;
        }
        if self.apply_actor_hotkey(action) {
            return true;
        }
        self.apply_shell_hotkey(action)
    }

    fn apply_findings_hotkey(&mut self, action: ViewHotkeyAction) -> Option<bool> {
        match action {
            ViewHotkeyAction::FindingsNext => {
                let max = self.findings.len().saturating_sub(1);
                self.findings_cursor = (self.findings_cursor + 1).min(max);
                Some(true)
            }
            ViewHotkeyAction::FindingsPrevious => {
                self.findings_cursor = self.findings_cursor.saturating_sub(1);
                Some(true)
            }
            ViewHotkeyAction::FindingsFirst => {
                self.findings_cursor = 0;
                Some(true)
            }
            ViewHotkeyAction::FindingsLast => {
                self.findings_cursor = self.findings.len().saturating_sub(1);
                Some(true)
            }
            ViewHotkeyAction::FindingsPageDown => {
                self.page_down_current_view();
                Some(true)
            }
            ViewHotkeyAction::FindingsPageUp => {
                self.page_up_current_view();
                Some(true)
            }
            ViewHotkeyAction::FindingsOpen => {
                if self.findings.is_empty() {
                    return Some(false);
                }
                self.open_finding_at_cursor();
                Some(true)
            }
            _ => None,
        }
    }

    fn apply_scroll_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::ViewScrollUp => self.scroll_up(1),
            ViewHotkeyAction::ViewScrollDown => self.scroll_down(1),
            ViewHotkeyAction::ViewScrollTop => self.scroll_to_top(),
            ViewHotkeyAction::ViewScrollBottom => self.scroll_to_bottom(),
            _ => return false,
        }
        true
    }

    fn apply_prompt_or_tune_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::TuneCursorPrevious => self.move_tune_cursor(-1),
            ViewHotkeyAction::TuneCursorNext => self.move_tune_cursor(1),
            ViewHotkeyAction::TuneActivate => self.activate_tune_action(),
            ViewHotkeyAction::PromptsCursorPrevious => self.move_prompts_cursor(-1),
            ViewHotkeyAction::PromptsCursorNext => self.move_prompts_cursor(1),
            ViewHotkeyAction::PromptsAction(action) => self.activate_prompts_action(action),
            _ => return false,
        }
        true
    }

    fn apply_actor_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::ActorDetail(index) => self.shell_view = ShellView::ActorDetail(index),
            ViewHotkeyAction::ActorDetailFilterCycle => {
                self.actor_detail_filter = self.actor_detail_filter.next();
            }
            ViewHotkeyAction::ActorDetailFilterReset => {
                self.actor_detail_filter = ActorDetailFilter::All;
            }
            _ => return false,
        }
        true
    }

    fn apply_shell_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::ThreatView(view) => {
                self.shell_view = ShellView::Threat(view);
            }
            ViewHotkeyAction::PauseScan => {
                self.handle_command(ShellCommand::Pause);
            }
            ViewHotkeyAction::ResumeScan => {
                self.handle_command(ShellCommand::Resume(None));
            }
            ViewHotkeyAction::ActivityTabPaneFocus => {
                if let Some(session) = self.activity.as_mut() {
                    session.toggle_pane_focus();
                }
            }
            ViewHotkeyAction::ActivityToggleVerbose => {
                if let Some(session) = self.activity.as_mut() {
                    session.toggle_verbose_subsystems();
                }
            }
            ViewHotkeyAction::ActivityTogglePause => {
                if let Some(session) = self.activity.as_mut() {
                    session.toggle_paused();
                }
            }
            ViewHotkeyAction::ActivityReset => {
                self.activity = None;
            }
            ViewHotkeyAction::ActivityFocusSelected => {
                if let Some(session) = self.activity.as_mut() {
                    if !session.tasks.is_empty() {
                        let cursor = session
                            .task_scroll
                            .min(session.tasks.len().saturating_sub(1));
                        let task_id = session
                            .tasks
                            .values()
                            .nth(cursor)
                            .map(|row| row.task_id.clone());
                        session.focus_task = task_id;
                    }
                }
            }
            ViewHotkeyAction::ActivityCancelRunning => {
                // Try scan first, then single-tool. Both are no-ops if nothing
                // is running, so the order doesn't matter much; scan abort
                // first matches the operator mental model when both fire.
                let aborted = self.request_scan_abort() || self.request_tool_abort();
                if !aborted {
                    self.log(
                        "activity",
                        "no running tool or scan to cancel",
                    );
                }
            }
            _ => return false,
        }
        true
    }
}
