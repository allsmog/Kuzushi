use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};

use crate::commands::ShellCommand;

use super::{
    ActorDetailFilter, BudgetHalt, PromptsAction, ShellApp, ShellView, ThreatView,
    ThrottleAdvisory, CTRL_C_ARM_WINDOW, FINDINGS_PAGE_ROWS, SPINNER_FRAME, THROTTLE_STALE_AFTER,
    VIEWPORT_PAGE_LINES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HotkeyTrigger {
    Char(char),
    Enter,
    PageUp,
    PageDown,
    Up,
    Down,
}

impl HotkeyTrigger {
    fn matches(self, key: KeyEvent) -> bool {
        if !key.modifiers.is_empty() {
            return false;
        }
        match (self, key.code) {
            (Self::Char(expected), KeyCode::Char(actual)) => expected == actual,
            (Self::Enter, KeyCode::Enter) => true,
            (Self::PageUp, KeyCode::PageUp) => true,
            (Self::PageDown, KeyCode::PageDown) => true,
            (Self::Up, KeyCode::Up) => true,
            (Self::Down, KeyCode::Down) => true,
            _ => false,
        }
    }

    fn is_char(self) -> bool {
        matches!(self, Self::Char(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViewHotkeyAction {
    FindingsNext,
    FindingsPrevious,
    FindingsFirst,
    FindingsLast,
    FindingsPageDown,
    FindingsPageUp,
    FindingsOpen,
    ThreatView(ThreatView),
    ActorDetail(usize),
    PauseScan,
    ResumeScan,
    ViewScrollUp,
    ViewScrollDown,
    ViewScrollTop,
    ViewScrollBottom,
    TuneCursorPrevious,
    TuneCursorNext,
    TuneActivate,
    PromptsCursorPrevious,
    PromptsCursorNext,
    PromptsAction(PromptsAction),
    ActorDetailFilterCycle,
    ActorDetailFilterReset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ViewKeybinding {
    pub trigger: HotkeyTrigger,
    pub hint: &'static str,
    pub label: &'static str,
    pub action: ViewHotkeyAction,
}

impl ViewKeybinding {
    fn matches(self, key: KeyEvent) -> bool {
        self.trigger.matches(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyModifierState {
    ctrl: bool,
    alt: bool,
    plain: bool,
    no_modifiers: bool,
}

impl KeyModifierState {
    fn new(key: KeyEvent) -> Self {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        Self {
            ctrl,
            alt,
            plain: !ctrl && !alt,
            no_modifiers: key.modifiers.is_empty(),
        }
    }

    fn ctrl_or_alt(self) -> bool {
        self.ctrl || self.alt
    }
}

fn is_quit_chord(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('d'))
}

impl ShellApp {
    pub(crate) fn view_keybindings(&self) -> Vec<ViewKeybinding> {
        match self.shell_view {
            ShellView::Findings if !self.findings.is_empty() => vec![
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('j'),
                    hint: "j/k/g/G",
                    label: "move",
                    action: ViewHotkeyAction::FindingsNext,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('k'),
                    hint: "j/k/g/G",
                    label: "move",
                    action: ViewHotkeyAction::FindingsPrevious,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('g'),
                    hint: "j/k/g/G",
                    label: "move",
                    action: ViewHotkeyAction::FindingsFirst,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('G'),
                    hint: "j/k/g/G",
                    label: "move",
                    action: ViewHotkeyAction::FindingsLast,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::PageDown,
                    hint: "PgUp/PgDn",
                    label: "page",
                    action: ViewHotkeyAction::FindingsPageDown,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::PageUp,
                    hint: "PgUp/PgDn",
                    label: "page",
                    action: ViewHotkeyAction::FindingsPageUp,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Enter,
                    hint: "Enter",
                    label: "open",
                    action: ViewHotkeyAction::FindingsOpen,
                },
            ],
            ShellView::Threat(_) => vec![
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('1'),
                    hint: "1..5",
                    label: "switch threat view",
                    action: ViewHotkeyAction::ThreatView(ThreatView::Dfd),
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('2'),
                    hint: "1..5",
                    label: "switch threat view",
                    action: ViewHotkeyAction::ThreatView(ThreatView::Stride),
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('3'),
                    hint: "1..5",
                    label: "switch threat view",
                    action: ViewHotkeyAction::ThreatView(ThreatView::Stories),
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('4'),
                    hint: "1..5",
                    label: "switch threat view",
                    action: ViewHotkeyAction::ThreatView(ThreatView::Scope),
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('5'),
                    hint: "1..5",
                    label: "switch threat view",
                    action: ViewHotkeyAction::ThreatView(ThreatView::Summary),
                },
            ],
            ShellView::ModuleRun => {
                let mut bindings = Vec::new();
                for index in 1..=4 {
                    bindings.push(ViewKeybinding {
                        trigger: HotkeyTrigger::Char(char::from_digit(index as u32, 10).unwrap()),
                        hint: "1..4",
                        label: "actor",
                        action: ViewHotkeyAction::ActorDetail(index),
                    });
                }
                if self.can_pause_scan_hotkey() {
                    bindings.push(ViewKeybinding {
                        trigger: HotkeyTrigger::Char('p'),
                        hint: "p",
                        label: "pause",
                        action: ViewHotkeyAction::PauseScan,
                    });
                    bindings.push(ViewKeybinding {
                        trigger: HotkeyTrigger::Char('P'),
                        hint: "p",
                        label: "pause",
                        action: ViewHotkeyAction::PauseScan,
                    });
                }
                if self.can_resume_scan_hotkey() {
                    bindings.push(ViewKeybinding {
                        trigger: HotkeyTrigger::Char('r'),
                        hint: "r",
                        label: "resume",
                        action: ViewHotkeyAction::ResumeScan,
                    });
                    bindings.push(ViewKeybinding {
                        trigger: HotkeyTrigger::Char('R'),
                        hint: "r",
                        label: "resume",
                        action: ViewHotkeyAction::ResumeScan,
                    });
                }
                bindings
            }
            ShellView::ActorDetail(_) => vec![
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('f'),
                    hint: "f",
                    label: "filter",
                    action: ViewHotkeyAction::ActorDetailFilterCycle,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('0'),
                    hint: "0",
                    label: "reset filter",
                    action: ViewHotkeyAction::ActorDetailFilterReset,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('j'),
                    hint: "j/k/g/G",
                    label: "scroll",
                    action: ViewHotkeyAction::ViewScrollDown,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('k'),
                    hint: "j/k/g/G",
                    label: "scroll",
                    action: ViewHotkeyAction::ViewScrollUp,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('g'),
                    hint: "j/k/g/G",
                    label: "scroll",
                    action: ViewHotkeyAction::ViewScrollTop,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('G'),
                    hint: "j/k/g/G",
                    label: "scroll",
                    action: ViewHotkeyAction::ViewScrollBottom,
                },
            ],
            ShellView::PromptsEditor => vec![
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('j'),
                    hint: "j/k",
                    label: "row",
                    action: ViewHotkeyAction::PromptsCursorNext,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('k'),
                    hint: "j/k",
                    label: "row",
                    action: ViewHotkeyAction::PromptsCursorPrevious,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Down,
                    hint: "Up/Down",
                    label: "row",
                    action: ViewHotkeyAction::PromptsCursorNext,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Up,
                    hint: "Up/Down",
                    label: "row",
                    action: ViewHotkeyAction::PromptsCursorPrevious,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('e'),
                    hint: "e/s/d/r",
                    label: "edit",
                    action: ViewHotkeyAction::PromptsAction(PromptsAction::Edit),
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('s'),
                    hint: "e/s/d/r",
                    label: "show",
                    action: ViewHotkeyAction::PromptsAction(PromptsAction::Show),
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('d'),
                    hint: "e/s/d/r",
                    label: "diff",
                    action: ViewHotkeyAction::PromptsAction(PromptsAction::Diff),
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('r'),
                    hint: "e/s/d/r",
                    label: "reset",
                    action: ViewHotkeyAction::PromptsAction(PromptsAction::Reset),
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('S'),
                    hint: "S",
                    label: "set",
                    action: ViewHotkeyAction::PromptsAction(PromptsAction::Set),
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Enter,
                    hint: "Enter",
                    label: "show",
                    action: ViewHotkeyAction::PromptsAction(PromptsAction::Show),
                },
            ],
            ShellView::Tune => vec![
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('j'),
                    hint: "j/k",
                    label: "row",
                    action: ViewHotkeyAction::TuneCursorNext,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Char('k'),
                    hint: "j/k",
                    label: "row",
                    action: ViewHotkeyAction::TuneCursorPrevious,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Down,
                    hint: "Up/Down",
                    label: "row",
                    action: ViewHotkeyAction::TuneCursorNext,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Up,
                    hint: "Up/Down",
                    label: "row",
                    action: ViewHotkeyAction::TuneCursorPrevious,
                },
                ViewKeybinding {
                    trigger: HotkeyTrigger::Enter,
                    hint: "Enter",
                    label: "activate",
                    action: ViewHotkeyAction::TuneActivate,
                },
            ],
            _ => Vec::new(),
        }
    }

    fn can_pause_scan_hotkey(&self) -> bool {
        self.scan.as_ref().is_some_and(|scan| scan.running)
            && self.scan_cancel.is_some()
            && !self.is_scan_paused()
    }

    fn can_resume_scan_hotkey(&self) -> bool {
        self.scan.as_ref().is_some_and(|scan| scan.running)
            && self.scan_cancel.is_some()
            && self.is_scan_paused()
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.handle_modal_key(key) {
            return;
        }

        self.update_quit_chord_arm(key);
        if self.handle_story_toggle_key(key) {
            return;
        }

        let modifiers = KeyModifierState::new(key);
        self.reset_completion_cycle_for_key(key);

        if self.handle_control_key(key, modifiers)
            || self.handle_cursor_key(key, modifiers)
            || self.handle_empty_input_view_key(key, modifiers)
            || self.handle_history_key(key, modifiers)
            || self.handle_text_key(key)
        {
            return;
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) -> bool {
        self.handle_prereq_prompt_key(key)
            || self.handle_confirm_key(key)
            || self.handle_budget_key(key)
            || self.handle_pending_plan_key(key)
    }

    fn handle_prereq_prompt_key(&mut self, key: KeyEvent) -> bool {
        if self.pending_prereq_prompt.is_none() || !key.modifiers.is_empty() {
            return false;
        }
        let KeyCode::Char(ch) = key.code else {
            return false;
        };
        match ch {
            'r' | 'R' | 'y' | 'Y' => {
                self.resolve_prereq_prompt(true);
                true
            }
            'g' | 'G' | 'n' | 'N' => {
                self.resolve_prereq_prompt(false);
                true
            }
            _ => false,
        }
    }

    fn handle_confirm_key(&mut self, key: KeyEvent) -> bool {
        if self.advisory.pending_confirm.is_none() || !key.modifiers.is_empty() {
            return false;
        }
        let KeyCode::Char(ch) = key.code else {
            return false;
        };
        match ch {
            'y' => {
                self.resolve_confirm(true, false);
            }
            'Y' => {
                self.resolve_confirm(true, true);
            }
            'n' => {
                self.resolve_confirm(false, false);
            }
            'N' => {
                self.resolve_confirm(false, true);
            }
            _ => return false,
        }
        true
    }

    fn handle_budget_key(&mut self, key: KeyEvent) -> bool {
        if !self.is_budget_halted() || !key.modifiers.is_empty() {
            return false;
        }
        let KeyCode::Char(ch) = key.code else {
            return false;
        };
        match ch.to_ascii_lowercase() {
            'c' => self.continue_past_budget(),
            'a' => self.abort_for_budget(),
            _ => return false,
        }
        true
    }

    fn handle_pending_plan_key(&mut self, key: KeyEvent) -> bool {
        if self.pending_plan.is_none() || !self.input.is_empty() || !key.modifiers.is_empty() {
            return false;
        }
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => self.apply_pending_plan(),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.discard_pending_plan(),
            KeyCode::Char(' ') => self.toggle_plan_change_skip(),
            KeyCode::Char('j') | KeyCode::Down => self.move_plan_cursor(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_plan_cursor(-1),
            KeyCode::Char('g') => self.plan_cursor = 0,
            KeyCode::Char('G') => self.move_plan_cursor_to_end(),
            _ => return false,
        }
        true
    }

    fn move_plan_cursor_to_end(&mut self) {
        let total = self.plan_change_count();
        if total > 0 {
            self.plan_cursor = total - 1;
        }
    }

    fn update_quit_chord_arm(&mut self, key: KeyEvent) {
        if !is_quit_chord(key) {
            self.ctrl_c_armed_at = None;
        }
    }

    fn handle_story_toggle_key(&mut self, key: KeyEvent) -> bool {
        if !key.modifiers.contains(KeyModifiers::CONTROL)
            || !matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O'))
        {
            return false;
        }
        self.toggle_story_overlay();
        true
    }

    fn reset_completion_cycle_for_key(&mut self, key: KeyEvent) {
        if !matches!(key.code, KeyCode::Tab) {
            self.reset_completion_cycle();
        }
    }

    fn handle_control_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        if !modifiers.ctrl {
            return false;
        }
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('d') => self.handle_quit_chord(),
            KeyCode::Char('a') => self.move_cursor_home(),
            KeyCode::Char('e') => self.move_cursor_end(),
            KeyCode::Char('b') => self.move_cursor_left(),
            KeyCode::Char('f') => self.move_cursor_right(),
            KeyCode::Char('w') => self.delete_word_left(),
            KeyCode::Char('u') => self.kill_to_start(),
            KeyCode::Char('k') => self.kill_to_end(),
            KeyCode::Char('h') => self.backspace(),
            KeyCode::Char('p') => self.history_prev(),
            KeyCode::Char('n') => self.history_next(),
            KeyCode::Char('l') => self.clear_conversation_preserving_input(),
            _ => return false,
        }
        true
    }

    fn clear_conversation_preserving_input(&mut self) {
        let saved_input = std::mem::take(&mut self.input);
        let saved_cursor = self.cursor;
        self.clear_conversation();
        self.input = saved_input;
        self.cursor = saved_cursor.min(self.input.chars().count());
    }

    fn handle_cursor_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        match key.code {
            KeyCode::Left if modifiers.ctrl_or_alt() => self.move_cursor_word_left(),
            KeyCode::Right if modifiers.ctrl_or_alt() => self.move_cursor_word_right(),
            KeyCode::Backspace if modifiers.ctrl_or_alt() => self.delete_word_left(),
            KeyCode::Left if modifiers.plain => self.move_cursor_left(),
            KeyCode::Right if modifiers.plain => self.move_cursor_right(),
            KeyCode::Home => self.move_cursor_home(),
            KeyCode::End => self.move_cursor_end(),
            KeyCode::Delete => self.delete_forward(),
            _ => return false,
        }
        true
    }

    fn handle_empty_input_view_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        if !self.input.is_empty() {
            return false;
        }
        if self.handle_config_view_key(key, modifiers) {
            return true;
        }
        if self.handle_findings_view_key(key, modifiers) {
            return true;
        }
        if matches!(key.code, KeyCode::Up | KeyCode::Down)
            && modifiers.plain
            && self.handle_view_hotkey(key)
        {
            return true;
        }
        modifiers.no_modifiers && self.handle_view_hotkey(key)
    }

    fn handle_config_view_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        if !modifiers.plain || !matches!(self.shell_view, ShellView::Config) {
            return false;
        }
        match key.code {
            KeyCode::Up => self.move_model_selection(-1),
            KeyCode::Down => self.move_model_selection(1),
            KeyCode::Enter => self.select_current_model_choice(),
            _ => return false,
        }
        true
    }

    fn handle_findings_view_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        if !modifiers.plain || !matches!(self.shell_view, ShellView::Findings) {
            return false;
        }
        match key.code {
            KeyCode::Up => self.findings_cursor = self.findings_cursor.saturating_sub(1),
            KeyCode::Down => {
                self.findings_cursor =
                    (self.findings_cursor + 1).min(self.findings.len().saturating_sub(1));
            }
            _ => return false,
        }
        true
    }

    fn handle_history_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        if !modifiers.plain {
            return false;
        }
        match key.code {
            KeyCode::Up => self.history_prev(),
            KeyCode::Down => self.history_next(),
            _ => return false,
        }
        true
    }

    fn handle_text_key(&mut self, key: KeyEvent) -> bool {
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

    fn insert_printable_key(&mut self, ch: char) {
        self.insert_char_at_cursor(ch);
        self.last_char_at = Some(Instant::now());
    }

    fn handle_enter_key(&mut self) {
        let raw = self.take_input();
        if self.submit_catalog_cursor_for_empty_enter(&raw) {
            return;
        }
        self.submit_line(&raw);
    }

    fn submit_catalog_cursor_for_empty_enter(&mut self, raw: &str) -> bool {
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
            self.log(
                "paste",
                format!(
                    "kept first line ({kept}/{total} chars); dropped {dropped_lines} more line(s). Submit, then paste the next part."
                ),
            );
            return;
        }
        self.insert_str_at_cursor(&normalised);
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if matches!(self.shell_view, ShellView::Findings) && !self.findings.is_empty() {
                    self.findings_cursor = self.findings_cursor.saturating_sub(3);
                } else {
                    self.scroll_up(3);
                }
            }
            MouseEventKind::ScrollDown => {
                if matches!(self.shell_view, ShellView::Findings) && !self.findings.is_empty() {
                    self.findings_cursor =
                        (self.findings_cursor + 3).min(self.findings.len().saturating_sub(1));
                } else {
                    self.scroll_down(3);
                }
            }
            _ => {}
        }
    }

    fn handle_view_hotkey(&mut self, key: KeyEvent) -> bool {
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

    fn apply_view_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
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

    fn handle_generic_scroll_hotkey(&mut self, key: KeyEvent) -> bool {
        // Catalog j/k drives the row cursor (`design/mockups/catalog.jsx`
        // advertises `j/k row`), not the module-scroll.  Catalog scrolling
        // already lives on PgUp/PgDn for very tall workspaces.
        if matches!(self.shell_view, ShellView::Catalog) && self.catalog_expanded {
            match key.code {
                KeyCode::Char('j') => {
                    self.move_catalog_cursor(1);
                    return true;
                }
                KeyCode::Char('k') => {
                    self.move_catalog_cursor(-1);
                    return true;
                }
                KeyCode::Char('g') => {
                    self.catalog_cursor = 0;
                    return true;
                }
                KeyCode::Char('G') => {
                    let total = self.catalog_module_count();
                    self.catalog_cursor = total.saturating_sub(1);
                    return true;
                }
                _ => {}
            }
        }
        if !self.is_scrollable_view() {
            return false;
        }
        match key.code {
            KeyCode::Char('j') => self.scroll_down(1),
            KeyCode::Char('k') => self.scroll_up(1),
            KeyCode::Char('g') => self.scroll_to_top(),
            KeyCode::Char('G') => self.scroll_to_bottom(),
            _ => return false,
        }
        true
    }

    fn page_down_current_view(&mut self) {
        let step = VIEWPORT_PAGE_LINES;
        match self.shell_view {
            ShellView::Findings => {
                if !self.findings.is_empty() {
                    self.findings_cursor = (self.findings_cursor + FINDINGS_PAGE_ROWS)
                        .min(self.findings.len().saturating_sub(1));
                }
            }
            ShellView::Help | ShellView::Quickstart => {
                self.help_scroll = self.help_scroll.saturating_add(step);
            }
            ShellView::Tools => self.tools_scroll = self.tools_scroll.saturating_add(step),
            ShellView::History => self.history_scroll = self.history_scroll.saturating_add(step),
            ShellView::KnowledgeBase => self.kb_scroll = self.kb_scroll.saturating_add(step),
            ShellView::Catalog if self.catalog_expanded => {
                self.modules_scroll = self.modules_scroll.saturating_add(step);
            }
            _ if self.is_scrollable_view() => self.scroll_down(step as u16),
            _ => {}
        }
    }

    fn page_up_current_view(&mut self) {
        let step = VIEWPORT_PAGE_LINES;
        match self.shell_view {
            ShellView::Findings => {
                self.findings_cursor = self.findings_cursor.saturating_sub(FINDINGS_PAGE_ROWS);
            }
            ShellView::Help | ShellView::Quickstart => {
                self.help_scroll = self.help_scroll.saturating_sub(step);
            }
            ShellView::Tools => self.tools_scroll = self.tools_scroll.saturating_sub(step),
            ShellView::History => self.history_scroll = self.history_scroll.saturating_sub(step),
            ShellView::KnowledgeBase => self.kb_scroll = self.kb_scroll.saturating_sub(step),
            ShellView::Catalog if self.catalog_expanded => {
                self.modules_scroll = self.modules_scroll.saturating_sub(step);
            }
            _ if self.is_scrollable_view() => self.scroll_up(step as u16),
            _ => {}
        }
    }

    fn is_scrollable_view(&self) -> bool {
        match &self.shell_view {
            ShellView::Catalog => self.catalog_expanded,
            ShellView::Help
            | ShellView::Quickstart
            | ShellView::Tools
            | ShellView::Options(_)
            | ShellView::Runs
            | ShellView::Replay(_)
            | ShellView::Trace(_)
            | ShellView::SastTasks
            | ShellView::Context
            | ShellView::Workspace
            | ShellView::KnowledgeBase
            | ShellView::AgentChat
            | ShellView::History
            | ShellView::Story
            | ShellView::Threat(_)
            | ShellView::ThreatEditor
            | ShellView::PromptsEditor
            | ShellView::Tune
            | ShellView::ActorDetail(_)
            | ShellView::ModuleRun
            | ShellView::Finding => true,
            _ => false,
        }
    }

    pub(super) fn go_back(&mut self) {
        self.shell_view = match self.shell_view {
            ShellView::Finding => ShellView::Findings,
            ShellView::Findings
            | ShellView::Help
            | ShellView::Quickstart
            | ShellView::Config
            | ShellView::Tools
            | ShellView::Runs
            | ShellView::Replay(_)
            | ShellView::Trace(_)
            | ShellView::History
            | ShellView::Story
            | ShellView::Auth
            | ShellView::Cost
            | ShellView::Patch(_)
            | ShellView::Threat(_)
            | ShellView::ThreatEditor => ShellView::Catalog,
            ShellView::Tune
            | ShellView::PromptsEditor
            | ShellView::Options(_)
            | ShellView::SastTasks
            | ShellView::Context
            | ShellView::Workspace
            | ShellView::KnowledgeBase
            | ShellView::AgentChat => {
                if self.focused_module.is_some() {
                    ShellView::Module
                } else {
                    ShellView::Catalog
                }
            }
            ShellView::ActorDetail(_) => ShellView::ModuleRun,
            ShellView::ModuleRun | ShellView::Module => ShellView::Catalog,
            ShellView::Catalog => ShellView::Catalog,
        };
    }

    pub(super) fn request_exit(&mut self) {
        self.request_active_abort();
        if !self.should_quit {
            self.log("system", "exit requested; closing shell");
        }
        self.should_quit = true;
    }

    fn request_active_abort(&mut self) -> bool {
        let mut requested = false;
        requested |= self.request_scan_abort();
        requested |= self.request_tool_abort();
        requested |= self.request_agent_abort();
        requested |= self.request_plan_abort();
        requested |= self.request_threat_abort();
        requested
    }

    fn request_scan_abort(&mut self) -> bool {
        if !self.scan.as_ref().is_some_and(|scan| scan.running) {
            return false;
        }
        if self.scan.as_ref().is_some_and(|scan| scan.abort_requested) {
            return false;
        }

        if let Some(cancel) = &self.scan_cancel {
            cancel.cancel();
        }
        if let Some(scan) = &mut self.scan {
            scan.stage = "abort requested".to_string();
            scan.abort_requested = true;
        }
        self.log(
            "scan",
            "abort requested; waiting for scanner subprocess to stop (not claiming it was killed)",
        );
        true
    }

    fn request_tool_abort(&mut self) -> bool {
        let Some(tool_name) = self.tool_running.clone() else {
            return false;
        };
        if self.tool_abort_requested {
            return false;
        }
        self.tool_abort_requested = true;
        self.log(
            "tool",
            format!("{tool_name} abort requested; waiting for the current filesystem step to finish (process kill not confirmed)"),
        );
        true
    }

    fn request_agent_abort(&mut self) -> bool {
        let Some(agent) = &mut self.agent_chat else {
            return false;
        };
        if !agent.running || agent.abort_requested {
            return false;
        }
        agent.abort_requested = true;
        self.log(
            "agent",
            "abort requested; waiting for pi-agent-core to return (process kill not confirmed)",
        );
        true
    }

    fn request_plan_abort(&mut self) -> bool {
        if !self.planner_running || self.plan_abort_requested {
            return false;
        }
        self.plan_abort_requested = true;
        self.log(
            "plan",
            "abort requested; waiting for pi-agent-core planner to return (process kill not confirmed)",
        );
        true
    }

    fn request_threat_abort(&mut self) -> bool {
        if !self.threat_worker_running || self.threat_abort_requested {
            return false;
        }
        self.threat_abort_requested = true;
        self.log(
            "threats",
            "abort requested; waiting for pi-agent-core threat worker to return (process kill not confirmed)",
        );
        true
    }

    fn handle_quit_chord(&mut self) {
        if self.request_active_abort() {
            self.ctrl_c_armed_at = None;
            return;
        }
        let now = Instant::now();
        if let Some(armed_at) = self.ctrl_c_armed_at {
            if now.duration_since(armed_at) <= CTRL_C_ARM_WINDOW {
                self.should_quit = true;
                return;
            }
        }
        self.ctrl_c_armed_at = Some(now);
        self.log(
            "system",
            "press Ctrl+C again within 2s to exit (any other key cancels)",
        );
    }

    pub fn tick(&mut self) -> bool {
        let mut changed = false;
        if let Some(armed_at) = self.ctrl_c_armed_at {
            if Instant::now().duration_since(armed_at) > CTRL_C_ARM_WINDOW {
                self.ctrl_c_armed_at = None;
                changed = true;
            }
        }
        if let Some(throttle) = &self.advisory.throttle {
            if Instant::now().duration_since(throttle.since) > THROTTLE_STALE_AFTER {
                self.advisory.throttle = None;
                changed = true;
            }
        }
        if self.has_running_work() {
            let now = Instant::now();
            let due = self
                .last_spinner_advance
                .map(|prev| now.duration_since(prev) >= SPINNER_FRAME)
                .unwrap_or(true);
            if due {
                self.spinner_phase = self.spinner_phase.wrapping_add(1);
                self.last_spinner_advance = Some(now);
                changed = true;
            }
        } else {
            self.last_spinner_advance = None;
        }
        changed
    }

    pub fn has_running_work(&self) -> bool {
        let scan_running = self.scan.as_ref().is_some_and(|scan| scan.running);
        let tool_running = self.tool_running.is_some();
        let agent_running = self.agent_chat.as_ref().is_some_and(|agent| agent.running);
        scan_running
            || tool_running
            || agent_running
            || self.planner_running
            || self.threat_worker_running
    }

    pub fn spinner_glyph(&self) -> &'static str {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        FRAMES[(self.spinner_phase as usize) % FRAMES.len()]
    }

    pub fn ctrl_c_armed(&self) -> bool {
        self.ctrl_c_armed_at
            .map(|armed_at| Instant::now().duration_since(armed_at) <= CTRL_C_ARM_WINDOW)
            .unwrap_or(false)
    }

    pub fn set_throttle(&mut self, source: impl Into<String>, message: impl Into<String>) {
        let source = source.into();
        let message = message.into();
        self.log("throttle", format!("{source}: {message}"));
        self.advisory.throttle = Some(ThrottleAdvisory {
            source,
            message,
            since: Instant::now(),
        });
    }

    pub fn clear_throttle(&mut self) {
        self.advisory.throttle = None;
    }

    pub fn is_budget_halted(&self) -> bool {
        self.advisory.budget_halt.is_some()
    }

    pub fn record_cost(&mut self, cost_usd: f64) {
        self.last_tool_cost_usd = Some(cost_usd);
        self.session_cost_usd += cost_usd;
        self.maybe_trigger_budget_halt();
    }

    fn maybe_trigger_budget_halt(&mut self) {
        if self.advisory.budget_halt.is_some() {
            return;
        }
        if let Some(limit) = self.session_budget_usd {
            if limit > 0.0 && self.session_cost_usd >= limit {
                self.advisory.budget_halt = Some(BudgetHalt {
                    limit_usd: limit,
                    spent_usd: self.session_cost_usd,
                });
                self.log(
                    "budget",
                    format!(
                        "session cost ${:.4} reached cap ${:.4}; press [c] to continue or [a] to abort",
                        self.session_cost_usd, limit
                    ),
                );
            }
        }
    }

    fn continue_past_budget(&mut self) {
        if let Some(halt) = self.advisory.budget_halt.take() {
            self.session_budget_usd = Some(halt.spent_usd * 2.0);
            self.log(
                "budget",
                format!(
                    "continuing past ${:.4}; new soft cap ${:.4}",
                    halt.spent_usd,
                    self.session_cost_usd * 2.0
                ),
            );
        }
    }

    fn abort_for_budget(&mut self) {
        self.advisory.budget_halt = None;
        let requested = self.request_active_abort();
        self.log(
            "budget",
            format!(
                "aborting due to cost cap (abort requested: {requested}). Next: /cost or /scan",
            ),
        );
    }
}
