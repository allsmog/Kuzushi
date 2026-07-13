use super::confirmation_keys::{
    confirm_key_action, confirm_key_is_consumed_without_action, confirm_key_modifiers_allowed,
    ConfirmKeyAction,
};
use super::control_keys::control_key_action;
use super::*;

impl ShellApp {
    pub(crate) fn reduce_key(&mut self, key: KeyEvent) -> InputUpdate {
        let update = self.reduce_key_without_recording(key);
        if update.handled {
            self.record_operator_interaction();
        }
        update
    }

    fn reduce_key_without_recording(&mut self, key: KeyEvent) -> InputUpdate {
        let budget_update = self.handle_budget_key(key);
        if budget_update.handled {
            return budget_update;
        }
        if let Some(update) = self.reduce_modal_key(key) {
            return update;
        }

        self.update_quit_chord_arm(key);
        if self.handle_story_toggle_key(key) {
            return InputUpdate::handled();
        }

        self.reduce_non_modal_key(key)
    }

    fn reduce_modal_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let update = self.handle_modal_key(key);
        if update.handled {
            return Some(update);
        }
        None
    }

    fn reduce_non_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        let modifiers = KeyModifierState::new(key);
        self.reset_completion_cycle_for_key(key);

        if let Some(update) = self.handle_autonomy_key(key, modifiers) {
            return update;
        }

        let update = self.handle_mode_or_control_key(key, modifiers);
        if update.handled {
            return update;
        }
        self.reduce_navigation_or_text_key(key, modifiers)
    }

    fn handle_mode_or_control_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if self.handle_input_mode_key(key, modifiers) {
            return InputUpdate::handled();
        }
        self.handle_control_key(key, modifiers)
    }

    fn reduce_navigation_or_text_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        match self.input_mode() {
            InputMode::Prompt => self.reduce_prompt_key(key, modifiers),
            InputMode::Navigate => self.reduce_navigate_key(key, modifiers),
        }
    }

    fn reduce_prompt_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> InputUpdate {
        if self.handle_cursor_key(key, modifiers) || self.handle_history_key(key, modifiers) {
            return InputUpdate::handled();
        }
        self.handle_text_key(key)
    }

    fn reduce_navigate_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> InputUpdate {
        let update = self.handle_empty_input_view_key(key, modifiers);
        if update.handled {
            return update;
        }
        InputUpdate::handled_if(self.handle_unhandled_navigation_key(key, modifiers))
    }

    fn record_operator_interaction(&mut self) {
        self.ui_mut().record_operator_interaction(Instant::now());
    }

    pub(super) fn handle_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        if matches!(self.shell_view(), ShellView::PromptsEditor)
            && self.router.prompts().document().is_some()
        {
            return self.reduce_prompt_document_key(key);
        }
        let prereq_update = self.handle_prereq_prompt_key(key);
        if prereq_update.handled {
            return prereq_update;
        }
        if self.handle_overlay_key(key) {
            return InputUpdate::handled();
        }
        self.handle_shared_modal_key(key)
    }

    /// Command palette and Ctrl+R reverse search both fully capture input while
    /// active. Checked before the normal key chain; Ctrl+C still falls through.
    fn handle_overlay_key(&mut self, key: KeyEvent) -> bool {
        if matches!(self.shell_view(), ShellView::CommandPalette) {
            return self.handle_command_palette_key(key);
        }
        if self.history_search().is_some() {
            return self.handle_history_search_key(key);
        }
        false
    }

    /// Drive Ctrl+R reverse search. Enter accepts, Esc/Ctrl+C cancels, Ctrl+R
    /// steps to the next match, Backspace/printables edit the query.
    fn handle_history_search_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Esc => self.cancel_history_search(),
            KeyCode::Char('c') if ctrl => {
                let work_running = self.has_running_work();
                self.cancel_history_search();
                if work_running {
                    return false;
                }
            }
            KeyCode::Char('r') if ctrl => self.history_search_next(),
            KeyCode::Enter => self.accept_history_search(),
            KeyCode::Backspace => self.history_search_backspace(),
            KeyCode::Char(ch) if !ctrl && !alt => self.history_search_input(ch),
            // Any navigation key accepts the match, then the keystroke is
            // re-dispatched normally (readline behavior).
            _ => {
                self.accept_history_search();
                return false;
            }
        }
        true
    }

    /// Drive the command palette while it is open. Ctrl+C falls through so the
    /// quit chord still works; everything else (typing, arrows, Enter, Esc) is
    /// consumed here.
    fn handle_command_palette_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Esc => self.close_palette(),
            KeyCode::Enter => self.accept_palette(),
            KeyCode::Up => self.palette_move(-1),
            KeyCode::Down => self.palette_move(1),
            KeyCode::Char('p') if ctrl => self.palette_move(-1),
            KeyCode::Char('n') if ctrl => self.palette_move(1),
            KeyCode::Char('g') if ctrl => self.close_palette(),
            KeyCode::Char('c') if ctrl => return false,
            KeyCode::Backspace => self.palette_backspace(),
            KeyCode::Char(ch) if !ctrl && !alt => self.palette_input(ch),
            _ => return false,
        }
        true
    }

    fn handle_shared_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        let update = self.handle_confirm_key(key);
        if update.handled {
            return update;
        }
        let update = self.handle_deferred_modal_key(key);
        if update.handled {
            return update;
        }
        InputUpdate::handled_if(self.handle_notice_dismiss_key(key))
    }

    fn handle_deferred_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        let update = self.handle_primary_deferred_modal_key(key);
        if update.handled {
            return update;
        }
        self.handle_secondary_deferred_modal_key(key)
    }

    fn handle_primary_deferred_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        let update = self.handle_pending_plan_key(key);
        if update.handled {
            return update;
        }
        self.handle_system_overlay_modal_key(key)
    }

    fn handle_secondary_deferred_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        let update = self.handle_retry_key(key);
        if update.handled {
            return update;
        }
        let update = self.handle_picker_key(key);
        if update.handled {
            return update;
        }
        InputUpdate::ignored()
    }

    fn handle_system_overlay_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        match self.shell_view() {
            ShellView::QuitConfirm => self.handle_quit_confirm_key(key),
            ShellView::Keymap => self.handle_keymap_overlay_key(key),
            _ => InputUpdate::ignored(),
        }
    }

    fn handle_keymap_overlay_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !KeyModifierState::new(key).no_modifiers {
            return InputUpdate::ignored();
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.go_back(),
            KeyCode::Char('j') => self.scroll_current_view_down(1),
            KeyCode::Char('k') => self.scroll_current_view_up(1),
            KeyCode::Char('g') => self.scroll_current_view_to_top(),
            KeyCode::Char('G') => self.scroll_current_view_to_bottom(),
            KeyCode::PageDown => self.page_down_current_view(),
            KeyCode::PageUp => self.page_up_current_view(),
            _ => return InputUpdate::handled(),
        }
        InputUpdate::handled()
    }

    fn handle_quit_confirm_key(&mut self, key: KeyEvent) -> InputUpdate {
        if quit_choice_matches(key, 'y', 'Y') {
            return InputUpdate::handled_with_effects(vec![ShellEffect::Quit]);
        }
        if quit_choice_matches(key, 'n', 'N') || HotkeyTrigger::Esc.matches(key) {
            self.go_back();
            return InputUpdate::handled();
        }
        if key.modifiers.is_empty() {
            return InputUpdate::handled();
        }
        InputUpdate::ignored()
    }

    /// The end-of-engagement retry gate: `y`/Enter retries the failed tasks
    /// (with auto-adjustments), `n`/Esc skips them.
    fn handle_retry_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.advisory().pending_retry.is_none() || !key.modifiers.is_empty() {
            return InputUpdate::ignored();
        }
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                InputUpdate::handled_with_effects(self.retry_failed_tasks())
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.decline_retry();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    /// Esc dismisses a visible notice banner. Returns false when no notice is
    /// present so Esc falls through to view-back / draft-restore as usual.
    fn handle_notice_dismiss_key(&mut self, key: KeyEvent) -> bool {
        if self.advisory().notice.is_none() || key.code != KeyCode::Esc || !key.modifiers.is_empty()
        {
            return false;
        }
        self.clear_notice();
        true
    }

    pub(super) fn handle_confirm_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !self.confirm_key_ready(key) {
            return InputUpdate::ignored();
        }
        let Some(action) = confirm_key_action(key.code) else {
            return InputUpdate::handled_if(confirm_key_is_consumed_without_action(key.code));
        };
        self.apply_confirm_key_action(action)
    }

    fn confirm_key_ready(&self, key: KeyEvent) -> bool {
        self.advisory().pending_confirm.is_some() && confirm_key_modifiers_allowed(key)
    }

    fn apply_confirm_key_action(&mut self, action: ConfirmKeyAction) -> InputUpdate {
        let resolved = self.resolve_confirm(action.outcome, action.remember);
        let launch = self.confirmed_run_launch(action, resolved.as_ref());
        self.advisory_mut().pending_confirm_launch = None;
        match launch {
            Some(launch) => {
                InputUpdate::handled_with_effects(vec![ShellEffect::DispatchRunTool(launch)])
            }
            None => InputUpdate::handled(),
        }
    }

    fn confirmed_run_launch(
        &mut self,
        action: ConfirmKeyAction,
        resolved: Option<&PendingConfirm>,
    ) -> Option<RunToolLaunch> {
        if !action.outcome {
            return None;
        }
        let request = resolved?;
        if !request.kind.allows_yes() {
            return None;
        }
        let mut launch = self.advisory_mut().pending_confirm_launch.take()?;
        launch.authorization = ExecutionAuthorization::interactive_request();
        Some(launch)
    }

    pub(super) fn handle_budget_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !self.is_budget_halted() {
            return InputUpdate::ignored();
        }
        let effect = match (key.code, key.modifiers.is_empty()) {
            (KeyCode::Char(ch), true) if ch.eq_ignore_ascii_case(&'c') => {
                Some(ShellEffect::ContinuePastBudget)
            }
            (KeyCode::Char(ch), true) if ch.eq_ignore_ascii_case(&'a') => {
                Some(ShellEffect::AbortForBudget)
            }
            _ => None,
        };
        effect.map_or_else(InputUpdate::handled, |effect| {
            InputUpdate::handled_with_effects(vec![effect])
        })
    }

    pub(super) fn update_quit_chord_arm(&mut self, key: KeyEvent) {
        if !is_quit_chord(key) {
            self.set_ctrl_c_armed_at(None);
        }
    }

    /// The always-available autonomy dial chord: `Ctrl+↑` raises the posture
    /// one rung, `Ctrl+↓` lowers it. Arrows are the only chord family free in
    /// every view and never swallowed by the text input line, so wiring is
    /// additive (no readline key is stolen). Runs before the text/nav chain;
    /// modal/palette/history-search already returned earlier in the dispatch,
    /// so the dial never fires while one of those is capturing input.
    fn handle_autonomy_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> Option<InputUpdate> {
        if !modifiers.ctrl {
            return None;
        }
        match key.code {
            KeyCode::Up => self.raise_autonomy(),
            KeyCode::Down => self.lower_autonomy(),
            _ => return None,
        }
        Some(InputUpdate::handled())
    }

    pub(super) fn handle_story_toggle_key(&mut self, key: KeyEvent) -> bool {
        if !key.modifiers.contains(KeyModifiers::CONTROL)
            || !matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O'))
        {
            return false;
        }
        self.toggle_story_overlay();
        true
    }

    pub(super) fn reset_completion_cycle_for_key(&mut self, key: KeyEvent) {
        // Tab keeps the cycle alive (it's the cycle's input). Esc owns
        // the cycle teardown via `esc_clear_input_or_completion` (M3 §3.3) so the
        // popup can restore the operator's original prefix instead of
        // losing it to a blanket reset.
        if matches!(key.code, KeyCode::Tab | KeyCode::Esc) {
            return;
        }
        self.reset_completion_cycle();
    }

    pub(super) fn handle_control_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if !modifiers.ctrl {
            return InputUpdate::ignored();
        }
        let Some(action) = control_key_action(key.code) else {
            return InputUpdate::ignored();
        };
        action.apply(self)
    }

    fn handle_input_mode_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        if !modifiers.no_modifiers {
            return false;
        }
        match key.code {
            KeyCode::F(2) => self.enter_navigate_mode(),
            KeyCode::Esc if self.input_mode() == InputMode::Navigate => self.enter_prompt_mode(),
            _ => return false,
        }
        true
    }

    fn enter_navigate_mode(&mut self) {
        if !self.input().is_empty() {
            self.log(
                "input",
                "finish or clear the prompt before entering navigation mode",
            );
            return;
        }
        self.set_input_mode(InputMode::Navigate);
        self.log("input", "navigation mode — Esc returns to prompt");
    }

    fn enter_prompt_mode(&mut self) {
        self.set_input_mode(InputMode::Prompt);
        self.log("input", "prompt mode — F2 returns to navigation");
    }

    fn handle_unhandled_navigation_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> bool {
        if self.input_mode() != InputMode::Navigate || !self.input().is_empty() || !modifiers.plain
        {
            return false;
        }
        match key.code {
            KeyCode::Char(ch) => self.log(
                "input",
                format!("no navigation action for `{ch}` here — Esc returns to prompt"),
            ),
            KeyCode::Enter | KeyCode::Tab | KeyCode::BackTab => {
                self.log("input", "no navigation action here — Esc returns to prompt")
            }
            _ => return false,
        }
        true
    }
}

fn quit_choice_matches(key: KeyEvent, lowercase: char, uppercase: char) -> bool {
    HotkeyTrigger::Char(lowercase).matches(key) || HotkeyTrigger::Char(uppercase).matches(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn plain_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    fn pending_network_confirm() -> PendingConfirm {
        PendingConfirm {
            kind: ConfirmKind::NetworkEgress,
            tool: "sandbox:run".to_string(),
            target: "https://refund.acme/api".to_string(),
            rationale: None,
            allowlist: None,
            actor: None,
            remembered: false,
        }
    }

    #[test]
    fn keymap_owns_scroll_and_close_keys_in_prompt_mode() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);
        app.sync_view_change();
        app.set_shell_view(ShellView::Keymap);
        app.sync_view_change();
        app.set_input_mode(InputMode::Prompt);

        app.reduce_key(plain_key(KeyCode::Char('j')));
        assert_eq!(app.router.default_scroll().offset(), 1);
        assert!(app.input().is_empty());

        app.reduce_key(plain_key(KeyCode::Char('x')));
        assert!(app.input().is_empty());

        app.reduce_key(plain_key(KeyCode::Esc));
        assert_eq!(app.shell_view(), ShellView::Workbench);
    }

    #[test]
    fn ctrl_arrows_move_the_autonomy_dial_without_typing_into_the_prompt() {
        use kuzushi_core::AutonomyPosture;
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_autonomy(AutonomyPosture::ReconOnly);

        let update = app.reduce_key(ctrl_key(KeyCode::Up));
        assert!(update.handled);
        assert_eq!(app.autonomy(), AutonomyPosture::Hunt);
        // The chord must never leak into the input line (regression against
        // handle_text_key inserting the keystroke).
        assert!(app.input().is_empty());

        let update = app.reduce_key(ctrl_key(KeyCode::Down));
        assert!(update.handled);
        assert_eq!(app.autonomy(), AutonomyPosture::ReconOnly);
        assert!(app.input().is_empty());
    }

    #[test]
    fn plain_arrows_do_not_move_the_autonomy_dial() {
        use kuzushi_core::AutonomyPosture;
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_autonomy(AutonomyPosture::Hunt);
        app.reduce_key(plain_key(KeyCode::Up));
        assert_eq!(app.autonomy(), AutonomyPosture::Hunt);
    }

    #[test]
    fn quit_confirm_y_is_consumed_as_quit_effect_not_text_input() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::QuitConfirm);

        let update = app.reduce_key(plain_key(KeyCode::Char('y')));

        assert!(update.handled);
        assert!(matches!(update.effects.as_slice(), [ShellEffect::Quit]));
        assert!(app.input().is_empty());
    }

    #[test]
    fn quit_confirm_n_is_consumed_as_close_not_text_input() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::QuitConfirm);

        let update = app.reduce_key(plain_key(KeyCode::Char('n')));

        assert!(update.handled);
        assert!(update.effects.is_empty());
        assert!(app.input().is_empty());
    }

    #[test]
    fn quit_confirm_shift_y_emits_quit_and_shift_n_stays() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::QuitConfirm);

        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('Y'), KeyModifiers::SHIFT));
        assert!(matches!(update.effects.as_slice(), [ShellEffect::Quit]));

        app.set_shell_view(ShellView::QuitConfirm);
        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('N'), KeyModifiers::SHIFT));
        assert!(update.handled);
        assert!(update.effects.is_empty());
    }

    #[test]
    fn quit_confirm_p_has_no_detach_action() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::QuitConfirm);

        let update = app.reduce_key(plain_key(KeyCode::Char('p')));

        assert!(update.handled);
        assert!(update.effects.is_empty());
        assert_eq!(app.shell_view(), ShellView::QuitConfirm);
        assert!(app
            .log_lines()
            .iter()
            .all(|line| !line.body.to_ascii_lowercase().contains("detach")));
    }

    #[test]
    fn pending_confirm_shift_y_remembers_allow() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(pending_network_confirm());

        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('Y'), KeyModifiers::SHIFT));

        assert!(update.handled);
        assert!(app.advisory().pending_confirm.is_none());
        assert!(app
            .engagement
            .confirm_allowlist()
            .contains("sandbox:run https://refund.acme/api"));
    }

    #[test]
    fn pending_confirm_shift_n_remembers_denial() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(pending_network_confirm());

        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('N'), KeyModifiers::SHIFT));

        assert!(update.handled);
        assert!(app.advisory().pending_confirm.is_none());
        assert!(app
            .engagement
            .confirm_denylist()
            .contains("sandbox:run https://refund.acme/api"));
    }

    #[test]
    fn pending_confirm_rejects_ctrl_modified_uppercase_choices() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(pending_network_confirm());

        let update = app.handle_confirm_key(KeyEvent::new(
            KeyCode::Char('Y'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ));

        assert!(!update.handled);
        assert!(app.advisory().pending_confirm.is_some());
        assert!(app.engagement.confirm_allowlist().is_empty());
        assert!(app.engagement.confirm_denylist().is_empty());
    }
}
