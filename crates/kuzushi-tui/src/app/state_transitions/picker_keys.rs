use super::*;
use crate::app::{
    api_key_model_choice_for_provider, auth_ready_for_provider, build_execution_plan,
    display_model_selector, oauth_model_choice_for_provider, provider_has_multiple_auth_methods,
    toggle_planning_row, visible_model_choices, ToggleOutcome,
};

impl ShellApp {
    /// The first-run model/auth/planning pickers are modal selection screens.
    pub(crate) fn is_picker_view(&self) -> bool {
        matches!(
            self.shell_view,
            ShellView::ModelPicker
                | ShellView::AuthMethodPicker(_)
                | ShellView::PlanningPicker
                | ShellView::TargetPicker
                | ShellView::FilePicker
        )
    }

    pub(super) fn handle_picker_key(&mut self, key: KeyEvent) -> bool {
        if !self.picker_should_capture_key(key) {
            return false;
        }
        self.handle_captured_picker_key(key)
    }

    fn handle_captured_picker_key(&mut self, key: KeyEvent) -> bool {
        if matches!(self.shell_view, ShellView::FilePicker) {
            return self.handle_file_picker_key(key);
        }
        if self.picker_prompt_focused() {
            return self.handle_picker_prompt_focus_key(key);
        }
        if self.enter_picker_prompt_if_requested(key) {
            return true;
        }
        self.dispatch_picker_control_key(key);
        // Treat a picker as a true modal: swallow every other non-Ctrl/Alt
        // keystroke so stray input cannot divert later navigation into the
        // prompt and make the picker feel frozen.
        true
    }

    fn enter_picker_prompt_if_requested(&mut self, key: KeyEvent) -> bool {
        if !self.should_enter_picker_prompt(key) {
            return false;
        }
        self.enter_picker_prompt_focus();
        true
    }

    fn picker_should_capture_key(&self, key: KeyEvent) -> bool {
        self.is_picker_view() && !picker_shell_chord(key.modifiers)
    }

    fn dispatch_picker_control_key(&mut self, key: KeyEvent) {
        match &self.shell_view {
            ShellView::ModelPicker => {
                self.handle_model_picker_key(key.code);
            }
            ShellView::AuthMethodPicker(_) => {
                self.handle_auth_picker_key(key.code);
            }
            ShellView::PlanningPicker => {
                self.handle_planning_picker_key(key);
            }
            ShellView::TargetPicker => {
                self.handle_target_picker_key(key.code);
            }
            ShellView::FilePicker => {
                self.handle_file_picker_key(key);
            }
            _ => {}
        };
    }

    pub(crate) fn picker_prompt_focused(&self) -> bool {
        self.is_picker_view() && self.picker_focus == PickerFocus::Prompt
    }

    fn handle_picker_prompt_focus_key(&mut self, key: KeyEvent) -> bool {
        if !key.modifiers.is_empty() || key.code != KeyCode::Esc {
            return false;
        }
        self.leave_picker_prompt_focus();
        true
    }

    fn should_enter_picker_prompt(&self, key: KeyEvent) -> bool {
        key.modifiers.is_empty()
            && key.code == KeyCode::Char(':')
            && self.planning_option_edit.is_none()
    }

    fn enter_picker_prompt_focus(&mut self) {
        self.picker_focus = PickerFocus::Prompt;
        self.planning_option_edit = None;
        self.planning_option_error = None;
    }

    fn leave_picker_prompt_focus(&mut self) {
        self.reset_completion_cycle();
        if !self.input.is_empty() {
            self.last_cleared_input = Some(std::mem::take(&mut self.input));
            self.cursor = 0;
            self.history_index = None;
        }
        self.picker_focus = PickerFocus::List;
    }

    fn handle_model_picker_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_model_picker_cursor(-1);
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_model_picker_cursor(1);
                true
            }
            KeyCode::Enter => {
                self.accept_model_picker_choice();
                true
            }
            KeyCode::Char('d') => {
                self.start_offline_demo_fixture_scan();
                true
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.defer_model_picker();
                true
            }
            _ => false,
        }
    }

    fn move_model_picker_cursor(&mut self, delta: isize) {
        let len = visible_model_choices(self.config.model.as_deref()).len();
        if len == 0 {
            return;
        }
        let current = (self.model_picker_cursor.min(len - 1)) as isize;
        self.model_picker_cursor = (current + delta).rem_euclid(len as isize) as usize;
    }

    fn accept_model_picker_choice(&mut self) {
        let choices = visible_model_choices(self.config.model.as_deref());
        let Some(choice) = choices.get(self.model_picker_cursor).copied() else {
            self.log("error", "no model choices available");
            return;
        };
        self.config.model = Some(choice.id.to_string());
        self.session_thinking_level = Some(choice.thinking_level.to_string());
        self.persist_global_model_choice(choice.id, Some(choice.thinking_level));
        self.log(
            "model",
            format!(
                "{} selected via onboarding (saved as the global model)",
                display_model_selector(choice.id),
            ),
        );
        self.transition_after_model_choice(choice.provider);
    }

    fn transition_after_model_choice(&mut self, provider: &'static str) {
        if provider_has_multiple_auth_methods(provider) && !auth_ready_for_provider(provider) {
            self.open_auth_method_picker(provider.to_string());
            return;
        }
        if !auth_ready_for_provider(provider) {
            self.log(
                "onboarding",
                format!("{provider} credentials missing; continuing to Workbench (run /auth login {provider} to fix)"),
            );
            self.open_workbench(WorkbenchPane::Findings);
            return;
        }
        self.open_fresh_planner_or_workbench();
    }

    fn handle_target_picker_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_target_picker_cursor(-1);
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_target_picker_cursor(1);
                true
            }
            KeyCode::Enter => {
                self.accept_target_picker_choice();
                true
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.defer_target_picker();
                true
            }
            _ => false,
        }
    }

    fn move_target_picker_cursor(&mut self, delta: isize) {
        let len = self.target_candidates.len();
        if len == 0 {
            return;
        }
        let current = (self.target_picker_cursor.min(len - 1)) as isize;
        self.target_picker_cursor = (current + delta).rem_euclid(len as isize) as usize;
    }

    fn accept_target_picker_choice(&mut self) {
        let Some(candidate) = self.target_candidates.get(self.target_picker_cursor) else {
            self.log("error", "no target candidates available");
            return;
        };
        let path = candidate.path.display().to_string();
        let selected_scope = candidate.scope.clone();
        // Same wiring as the `target <path>` verb: workspace root, state
        // dir, findings, and program scope all refresh together.
        self.handle_target_command(Some(&path));
        if self.target.is_none() {
            // Invalid pick (already logged) — stay in the picker.
            return;
        }
        if let Some(scope) = selected_scope {
            self.active_scope = Some(scope.clone());
            self.log(
                "target",
                format!(
                    "entered {} scope {} ({})",
                    scope.kind.label(),
                    scope.rel_path,
                    scope.id
                ),
            );
        }
        // `target <path>` already continues the first-run chain; the picker
        // intentionally shares that route so typed and selected targets do
        // not diverge.
        if self.shell_view == ShellView::TargetPicker {
            self.open_workbench(WorkbenchPane::Findings);
        }
    }

    fn defer_target_picker(&mut self) {
        self.log(
            "onboarding",
            "browsing without a target — set one later with `target <path>`",
        );
        self.open_workbench(WorkbenchPane::Findings);
    }

    fn defer_model_picker(&mut self) {
        self.log(
            "onboarding",
            "model selection deferred — set one with /model <id>",
        );
        self.open_workbench(WorkbenchPane::Findings);
    }

    fn handle_auth_picker_key(&mut self, code: KeyCode) -> bool {
        if self.handle_auth_api_key_draft_key(code) {
            return true;
        }
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_auth_picker_cursor(-1);
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_auth_picker_cursor(1);
                true
            }
            KeyCode::Enter => {
                self.accept_auth_picker_choice();
                true
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.defer_auth_picker();
                true
            }
            _ => false,
        }
    }

    fn handle_auth_api_key_draft_key(&mut self, code: KeyCode) -> bool {
        if self.auth_picker_cursor != 0 {
            return false;
        }
        match code {
            KeyCode::Char(ch)
                if self.auth_key_draft.is_empty() && matches!(ch, 'j' | 'k' | 'q') =>
            {
                false
            }
            KeyCode::Char(ch) if !ch.is_control() && !ch.is_whitespace() => {
                self.auth_key_draft.push(ch);
                true
            }
            KeyCode::Backspace => {
                self.auth_key_draft.pop();
                true
            }
            KeyCode::Delete => {
                self.auth_key_draft.clear();
                true
            }
            _ => false,
        }
    }

    fn move_auth_picker_cursor(&mut self, delta: isize) {
        let len = 3usize; // API key + OAuth + offline demo
        let current = (self.auth_picker_cursor.min(len - 1)) as isize;
        self.auth_picker_cursor = (current + delta).rem_euclid(len as isize) as usize;
    }

    fn accept_auth_picker_choice(&mut self) {
        let provider = match &self.shell_view {
            ShellView::AuthMethodPicker(provider) => provider.clone(),
            _ => return,
        };
        if self.auth_picker_cursor == 2 {
            self.auth_key_draft.clear();
            self.start_offline_demo_fixture_scan();
            return;
        }
        if self.auth_picker_cursor == 0 {
            self.accept_auth_api_key_choice(&provider);
        } else {
            self.accept_auth_oauth_choice(&provider);
        }
    }

    fn accept_auth_api_key_choice(&mut self, provider: &str) {
        let api_key_provider = api_key_auth_provider(provider);
        if !self.auth_key_draft.trim().is_empty() {
            self.accept_pasted_auth_api_key(provider, api_key_provider);
            return;
        }
        if auth_ready_for_provider(api_key_provider) {
            self.select_api_key_model_for_provider(provider);
            self.log(
                "onboarding",
                format!("{api_key_provider} API key already set; continuing"),
            );
            self.transition_after_auth_ready();
            return;
        }
        let env_var = api_key_env_var(api_key_provider);
        self.log(
            "onboarding",
            format!("paste {env_var} here, then press Enter; value stays session-only and hidden"),
        );
    }

    fn accept_pasted_auth_api_key(&mut self, provider: &str, api_key_provider: &str) {
        let env_var = api_key_env_var(api_key_provider);
        let key = self.auth_key_draft.trim().to_string();
        self.auth_key_draft.clear();
        // In-session only: this removes the relaunch wall without writing a
        // secret to shell history, command history, config, or logs.
        unsafe {
            std::env::set_var(env_var, &key);
        }
        self.select_api_key_model_for_provider(provider);
        self.log(
            "onboarding",
            format!("{env_var} accepted for this session; value hidden"),
        );
        self.transition_after_auth_ready();
    }

    fn accept_auth_oauth_choice(&mut self, provider: &str) {
        let oauth_provider = oauth_credential_provider(provider);
        if auth_ready_for_provider(oauth_provider) {
            self.select_oauth_model_for_provider(provider);
            self.log(
                "onboarding",
                format!("{provider} OAuth already stored; continuing"),
            );
            self.transition_after_auth_ready();
            return;
        }
        self.log(
            "onboarding",
            format!(
                "dispatching OAuth login for {provider}; complete in the browser, then re-run /onboarding"
            ),
        );
        self.handle_auth_login_command(Some(provider.to_string()));
        // OAuth credentials land under the storage provider key
        // (openai → openai-codex), so check readiness there, not under the
        // picker's display provider, or a successful login would look unmet.
        if auth_ready_for_provider(oauth_provider) {
            self.select_oauth_model_for_provider(provider);
            self.transition_after_auth_ready();
        }
    }

    fn select_api_key_model_for_provider(&mut self, provider: &str) {
        let Some(choice) = api_key_model_choice_for_provider(provider) else {
            return;
        };
        self.select_auth_model_choice(choice, "API key");
    }

    fn select_oauth_model_for_provider(&mut self, provider: &str) {
        let Some(choice) = oauth_model_choice_for_provider(provider) else {
            return;
        };
        self.select_auth_model_choice(choice, "OAuth");
    }

    fn select_auth_model_choice(&mut self, choice: &ModelChoice, auth_method: &str) {
        if self.config.model.as_deref() == Some(choice.id) {
            return;
        }
        self.config.model = Some(choice.id.to_string());
        self.session_thinking_level = Some(choice.thinking_level.to_string());
        self.persist_global_model_choice(choice.id, Some(choice.thinking_level));
        self.log(
            "model",
            format!(
                "{} selected for {auth_method} (no fallback model)",
                display_model_selector(choice.id)
            ),
        );
    }

    fn defer_auth_picker(&mut self) {
        self.auth_key_draft.clear();
        self.log(
            "onboarding",
            "auth deferred — set credentials and re-run /onboarding when ready",
        );
        self.open_workbench(WorkbenchPane::Findings);
    }

    fn transition_after_auth_ready(&mut self) {
        self.open_fresh_planner_or_workbench();
    }

    fn handle_planning_picker_key(&mut self, key: KeyEvent) -> bool {
        if self.handle_planning_option_edit_key(key.code) {
            return true;
        }
        match self.picker_focus {
            PickerFocus::List => self.handle_planning_step_key(key.code),
            PickerFocus::OptionsPane => self.handle_planning_options_key(key.code),
            PickerFocus::Prompt => false,
        }
    }

    fn handle_planning_option_edit_key(&mut self, code: KeyCode) -> bool {
        if self.planning_option_edit.is_none() {
            return false;
        }
        match code {
            KeyCode::Enter => {
                self.commit_planning_option_edit();
                true
            }
            KeyCode::Esc => {
                self.cancel_planning_option_edit();
                true
            }
            KeyCode::Backspace => {
                self.backspace_planning_option_draft();
                true
            }
            KeyCode::Delete => {
                if let Some(edit) = self.planning_option_edit.as_mut() {
                    edit.draft.clear();
                }
                true
            }
            KeyCode::Char(ch) if !ch.is_control() => {
                self.edit_planning_option_draft(ch);
                true
            }
            _ => true,
        }
    }

    fn handle_planning_step_key(&mut self, code: KeyCode) -> bool {
        self.handle_planning_step_navigation_key(code)
            || self.handle_planning_step_selection_key(code)
            || self.handle_planning_step_action_key(code)
    }

    fn handle_planning_step_navigation_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_planning_cursor(-1);
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_planning_cursor(1);
                true
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.move_planning_phase(-1);
                true
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.move_planning_phase(1);
                true
            }
            KeyCode::Char(ch) if phase_for_digit(ch).is_some() => {
                if let Some(phase) = phase_for_digit(ch) {
                    self.open_phase_picker(phase);
                }
                true
            }
            _ => false,
        }
    }

    fn handle_planning_step_selection_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char(' ') => {
                self.toggle_planning_current_row();
                true
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                self.select_all_planning_rows();
                true
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                self.clear_planning_selection();
                true
            }
            KeyCode::Char('g') => {
                self.toggle_rebuild_current_row();
                true
            }
            _ => false,
        }
    }

    fn handle_planning_step_action_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('o') => {
                self.enter_planning_options_pane();
                true
            }
            KeyCode::Enter => {
                if self.open_file_picker_for_current_planning_row() {
                    return true;
                }
                self.accept_planning_picker();
                true
            }
            KeyCode::Char('s') => {
                self.skip_planning_phase();
                true
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.close_planning_picker();
                true
            }
            _ => false,
        }
    }

    fn handle_planning_options_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_planning_option_cursor(-1);
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_planning_option_cursor(1);
                true
            }
            KeyCode::Enter => {
                self.begin_planning_option_edit();
                true
            }
            KeyCode::Char(' ') => {
                self.cycle_selected_planning_option();
                true
            }
            KeyCode::Char(ch) if phase_for_digit(ch).is_some() => {
                if let Some(phase) = phase_for_digit(ch) {
                    self.open_phase_picker(phase);
                }
                true
            }
            KeyCode::Char('S') => {
                self.persist_selected_planning_option_override();
                true
            }
            KeyCode::Tab
            | KeyCode::BackTab
            | KeyCode::Char('o')
            | KeyCode::Esc
            | KeyCode::Char('q') => {
                self.leave_planning_options_pane();
                true
            }
            _ => false,
        }
    }

    /// `g` on a cached Map artifact row toggles it between reuse (default) and
    /// rebuild. Rebuild marks the row to re-run even though its artifact exists.
    fn toggle_rebuild_current_row(&mut self) {
        let Some(row) = self.planning_tasks.get(self.planning_cursor) else {
            return;
        };
        let id = row.id;
        if !matches!(
            row.artifact_state,
            crate::app::PlanningArtifactState::Cached
        ) {
            self.log(
                "phase",
                format!("{} has no cached artifact to rebuild", id.label()),
            );
            return;
        }
        if !row.cli_available {
            self.log(
                "phase",
                format!(
                    "{} is cached; rebuild requires `{}` on PATH",
                    id.label(),
                    row.required_cli.unwrap_or("required binary")
                ),
            );
            return;
        }
        if self.planning_rebuild.remove(&id) {
            self.planning_selected.remove(&id);
            self.log("phase", format!("[reuse] {} (cached)", id.label()));
        } else {
            self.planning_rebuild.insert(id);
            self.planning_selected.insert(id);
            self.log("phase", format!("[rebuild] {}", id.label()));
        }
    }

    fn move_planning_cursor(&mut self, delta: isize) {
        let len = self.planning_tasks.len();
        if len == 0 {
            return;
        }
        let current = (self.planning_cursor.min(len - 1)) as isize;
        self.planning_cursor = (current + delta).rem_euclid(len as isize) as usize;
        self.clamp_planning_option_cursor();
        self.planning_option_error = None;
    }

    fn move_planning_phase(&mut self, delta: isize) {
        let Some(current) = self.workflow_phase else {
            return;
        };
        let next = if delta < 0 {
            current.previous()
        } else {
            current.next()
        };
        let Some(next) = next else {
            self.log("phase", format!("already at {}", current.label()));
            return;
        };
        self.open_phase_picker(next);
    }

    fn toggle_planning_current_row(&mut self) {
        let Some(task) = self
            .planning_tasks
            .get(self.planning_cursor)
            .map(|row| row.id)
        else {
            return;
        };
        let outcome = toggle_planning_row(task, &self.planning_tasks, &mut self.planning_selected);
        self.log_toggle_outcome(&outcome);
    }

    fn log_toggle_outcome(&mut self, outcome: &ToggleOutcome) {
        match outcome {
            ToggleOutcome::On { task, auto_added } => {
                if auto_added.is_empty() {
                    self.log("planning", format!("[x] {}", task.label()));
                } else {
                    let deps = auto_added
                        .iter()
                        .map(|dep| dep.label())
                        .collect::<Vec<_>>()
                        .join(", ");
                    self.log(
                        "planning",
                        format!("[x] {} — auto-selected {}", task.label(), deps),
                    );
                }
            }
            ToggleOutcome::Off { task } => {
                self.log("planning", format!("[ ] {}", task.label()));
            }
            ToggleOutcome::Blocked { task, dependents } => {
                let deps = dependents
                    .iter()
                    .map(|dep| dep.label())
                    .collect::<Vec<_>>()
                    .join(", ");
                self.log(
                    "planning",
                    format!(
                        "cannot uncheck {} — still required by: {} (uncheck those first)",
                        task.label(),
                        deps
                    ),
                );
            }
            ToggleOutcome::MissingCli { task, cli } => {
                self.log(
                    "planning",
                    format!(
                        "{} needs `{cli}` on PATH — install it or set KUZUSHI_*_BIN",
                        task.label()
                    ),
                );
            }
        }
    }

    fn select_all_planning_rows(&mut self) {
        for row in &self.planning_tasks {
            if row.cli_available
                || matches!(
                    row.artifact_state,
                    crate::app::PlanningArtifactState::Cached
                )
            {
                self.planning_selected.insert(row.id);
            }
        }
        self.log("planning", "selected all available rows");
    }

    fn clear_planning_selection(&mut self) {
        self.planning_selected.clear();
        self.log("planning", "cleared selection");
    }

    fn accept_planning_picker(&mut self) {
        if self.open_file_picker_for_attach_only_plan() {
            return;
        }
        let plan = build_execution_plan(
            &self.planning_tasks,
            &self.planning_selected,
            &self.planning_rebuild,
        );
        if plan.is_empty() {
            self.explain_empty_planning_confirm();
            return;
        }
        let labels = plan
            .iter()
            .map(|task| task.tool_name())
            .collect::<Vec<_>>()
            .join(" → ");
        self.log(
            "planning",
            format!("running {} {}: {labels}", plan.len(), step_word(plan.len())),
        );
        self.planning_run_queue = plan.into_iter().collect();
        let Ok(workspace) = self.current_workspace() else {
            self.log(
                "error",
                "cannot run planning queue without an active workspace",
            );
            self.planning_run_queue.clear();
            return;
        };
        // A committed phase run always shows live progress — even when ad-hoc
        // activity auto-open is disabled — so the operator can see what's
        // running (and that the queue is waiting on ranking, if it stalls).
        self.shell_view = ShellView::Activity;
        self.dispatch_next_planning_task(workspace);
    }

    fn open_file_picker_for_current_planning_row(&mut self) -> bool {
        let Some(row) = self.planning_tasks.get(self.planning_cursor) else {
            return false;
        };
        if row.id != PlanningTaskId::AttachFiles {
            return false;
        }
        self.open_file_picker();
        true
    }

    fn open_file_picker_for_attach_only_plan(&mut self) -> bool {
        if self.planning_selected.len() != 1
            || !self
                .planning_selected
                .contains(&PlanningTaskId::AttachFiles)
        {
            return false;
        }
        self.open_file_picker();
        true
    }

    /// Enter built an empty plan. Checked-but-cached rows are reused without
    /// running, so confirming an all-cached selection used to silently advance
    /// the phase — say what happened instead, and only advance when the
    /// operator selected nothing at all (an explicit "skip this phase").
    fn explain_empty_planning_confirm(&mut self) {
        if self.planning_selected.is_empty() {
            let phase = self
                .workflow_phase
                .map(|phase| phase.label())
                .unwrap_or("planning");
            self.log("phase", format!("nothing selected — skipping {phase}"));
            if let Some(phase) = self.workflow_phase {
                self.planning_skipped_phases.insert(phase);
            }
            self.advance_to_next_phase();
            return;
        }
        self.log(
            "phase",
            format!(
                "nothing to run — all {} checked {} are cached and will be reused; \
                 press g to rebuild one, or s to skip this phase",
                self.planning_selected.len(),
                task_word(self.planning_selected.len())
            ),
        );
    }

    fn skip_planning_phase(&mut self) {
        let phase = self
            .workflow_phase
            .map(|phase| phase.label())
            .unwrap_or("planning");
        self.log("phase", format!("skipped {phase}"));
        if let Some(phase) = self.workflow_phase {
            self.planning_skipped_phases.insert(phase);
        }
        self.advance_to_next_phase();
    }

    fn close_planning_picker(&mut self) {
        let phase = self
            .workflow_phase
            .map(|phase| phase.label())
            .unwrap_or("planning");
        self.log("phase", format!("closed {phase} picker"));
        self.open_workbench(WorkbenchPane::Findings);
    }
}

fn picker_shell_chord(modifiers: KeyModifiers) -> bool {
    modifiers.contains(KeyModifiers::CONTROL) || modifiers.contains(KeyModifiers::ALT)
}

fn phase_for_digit(ch: char) -> Option<WorkflowPhase> {
    match ch {
        '1' => Some(WorkflowPhase::Map),
        '2' => Some(WorkflowPhase::Hunt),
        '3' => Some(WorkflowPhase::Confirm),
        '4' => Some(WorkflowPhase::Fix),
        _ => None,
    }
}

fn step_word(count: usize) -> &'static str {
    if count == 1 {
        "step"
    } else {
        "steps"
    }
}

fn task_word(count: usize) -> &'static str {
    if count == 1 {
        "task"
    } else {
        "tasks"
    }
}

/// Maps a picker's display provider to the key its OAuth credentials are
/// stored under in `oauth-credentials.json` (`openai` shares the
/// `openai-codex` ChatGPT credential).
fn oauth_credential_provider(provider: &str) -> &str {
    match provider {
        "openai" | "openai-codex" => "openai-codex",
        other => other,
    }
}

fn api_key_auth_provider(provider: &str) -> &str {
    match provider {
        "openai-codex" => "openai",
        other => other,
    }
}

fn api_key_env_var(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "ANTHROPIC_API_KEY",
        _ => "OPENAI_API_KEY",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selecting_openai_oauth_auth_method_selects_oauth_model() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.config.model = Some("openai:gpt-5.5".to_string());

        app.select_oauth_model_for_provider("openai");

        assert_eq!(app.config.model.as_deref(), Some("openai-codex:gpt-5.4"));
        assert_eq!(app.session_thinking_level.as_deref(), Some("xhigh"));
        assert!(app.log.iter().any(|line| {
            line.prefix == "model"
                && line.body.contains("openai-oauth:gpt-5.4")
                && !line.body.contains("openai-codex")
        }));
    }

    #[test]
    fn selecting_openai_api_key_auth_method_selects_api_key_model() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.config.model = Some("openai-codex:gpt-5.4".to_string());

        app.select_api_key_model_for_provider("openai-codex");

        assert_eq!(app.config.model.as_deref(), Some("openai:gpt-5.5"));
        assert_eq!(app.session_thinking_level.as_deref(), Some("xhigh"));
    }
}
