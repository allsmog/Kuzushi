use super::*;
use crate::app::{
    auth_ready_for_provider, build_execution_plan, provider_has_multiple_auth_methods,
    toggle_planning_row, visible_model_choices, ToggleOutcome,
};

impl ShellApp {
    pub(super) fn handle_picker_key(&mut self, key: KeyEvent) -> bool {
        if !self.input.is_empty() || !key.modifiers.is_empty() {
            return false;
        }
        match &self.shell_view {
            ShellView::ModelPicker => self.handle_model_picker_key(key.code),
            ShellView::AuthMethodPicker(_) => self.handle_auth_picker_key(key.code),
            ShellView::PlanningPicker => self.handle_planning_picker_key(key.code),
            _ => false,
        }
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
        self.log(
            "model",
            format!(
                "{} selected via onboarding (session only; persist with `model {}` after auth)",
                choice.id, choice.id,
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
                format!("{provider} credentials missing; continuing to catalog (run /auth login {provider} to fix)"),
            );
            self.shell_view = ShellView::Catalog;
            return;
        }
        if self.target.is_some() {
            self.open_planning_picker();
        } else {
            self.shell_view = ShellView::Catalog;
        }
    }

    fn defer_model_picker(&mut self) {
        self.log(
            "onboarding",
            "model selection deferred — set one with /model <id>",
        );
        self.shell_view = ShellView::Catalog;
    }

    fn handle_auth_picker_key(&mut self, code: KeyCode) -> bool {
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

    fn move_auth_picker_cursor(&mut self, delta: isize) {
        let len = 2usize; // API key + OAuth
        let current = (self.auth_picker_cursor.min(len - 1)) as isize;
        self.auth_picker_cursor = (current + delta).rem_euclid(len as isize) as usize;
    }

    fn accept_auth_picker_choice(&mut self) {
        let provider = match &self.shell_view {
            ShellView::AuthMethodPicker(provider) => provider.clone(),
            _ => return,
        };
        if self.auth_picker_cursor == 0 {
            self.accept_auth_api_key_choice(&provider);
        } else {
            self.accept_auth_oauth_choice(&provider);
        }
    }

    fn accept_auth_api_key_choice(&mut self, provider: &str) {
        if auth_ready_for_provider(provider) {
            self.log(
                "onboarding",
                format!("{provider} API key already set; continuing"),
            );
            self.transition_after_auth_ready();
            return;
        }
        let env_var = match provider {
            "anthropic" => "ANTHROPIC_API_KEY",
            _ => "OPENAI_API_KEY",
        };
        self.log(
            "onboarding",
            format!(
                "set {env_var} in your shell and relaunch kuzushi, or press Esc to defer onboarding"
            ),
        );
    }

    fn accept_auth_oauth_choice(&mut self, provider: &str) {
        self.log(
            "onboarding",
            format!(
                "dispatching OAuth login for {provider}; complete in the browser, then re-run /onboarding"
            ),
        );
        self.handle_auth_login_command(Some(provider.to_string()));
        if auth_ready_for_provider(provider) {
            self.transition_after_auth_ready();
        }
    }

    fn defer_auth_picker(&mut self) {
        self.log(
            "onboarding",
            "auth deferred — set credentials and re-run /onboarding when ready",
        );
        self.shell_view = ShellView::Catalog;
    }

    fn transition_after_auth_ready(&mut self) {
        if self.target.is_some() {
            self.open_planning_picker();
        } else {
            self.shell_view = ShellView::Catalog;
        }
    }

    fn handle_planning_picker_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_planning_cursor(-1);
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_planning_cursor(1);
                true
            }
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
            KeyCode::Char('g') | KeyCode::Char('G') => {
                self.toggle_rebuild_current_row();
                true
            }
            KeyCode::Enter => {
                self.accept_planning_picker();
                true
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.defer_planning_picker();
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
        if !matches!(row.artifact_state, crate::app::PlanningArtifactState::Cached) {
            self.log(
                "phase",
                format!("{} has no cached artifact to rebuild", id.label()),
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
            if row.cli_available {
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
        let plan = build_execution_plan(
            &self.planning_tasks,
            &self.planning_selected,
            &self.planning_rebuild,
        );
        if plan.is_empty() {
            self.log("phase", "nothing to run this phase — advancing");
            self.advance_to_next_phase();
            return;
        }
        let labels = plan
            .iter()
            .map(|task| task.tool_name())
            .collect::<Vec<_>>()
            .join(" → ");
        self.log(
            "planning",
            format!("running {} step(s): {labels}", plan.len()),
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

    fn defer_planning_picker(&mut self) {
        let phase = self
            .workflow_phase
            .map(|phase| phase.label())
            .unwrap_or("planning");
        self.log("phase", format!("skipped {phase}"));
        self.advance_to_next_phase();
    }
}
