use super::*;
use crate::app::{
    api_key_model_choice_for_provider, auth_ready_for_provider, build_execution_plan,
    display_model_selector, oauth_model_choice_for_provider, toggle_planning_row,
    visible_model_choices, AuthMethodRowKind, ToggleOutcome,
};

impl ShellApp {
    /// The first-run model/auth/planning pickers are modal selection screens.
    pub(crate) fn is_picker_view(&self) -> bool {
        matches!(
            self.shell_view(),
            ShellView::PlanningPicker
                | ShellView::TargetPicker
                | ShellView::Setup
                | ShellView::FilePicker
        )
    }

    pub(super) fn handle_picker_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !self.picker_should_capture_key(key) {
            return InputUpdate::ignored();
        }
        self.handle_captured_picker_key(key)
    }

    fn handle_captured_picker_key(&mut self, key: KeyEvent) -> InputUpdate {
        if let Some(update) = self.handle_picker_capture_override(key) {
            return update;
        }
        self.handle_picker_control_or_swallow(key)
    }

    fn handle_picker_capture_override(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if matches!(self.shell_view(), ShellView::FilePicker) {
            return Some(self.handle_file_picker_key(key));
        }
        if self.picker_prompt_focused() {
            return Some(InputUpdate::handled_if(
                self.handle_picker_prompt_focus_key(key),
            ));
        }
        if self.enter_picker_prompt_if_requested(key) {
            return Some(InputUpdate::handled());
        }
        None
    }

    fn handle_picker_control_or_swallow(&mut self, key: KeyEvent) -> InputUpdate {
        let update = self.dispatch_picker_control_key(key);
        if update.handled {
            return update;
        }
        // Treat a picker as a true modal: swallow every other non-Ctrl/Alt
        // keystroke so stray input cannot divert later navigation into the
        // prompt and make the picker feel frozen.
        InputUpdate::handled()
    }

    fn enter_picker_prompt_if_requested(&mut self, key: KeyEvent) -> bool {
        if !self.should_enter_picker_prompt(key) {
            return false;
        }
        self.enter_picker_prompt_focus();
        true
    }

    fn picker_should_capture_key(&self, key: KeyEvent) -> bool {
        self.is_picker_view()
            && (!picker_shell_chord(key.modifiers) || self.credential_picker_owns_shell_chord(key))
    }

    fn credential_picker_owns_shell_chord(&self, key: KeyEvent) -> bool {
        self.credential_picker_list_focused() && !credential_picker_global_chord(key)
    }

    fn credential_picker_list_focused(&self) -> bool {
        self.shell_view() == ShellView::Setup
            && self.router.setup().editor() == Some(SetupEditor::Credentials)
            && !self.picker_prompt_focused()
    }

    fn dispatch_picker_control_key(&mut self, key: KeyEvent) -> InputUpdate {
        match &self.shell_view() {
            ShellView::Setup => self.handle_setup_key(key),
            ShellView::PlanningPicker => self.handle_planning_picker_key(key),
            ShellView::TargetPicker => self.handle_target_picker_key(key.code),
            ShellView::FilePicker => self.handle_file_picker_key(key),
            _ => InputUpdate::ignored(),
        }
    }

    pub(crate) fn picker_prompt_focused(&self) -> bool {
        self.is_picker_view() && self.current_picker_focus() == PickerFocus::Prompt
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
            && self.engagement.planning_picker().option_edit().is_none()
    }

    fn enter_picker_prompt_focus(&mut self) {
        self.set_current_picker_focus(PickerFocus::Prompt);
        self.engagement.planning_picker_mut().set_option_edit(None);
        self.engagement.planning_picker_mut().clear_option_error();
    }

    fn leave_picker_prompt_focus(&mut self) {
        self.reset_completion_cycle();
        self.editor_mut().stash_and_clear_input();
        self.set_current_picker_focus(PickerFocus::List);
    }

    fn current_picker_focus(&self) -> PickerFocus {
        match self.shell_view() {
            ShellView::Setup if self.router.setup().editor() == Some(SetupEditor::Model) => {
                self.router.model_picker().focus()
            }
            ShellView::Setup if self.router.setup().editor() == Some(SetupEditor::Credentials) => {
                self.router.auth_picker().focus()
            }
            ShellView::Setup if self.router.setup().editor() == Some(SetupEditor::Plan) => {
                self.engagement.planning_picker().focus()
            }
            ShellView::Setup => self.router.setup().focus(),
            ShellView::TargetPicker => self.router.target_picker().focus(),
            ShellView::PlanningPicker => self.engagement.planning_picker().focus(),
            _ => PickerFocus::List,
        }
    }

    fn set_current_picker_focus(&mut self, focus: PickerFocus) {
        match self.shell_view() {
            ShellView::Setup if self.router.setup().editor() == Some(SetupEditor::Model) => {
                self.router.model_picker_mut().set_focus(focus)
            }
            ShellView::Setup if self.router.setup().editor() == Some(SetupEditor::Credentials) => {
                self.router.auth_picker_mut().set_focus(focus)
            }
            ShellView::Setup if self.router.setup().editor() == Some(SetupEditor::Plan) => {
                self.engagement.planning_picker_mut().set_focus(focus)
            }
            ShellView::Setup => self.router.setup_mut().set_focus(focus),
            ShellView::TargetPicker => self.router.target_picker_mut().set_focus(focus),
            ShellView::PlanningPicker => self.engagement.planning_picker_mut().set_focus(focus),
            _ => {}
        }
    }

    fn handle_model_picker_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_model_picker_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_model_picker_cursor(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => InputUpdate::handled_with_effects(self.accept_model_picker_choice()),
            KeyCode::Esc | KeyCode::Char('q') => {
                self.defer_model_picker();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn handle_setup_key(&mut self, key: KeyEvent) -> InputUpdate {
        match self.router.setup().editor() {
            Some(SetupEditor::Model) => return self.handle_model_picker_key(key.code),
            Some(SetupEditor::Credentials) => return self.handle_auth_picker_key(key),
            Some(SetupEditor::Plan) => return self.handle_planning_picker_key(key),
            _ => {}
        }
        let code = key.code;
        if self.router.setup().editor() == Some(SetupEditor::Budget) {
            return self.handle_setup_budget_key(code);
        }
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.router.setup_mut().move_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.router.setup_mut().move_cursor(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => self.activate_setup_row(),
            KeyCode::Esc | KeyCode::Char('q') => {
                self.open_workbench();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn handle_setup_budget_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Enter => self.commit_setup_budget(),
            KeyCode::Esc => {
                self.router.setup_mut().finish_editor();
                InputUpdate::handled()
            }
            KeyCode::Backspace => {
                self.router.setup_mut().pop_budget_char();
                InputUpdate::handled()
            }
            KeyCode::Delete => {
                self.router.setup_mut().clear_budget_draft();
                InputUpdate::handled()
            }
            KeyCode::Char(ch) if ch.is_ascii_digit() || ch == '.' => {
                self.router.setup_mut().push_budget_char(ch);
                InputUpdate::handled()
            }
            _ => InputUpdate::handled(),
        }
    }

    fn commit_setup_budget(&mut self) -> InputUpdate {
        let draft = self.router.setup().budget_draft().trim().to_string();
        if draft.is_empty() {
            self.session_mut().set_session_budget_usd(None);
            self.router.setup_mut().finish_editor();
            self.log("setup", "session budget unset; spending is not capped");
            return InputUpdate::handled();
        }
        let Ok(value) = draft.parse::<f64>() else {
            self.router
                .setup_mut()
                .set_budget_error("enter a positive USD amount, or clear to leave unset");
            return InputUpdate::handled();
        };
        if !value.is_finite() || value <= 0.0 {
            self.router
                .setup_mut()
                .set_budget_error("budget must be a finite positive amount");
            return InputUpdate::handled();
        }
        if self
            .config()
            .operator
            .spend_hard_ceiling_usd
            .is_some_and(|ceiling| value > ceiling)
        {
            let ceiling = self.config().operator.spend_hard_ceiling_usd.unwrap_or(0.0);
            self.router
                .setup_mut()
                .set_budget_error(format!("budget exceeds the hard ceiling ${ceiling:.2}"));
            return InputUpdate::handled();
        }
        self.session_mut().set_session_budget_usd(Some(value));
        self.router.setup_mut().finish_editor();
        self.log("setup", format!("session budget set to ${value:.2}"));
        InputUpdate::handled()
    }

    fn activate_setup_row(&mut self) -> InputUpdate {
        match self.router.setup().row() {
            SetupRowId::Target => {
                self.router.setup_mut().begin_editor(SetupEditor::Target);
                self.open_target_picker();
                InputUpdate::handled()
            }
            SetupRowId::Plan => self.open_setup_plan_editor(),
            SetupRowId::Model => {
                self.router.setup_mut().begin_editor(SetupEditor::Model);
                self.open_model_picker();
                InputUpdate::handled()
            }
            SetupRowId::Credentials => self.open_setup_credentials_editor(),
            SetupRowId::Prompt => self.open_setup_prompt_editor(),
            SetupRowId::Budget => {
                let current = self.session().session_budget_usd();
                self.router.setup_mut().begin_budget_edit(current);
                InputUpdate::handled()
            }
            SetupRowId::Start => self.start_setup_map(),
        }
    }

    fn open_setup_plan_editor(&mut self) -> InputUpdate {
        self.router.setup_mut().begin_editor(SetupEditor::Plan);
        self.engagement
            .planning_picker_mut()
            .set_return_to_setup(true);
        InputUpdate::handled()
    }

    fn open_setup_credentials_editor(&mut self) -> InputUpdate {
        let provider = self
            .config()
            .model
            .as_deref()
            .and_then(|model| model.split(':').next())
            .map(str::to_string);
        let Some(provider) = provider else {
            self.router.setup_mut().begin_editor(SetupEditor::Model);
            self.open_model_picker();
            return InputUpdate::handled();
        };
        self.router
            .setup_mut()
            .begin_editor(SetupEditor::Credentials);
        self.open_credential_entry(provider);
        InputUpdate::handled()
    }

    fn open_setup_prompt_editor(&mut self) -> InputUpdate {
        let task = self
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .find(|row| {
                self.engagement
                    .planning_picker()
                    .selected()
                    .contains(&row.id)
                    && !self.prompt_specs_for_tool(row.tool_name).is_empty()
            })
            .map(|row| row.id);
        let Some(task) = task else {
            self.log("setup", "the selected Map plan has no editable prompt");
            return InputUpdate::handled();
        };
        self.engagement
            .planning_picker_mut()
            .set_cursor_to_task(task);
        self.router.setup_mut().begin_editor(SetupEditor::Prompt);
        InputUpdate::handled_with_effects(self.review_planning_prompt())
    }

    fn start_setup_map(&mut self) -> InputUpdate {
        let readiness = crate::ui_view_models::setup_readiness_model(self);
        if !readiness.can_start {
            if let Some(index) = readiness.first_blocker {
                self.router.setup_mut().set_cursor(index);
            }
            let blocker = readiness
                .first_blocker
                .and_then(|index| readiness.rows.get(index))
                .map(|row| row.detail.as_str())
                .unwrap_or("setup is incomplete");
            self.set_warn_notice("setup", format!("Start Map blocked — {blocker}"));
            return InputUpdate::handled();
        }
        self.engagement.set_phase(WorkflowPhase::Map);
        self.engagement
            .planning_picker_mut()
            .set_return_to_setup(false);
        self.accept_planning_picker()
    }

    fn reduce_picker_command(&mut self, command: ShellCommand) -> InputUpdate {
        let update = self.reduce_command_message(command);
        if update.handled {
            InputUpdate::handled_with_effects(update.effects)
        } else {
            InputUpdate::ignored()
        }
    }

    fn move_model_picker_cursor(&mut self, delta: isize) {
        let len = visible_model_choices(self.config().model.as_deref()).len();
        self.router.model_picker_mut().move_cursor(delta, len);
    }

    fn accept_model_picker_choice(&mut self) -> Vec<ShellEffect> {
        let choices = visible_model_choices(self.config().model.as_deref());
        let Some(choice) = choices.get(self.router.model_picker().cursor()).copied() else {
            self.log("error", "no model choices available");
            return Vec::new();
        };
        self.config_mut().model = Some(choice.id.to_string());
        self.set_session_thinking_level(Some(choice.thinking_level.to_string()));
        self.log(
            "model",
            format!(
                "{} selected via onboarding (saved as the global model)",
                display_model_selector(choice.id),
            ),
        );
        self.transition_after_model_choice(choice.provider);
        vec![crate::app::global_model_selection_persist_effect(
            choice.id,
            Some(choice.thinking_level),
        )]
    }

    fn transition_after_model_choice(&mut self, provider: &'static str) {
        if self.router.setup().editor() == Some(SetupEditor::Model) {
            self.return_to_setup_from_editor();
            return;
        }
        // A credentialed provider with no wired credentials opens the inline
        // credential-entry step (API key / OAuth / offline demo) instead of
        // stranding the operator on the Workbench. Session readiness also
        // recognizes a key accepted moments earlier, before its environment
        // effect is drained.
        if !self.provider_auth_ready_for(provider) {
            self.open_credential_entry(provider.to_string());
            return;
        }
        self.open_fresh_planner_or_workbench();
    }

    fn handle_target_picker_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_target_picker_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_target_picker_cursor(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => InputUpdate::handled_with_effects(self.accept_target_picker_choice()),
            KeyCode::Esc | KeyCode::Char('q') => {
                self.defer_target_picker();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn move_target_picker_cursor(&mut self, delta: isize) {
        self.router.target_picker_mut().move_cursor(delta);
        if let Some(path) = self
            .router
            .target_picker()
            .selected()
            .map(|candidate| candidate.path.clone())
        {
            self.runtime_state.start_target_candidate_facts(path);
        }
    }

    fn accept_target_picker_choice(&mut self) -> Vec<ShellEffect> {
        let Some(candidate) = self.router.target_picker().selected().cloned() else {
            self.log("error", "no target candidates available");
            return Vec::new();
        };
        self.request_target_activation(TargetActivation {
            path: candidate.path,
            selected_scope: candidate.scope,
            source: TargetActivationSource::Picker,
        })
    }

    fn defer_target_picker(&mut self) {
        // Dismissing the picker never touches an existing binding: from the
        // Setup editor it returns to Setup with the target intact, and from
        // an already-targeted session it returns to the workbench.
        if self.router.setup().editor() == Some(SetupEditor::Target) {
            self.return_to_setup_from_editor();
            return;
        }
        if self.target().is_some() {
            self.log("onboarding", "target unchanged");
            self.open_workbench();
            return;
        }
        self.log(
            "onboarding",
            "browsing without a target — set one later with `target <path>`, or run `demo` for the offline fixture",
        );
        self.clear_focused_module();
        self.router.catalog_mut().collapse();
        self.router.catalog_mut().jump_start();
        self.router.modules_mut().open();
        self.set_shell_view(ShellView::Catalog);
    }

    fn defer_model_picker(&mut self) {
        self.log(
            "onboarding",
            "model selection deferred — set one with /model <id>, or run `demo` for the offline fixture",
        );
        if self.router.setup().editor() == Some(SetupEditor::Model) {
            self.return_to_setup_from_editor();
        } else {
            self.open_workbench();
        }
    }

    fn handle_auth_picker_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.handle_auth_api_key_edit_key(key) {
            return InputUpdate::handled();
        }
        let Some(code) = auth_picker_control_code(key) else {
            return InputUpdate::ignored();
        };
        if code == KeyCode::Esc {
            self.return_to_model_picker();
            return InputUpdate::handled();
        }
        match code {
            KeyCode::Char('q') => {
                self.defer_auth_picker();
                InputUpdate::handled()
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_auth_picker_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_auth_picker_cursor(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => self.accept_auth_picker_choice(),
            _ => InputUpdate::ignored(),
        }
    }

    fn handle_auth_api_key_edit_key(&mut self, key: KeyEvent) -> bool {
        if !self.router.auth_picker().is_api_key_row() {
            return false;
        }
        if auth_key_word_delete_requested(key) {
            self.router.auth_picker_mut().delete_key_word_left();
            return true;
        }
        let Some(code) = auth_picker_control_code(key) else {
            return false;
        };
        self.handle_auth_api_key_draft_key(code)
    }

    fn handle_auth_api_key_draft_key(&mut self, code: KeyCode) -> bool {
        if !self.router.auth_picker().is_api_key_row() {
            return false;
        }
        match code {
            KeyCode::Char(ch) if !ch.is_control() && !ch.is_whitespace() => {
                self.router.auth_picker_mut().push_key_char(ch);
                self.clear_credential_notice();
                true
            }
            KeyCode::Backspace => {
                self.router.auth_picker_mut().pop_key_char();
                true
            }
            KeyCode::Delete => {
                self.router.auth_picker_mut().clear_key_draft();
                true
            }
            _ => false,
        }
    }

    fn move_auth_picker_cursor(&mut self, delta: isize) {
        self.router.auth_picker_mut().move_cursor(delta);
    }

    /// Dispatches on the row identity under the cursor, not a positional
    /// fallthrough — an empty (or otherwise kind-less) `rows` list must be a
    /// no-op rather than silently landing on OAuth.
    fn accept_auth_picker_choice(&mut self) -> InputUpdate {
        let provider = match self.shell_view() {
            ShellView::Setup if self.router.setup().editor() == Some(SetupEditor::Credentials) => {
                self.router.auth_picker().provider().to_string()
            }
            _ => return InputUpdate::ignored(),
        };
        match self.router.auth_picker().selected_kind() {
            Some(AuthMethodRowKind::OfflineDemo) => {
                self.router.auth_picker_mut().clear_key_draft();
                self.reduce_picker_command(ShellCommand::Demo)
            }
            Some(AuthMethodRowKind::ApiKey) => {
                InputUpdate::handled_with_effects(self.accept_auth_api_key_choice(&provider))
            }
            Some(AuthMethodRowKind::OAuth) => {
                InputUpdate::handled_with_effects(self.accept_auth_oauth_choice(&provider))
            }
            None => InputUpdate::ignored(),
        }
    }

    fn accept_auth_api_key_choice(&mut self, provider: &str) -> Vec<ShellEffect> {
        let api_key_provider = api_key_auth_provider(provider);
        if !self.router.auth_picker().key_draft_trimmed().is_empty() {
            return self.accept_pasted_auth_api_key(provider, api_key_provider);
        }
        if self.provider_auth_ready_for(api_key_provider) {
            let effects = self.select_api_key_model_for_provider(provider);
            self.set_success_notice(
                "onboarding",
                format!(
                    "{} already available; value hidden",
                    api_key_env_var(api_key_provider)
                ),
            );
            self.transition_after_auth_ready();
            return effects;
        }
        let env_var = api_key_env_var(api_key_provider);
        let message =
            format!("API key is empty — paste {env_var}, then press Enter; it stays session-only and hidden");
        self.set_warn_notice("onboarding", message);
        Vec::new()
    }

    fn accept_pasted_auth_api_key(
        &mut self,
        provider: &str,
        api_key_provider: &str,
    ) -> Vec<ShellEffect> {
        let env_var = api_key_env_var(api_key_provider);
        let key = self.router.auth_picker_mut().take_key_draft_trimmed();
        let mut effects = self.select_api_key_model_for_provider(provider);
        self.session_mut()
            .mark_session_api_key_ready(api_key_provider);
        self.set_success_notice(
            "onboarding",
            format!("{env_var} accepted for this session; value hidden"),
        );
        self.transition_after_auth_ready();
        effects.push(ShellEffect::SetSessionEnv(SessionEnvVar {
            key: env_var.to_string(),
            value: key,
        }));
        effects
    }

    fn accept_auth_oauth_choice(&mut self, provider: &str) -> Vec<ShellEffect> {
        let oauth_provider = oauth_credential_provider(provider);
        if auth_ready_for_provider(oauth_provider) {
            let effects = self.select_oauth_model_for_provider(provider);
            self.set_success_notice(
                "onboarding",
                format!(
                    "{} OAuth already stored; credentials hidden",
                    auth_provider_label(provider)
                ),
            );
            self.transition_after_auth_ready();
            return effects;
        }
        self.clear_credential_notice();
        self.log(
            "onboarding",
            format!(
                "dispatching OAuth login for {}; complete in the browser, then re-run /onboarding",
                auth_provider_label(provider)
            ),
        );
        self.reduce_picker_auth_login(provider)
    }

    pub(crate) fn clear_credential_notice(&mut self) {
        let belongs_to_credential_flow = self
            .advisory()
            .notice
            .as_ref()
            .is_some_and(|notice| matches!(notice.source.as_str(), "auth" | "onboarding"));
        if belongs_to_credential_flow {
            self.clear_notice();
        }
    }

    fn select_api_key_model_for_provider(&mut self, provider: &str) -> Vec<ShellEffect> {
        let Some(choice) = api_key_model_choice_for_provider(provider) else {
            return Vec::new();
        };
        self.select_auth_model_choice(choice, "API key")
    }

    pub(crate) fn select_oauth_model_for_provider(&mut self, provider: &str) -> Vec<ShellEffect> {
        let Some(choice) = oauth_model_choice_for_provider(provider) else {
            return Vec::new();
        };
        self.select_auth_model_choice(choice, "OAuth")
    }

    fn select_auth_model_choice(
        &mut self,
        choice: &ModelChoice,
        auth_method: &str,
    ) -> Vec<ShellEffect> {
        if self.config().model.as_deref() == Some(choice.id) {
            return Vec::new();
        }
        self.config_mut().model = Some(choice.id.to_string());
        self.set_session_thinking_level(Some(choice.thinking_level.to_string()));
        self.log(
            "model",
            format!(
                "{} selected for {auth_method} (no fallback model)",
                display_model_selector(choice.id)
            ),
        );
        vec![crate::app::global_model_selection_persist_effect(
            choice.id,
            Some(choice.thinking_level),
        )]
    }

    fn defer_auth_picker(&mut self) {
        self.router.auth_picker_mut().clear_key_draft();
        self.log(
            "onboarding",
            "auth deferred — set credentials and re-run /onboarding, or run `demo` for the offline fixture",
        );
        if self.router.setup().editor() == Some(SetupEditor::Credentials) {
            self.return_to_setup_from_editor();
        } else {
            self.open_workbench();
        }
    }

    fn return_to_model_picker(&mut self) {
        self.router.auth_picker_mut().clear_key_draft();
        if self.router.setup().editor() == Some(SetupEditor::Credentials) {
            self.return_to_setup_from_editor();
        } else {
            self.open_model_picker();
        }
    }

    pub(crate) fn transition_after_auth_ready(&mut self) {
        if self.router.setup().editor() == Some(SetupEditor::Credentials) {
            self.return_to_setup_from_editor();
        } else {
            self.open_fresh_planner_or_workbench();
        }
    }

    fn return_to_setup_from_editor(&mut self) {
        self.router.setup_mut().finish_editor();
        self.engagement.clear_phase();
        self.set_shell_view(ShellView::Setup);
    }

    fn handle_planning_picker_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.handle_planning_option_edit_key(key.code) {
            return InputUpdate::handled();
        }
        match self.engagement.planning_picker().focus() {
            PickerFocus::List => self.handle_planning_step_key(key.code),
            PickerFocus::OptionsPane => self.handle_planning_options_key(key.code),
            PickerFocus::Prompt => InputUpdate::ignored(),
        }
    }

    fn handle_planning_option_edit_key(&mut self, code: KeyCode) -> bool {
        if self.engagement.planning_picker().option_edit().is_none() {
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
                if let Some(edit) = self.engagement.planning_picker_mut().option_edit_mut() {
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

    fn handle_planning_step_key(&mut self, code: KeyCode) -> InputUpdate {
        if self.handle_planning_step_navigation_key(code)
            || self.handle_planning_step_selection_key(code)
        {
            return InputUpdate::handled();
        }
        self.handle_planning_step_action_key(code)
    }

    fn handle_planning_step_navigation_key(&mut self, code: KeyCode) -> bool {
        if self.engagement.planning_picker().returns_to_setup()
            && matches!(
                code,
                KeyCode::Left | KeyCode::Right | KeyCode::Char('h' | 'l' | '1' | '2' | '3' | '4')
            )
        {
            self.log(
                "setup",
                "Setup edits the Map plan only; Start Map before moving phases",
            );
            return true;
        }
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

    fn handle_planning_step_action_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Char('p') => InputUpdate::handled_with_effects(self.review_planning_prompt()),
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('o') => {
                self.enter_planning_options_pane();
                InputUpdate::handled()
            }
            KeyCode::Enter if self.engagement.planning_picker().returns_to_setup() => {
                self.return_to_setup_from_editor();
                InputUpdate::handled()
            }
            KeyCode::Enter => {
                if self.open_file_picker_for_current_planning_row() {
                    return InputUpdate::handled();
                }
                self.accept_planning_picker()
            }
            KeyCode::Char('s') if self.engagement.planning_picker().returns_to_setup() => {
                self.return_to_setup_from_editor();
                InputUpdate::handled()
            }
            KeyCode::Char('s') => InputUpdate::handled_with_effects(self.skip_planning_phase()),
            KeyCode::Esc | KeyCode::Char('q') => {
                self.close_planning_picker();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn handle_planning_options_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_planning_option_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_planning_option_cursor(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => {
                self.begin_planning_option_edit();
                InputUpdate::handled()
            }
            KeyCode::Char(' ') => {
                self.cycle_selected_planning_option();
                InputUpdate::handled()
            }
            KeyCode::Char(ch) if phase_for_digit(ch).is_some() => {
                if let Some(phase) = phase_for_digit(ch) {
                    self.open_phase_picker(phase);
                }
                InputUpdate::handled()
            }
            KeyCode::Char('S') => InputUpdate::handled_with_effects(
                self.reduce_persist_selected_planning_option_override(),
            ),
            KeyCode::Tab
            | KeyCode::BackTab
            | KeyCode::Char('o')
            | KeyCode::Esc
            | KeyCode::Char('q') => {
                self.leave_planning_options_pane();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    /// `g` on a cached Map artifact row toggles it between reuse (default) and
    /// rebuild. Rebuild marks the row to re-run even though its artifact exists.
    fn toggle_rebuild_current_row(&mut self) {
        let Some(row) = self.engagement.planning_picker().current_row().cloned() else {
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
        if self.engagement.planning_picker_mut().toggle_rebuild(id) {
            self.log("phase", format!("[rebuild] {}", id.label()));
        } else {
            self.log("phase", format!("[reuse] {} (cached)", id.label()));
        }
    }

    fn move_planning_cursor(&mut self, delta: isize) {
        if self.engagement.planning_picker().tasks().is_empty() {
            return;
        }
        self.engagement.planning_picker_mut().move_cursor(delta);
        self.clamp_planning_option_cursor();
    }

    fn move_planning_phase(&mut self, delta: isize) {
        let Some(current) = self.engagement.current_phase() else {
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
            .engagement
            .planning_picker()
            .current_row()
            .map(|row| row.id)
        else {
            return;
        };
        let tasks = self.engagement.planning_picker().tasks().to_vec();
        let outcome = toggle_planning_row(
            task,
            &tasks,
            self.engagement.planning_picker_mut().selected_mut(),
        );
        self.log_toggle_outcome(&outcome);
    }

    fn log_toggle_outcome(&mut self, outcome: &ToggleOutcome) {
        let message = toggle_outcome_message(outcome);
        if toggle_outcome_is_refusal(outcome) {
            self.set_warn_notice("planning", message.clone());
            return;
        }
        self.log("planning", message);
    }

    fn select_all_planning_rows(&mut self) {
        let rows = self.engagement.planning_picker().tasks().to_vec();
        let selected = self.engagement.planning_picker_mut().selected_mut();
        for row in &rows {
            if row.cli_available
                || matches!(
                    row.artifact_state,
                    crate::app::PlanningArtifactState::Cached
                )
            {
                selected.insert(row.id);
            }
        }
        self.log("planning", "selected all available rows");
    }

    fn clear_planning_selection(&mut self) {
        self.engagement.planning_picker_mut().selected_mut().clear();
        self.log("planning", "cleared selection");
    }

    pub(crate) fn accept_planning_picker(&mut self) -> InputUpdate {
        if self.engagement.planning_picker().returns_to_setup() {
            self.return_to_setup_from_editor();
            return InputUpdate::handled();
        }
        if self.open_file_picker_for_attach_only_plan() {
            return InputUpdate::handled();
        }
        self.drop_failed_dependency_selection();
        let plan = build_execution_plan(
            self.engagement.planning_picker().tasks(),
            self.engagement.planning_picker().selected(),
            self.engagement.planning_picker().rebuild(),
        );
        if plan.is_empty() {
            return InputUpdate::handled_with_effects(self.explain_empty_planning_confirm());
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
        self.engagement.queue_plan(plan);
        InputUpdate::handled_with_effects(vec![ShellEffect::DispatchNextPlanningTask(
            PlanningTaskDispatch {
                target: self.target_owned(),
                missing_workspace_message: "cannot run planning queue without an active workspace",
                // A committed phase run always shows live progress — even when
                // ad-hoc activity auto-open is disabled — so the operator can
                // see what's running (and that the queue is waiting on ranking,
                // if it stalls).
                success_view: Some(PlanningDispatchView::Activity),
            },
        )])
    }

    fn drop_failed_dependency_selection(&mut self) {
        if !self.engagement.has_failed_tasks() {
            return;
        }
        let failed = self.engagement.failed_task_ids();
        let blocked = self
            .engagement
            .planning_picker()
            .selected()
            .iter()
            .copied()
            .filter(|task| Self::failed_selection_blocks(*task, &failed))
            .collect::<Vec<_>>();
        if blocked.is_empty() {
            return;
        }
        for task in &blocked {
            self.engagement
                .planning_picker_mut()
                .selected_mut()
                .remove(task);
        }
        let labels = blocked
            .iter()
            .map(|task| task.tool_name())
            .collect::<Vec<_>>()
            .join(", ");
        self.log(
            "phase",
            format!("skipping blocked downstream task(s): {labels}"),
        );
    }

    fn failed_selection_blocks(
        task: PlanningTaskId,
        failed: &std::collections::BTreeSet<PlanningTaskId>,
    ) -> bool {
        failed.contains(&task)
            || transitive_dependencies(task)
                .into_iter()
                .any(|dependency| failed.contains(&dependency))
    }

    fn open_file_picker_for_current_planning_row(&mut self) -> bool {
        let Some(row) = self.engagement.planning_picker().current_row() else {
            return false;
        };
        if row.id != PlanningTaskId::AttachFiles {
            return false;
        }
        if !self
            .engagement
            .planning_picker()
            .selected()
            .contains(&PlanningTaskId::AttachFiles)
        {
            return false;
        }
        self.open_file_picker();
        true
    }

    fn open_file_picker_for_attach_only_plan(&mut self) -> bool {
        if self.engagement.planning_picker().selected().len() != 1
            || !self
                .engagement
                .planning_picker()
                .selected()
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
    fn explain_empty_planning_confirm(&mut self) -> Vec<ShellEffect> {
        if self.engagement.planning_picker().selected().is_empty() {
            let phase = self
                .engagement
                .current_phase()
                .map(|phase| phase.label())
                .unwrap_or("planning");
            self.log("phase", format!("nothing selected — skipping {phase}"));
            self.record_current_phase_skip();
            return self.advance_to_next_phase();
        }
        self.log(
            "phase",
            format!(
                "nothing to run — all {} checked {} are cached and will be reused; \
                 press g to rebuild one, or s to skip this phase",
                self.engagement.planning_picker().selected().len(),
                task_word(self.engagement.planning_picker().selected().len())
            ),
        );
        Vec::new()
    }

    fn skip_planning_phase(&mut self) -> Vec<ShellEffect> {
        let phase = self
            .engagement
            .current_phase()
            .map(|phase| phase.label())
            .unwrap_or("planning");
        self.log("phase", format!("skipped {phase}"));
        self.record_current_phase_skip();
        self.advance_to_next_phase()
    }

    fn close_planning_picker(&mut self) {
        if self.engagement.planning_picker().returns_to_setup() {
            self.return_to_setup_from_editor();
            return;
        }
        let phase = self
            .engagement
            .current_phase()
            .map(|phase| phase.label())
            .unwrap_or("planning");
        self.log("phase", format!("closed {phase} picker"));
        self.open_workbench();
    }
}

fn picker_shell_chord(modifiers: KeyModifiers) -> bool {
    modifiers.contains(KeyModifiers::CONTROL) || modifiers.contains(KeyModifiers::ALT)
}

fn credential_picker_global_chord(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(
            key.code,
            KeyCode::Char('c' | 'd' | 'g') | KeyCode::Up | KeyCode::Down
        )
}

fn auth_picker_control_code(key: KeyEvent) -> Option<KeyCode> {
    (!picker_shell_chord(key.modifiers)).then_some(key.code)
}

fn auth_key_word_delete_requested(key: KeyEvent) -> bool {
    let modified_backspace = key.code == KeyCode::Backspace
        && key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
    let control_w = key.code == KeyCode::Char('w') && key.modifiers.contains(KeyModifiers::CONTROL);
    modified_backspace || control_w
}

fn phase_for_digit(ch: char) -> Option<WorkflowPhase> {
    match ch {
        '1' => Some(WorkflowPhase::Map),
        '2' => Some(WorkflowPhase::Scan),
        '3' => Some(WorkflowPhase::Review),
        '4' => Some(WorkflowPhase::Prove),
        '5' => Some(WorkflowPhase::Fix),
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
    AuthProvider::from_scene_provider(provider)
        .map(AuthProvider::oauth_credential_key)
        .unwrap_or(provider)
}

fn api_key_auth_provider(provider: &str) -> &str {
    AuthProvider::from_scene_provider(provider)
        .map(AuthProvider::api_key_provider)
        .unwrap_or(provider)
}

fn toggle_outcome_message(outcome: &ToggleOutcome) -> String {
    match outcome {
        ToggleOutcome::On { task, auto_added } => toggle_on_message(*task, auto_added),
        ToggleOutcome::Off { task } => format!("[ ] {}", task.label()),
        ToggleOutcome::Blocked { task, dependents } => blocked_toggle_message(*task, dependents),
        ToggleOutcome::MissingCli { task, cli } => {
            format!(
                "{} needs `{cli}` on PATH — install it, then reopen this phase",
                task.label()
            )
        }
        ToggleOutcome::MissingPrereq { task, reason } => {
            format!("{} unavailable — {reason}", task.label())
        }
    }
}

fn toggle_outcome_is_refusal(outcome: &ToggleOutcome) -> bool {
    matches!(
        outcome,
        ToggleOutcome::Blocked { .. }
            | ToggleOutcome::MissingCli { .. }
            | ToggleOutcome::MissingPrereq { .. }
    )
}

fn toggle_on_message(task: PlanningTaskId, auto_added: &[PlanningTaskId]) -> String {
    if auto_added.is_empty() {
        return format!("[x] {}", task.label());
    }
    format!(
        "[x] {} — auto-selected {}",
        task.label(),
        planning_task_labels(auto_added)
    )
}

fn blocked_toggle_message(task: PlanningTaskId, dependents: &[PlanningTaskId]) -> String {
    format!(
        "cannot uncheck {} — still required by: {} (uncheck those first)",
        task.label(),
        planning_task_labels(dependents)
    )
}

fn planning_task_labels(tasks: &[PlanningTaskId]) -> String {
    tasks
        .iter()
        .map(|dep| dep.label())
        .collect::<Vec<_>>()
        .join(", ")
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

    fn plain_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn colon_opens_the_command_prompt_from_aggregate_setup() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::Setup);
        app.router.setup_mut().open();

        let update = app.reduce_key(plain_key(KeyCode::Char(':')));

        assert!(update.handled);
        assert!(app.picker_prompt_focused());
        assert!(app.input().is_empty());
    }

    #[test]
    fn advertised_colon_opens_prompt_without_editing_the_api_key() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_auth_method_picker("anthropic".to_string());

        let update = app.reduce_key(plain_key(KeyCode::Char(':')));

        assert!(update.handled);
        assert!(app.picker_prompt_focused());
        assert!(app.router.auth_picker().key_draft().is_empty());
        app.reduce_key(plain_key(KeyCode::Char('j')));
        assert_eq!(app.input(), "j");
        assert!(app.router.auth_picker().key_draft().is_empty());
    }

    #[test]
    fn selecting_openai_oauth_auth_method_selects_oauth_model() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.config_mut().model = Some("openai:gpt-5.5".to_string());

        app.select_oauth_model_for_provider("openai");

        assert_eq!(app.config().model.as_deref(), Some("openai-codex:gpt-5.4"));
        assert_eq!(app.session_thinking_level(), Some("xhigh"));
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "model"
                && line.body.contains("openai-oauth:gpt-5.4")
                && !line.body.contains("openai-codex")
        }));
    }

    #[test]
    fn selecting_openai_api_key_auth_method_selects_api_key_model() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.config_mut().model = Some("openai-codex:gpt-5.4".to_string());

        app.select_api_key_model_for_provider("openai-codex");

        assert_eq!(app.config().model.as_deref(), Some("openai:gpt-5.5"));
        assert_eq!(app.session_thinking_level(), Some("xhigh"));
    }

    #[test]
    fn accept_auth_picker_choice_with_no_rows_is_a_no_op() {
        // Selection is decided by `selected_kind()` identity, not by
        // "offline-demo? api-key? else OAuth" positional fallthrough — an
        // empty (or otherwise kind-less) row list must never fall through
        // to dispatching OAuth.
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_auth_method_picker("unsupported".to_string());
        assert_eq!(app.router.auth_picker().row_count(), 0);
        assert_eq!(app.router.auth_picker().selected_kind(), None);

        let update = app.accept_auth_picker_choice();

        assert!(
            update.effects.is_empty(),
            "no row selected — nothing to dispatch"
        );
        assert!(app
            .log_lines()
            .iter()
            .all(|line| !line.body.contains("dispatching OAuth login")));
    }

    #[test]
    fn blocked_planning_toggle_is_visible_as_a_warning_notice() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        let outcome = ToggleOutcome::Blocked {
            task: PlanningTaskId::GatherRepoContext,
            dependents: vec![PlanningTaskId::MapEntryPoints],
        };

        app.log_toggle_outcome(&outcome);

        let notice = app.advisory().notice.as_ref().expect("warning notice");
        assert_eq!(notice.severity, crate::NoticeSeverity::Warn);
        assert!(notice
            .message
            .contains("cannot uncheck Gather repo context"));
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body == notice.message));
    }

    #[test]
    fn missing_cli_planning_toggle_is_visible_as_a_warning_notice() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        let outcome = ToggleOutcome::MissingCli {
            task: PlanningTaskId::BuildCodeQlDatabase,
            cli: "codeql",
        };

        app.log_toggle_outcome(&outcome);

        let notice = app.advisory().notice.as_ref().expect("warning notice");
        assert_eq!(notice.severity, crate::NoticeSeverity::Warn);
        assert!(notice.message.contains("`codeql` on PATH"));
        assert!(notice.message.contains("reopen this phase"));
        assert_eq!(
            app.log_lines()
                .iter()
                .filter(|line| line.body == notice.message)
                .count(),
            1,
            "notice creation should keep exactly one transcript receipt"
        );
    }

    #[test]
    fn missing_prerequisite_planning_toggle_is_visible_as_a_warning_notice() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        let outcome = ToggleOutcome::MissingPrereq {
            task: PlanningTaskId::BuildCodeQlDatabase,
            reason: "source language could not be inferred".to_string(),
        };

        app.log_toggle_outcome(&outcome);

        let notice = app.advisory().notice.as_ref().expect("warning notice");
        assert_eq!(notice.severity, crate::NoticeSeverity::Warn);
        assert!(notice
            .message
            .contains("source language could not be inferred"));
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body == notice.message));
    }
}
