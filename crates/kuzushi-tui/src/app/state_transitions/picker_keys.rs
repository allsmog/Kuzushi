use super::*;
use crate::app::{
    auth_ready_for_provider, build_execution_plan, cycle_planning_row, display_model_selector,
    visible_model_choices, AuthMethodRowKind, ToggleOutcome,
};
use std::path::PathBuf;

struct PlanningCredentialContext {
    target: PathBuf,
    phase: WorkflowPhase,
    model: String,
    provider: String,
    guidance: String,
}

enum PlanningCredentialGate {
    Ready,
    Blocked,
    Recover(PlanningCredentialContext),
}

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
        self.handle_non_file_picker_capture_override(key)
    }

    fn handle_non_file_picker_capture_override(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.picker_prompt_focused() {
            return Some(InputUpdate::handled_if(
                self.handle_picker_prompt_focus_key(key),
            ));
        }
        if self.inline_picker_editor_owns_key() {
            let update = self.dispatch_picker_control_key(key);
            return Some(if update.handled {
                update
            } else {
                InputUpdate::handled()
            });
        }
        self.enter_picker_command_input(key)
    }

    fn enter_picker_command_input(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.enter_picker_prompt_if_requested(key) {
            return Some(InputUpdate::handled());
        }
        if self.enter_picker_prompt_with_printable(key) {
            return Some(InputUpdate::handled());
        }
        None
    }

    fn handle_picker_control_or_swallow(&mut self, key: KeyEvent) -> InputUpdate {
        let update = self.dispatch_picker_control_key(key);
        if update.handled {
            return update;
        }
        // Non-printable keys without a picker action remain owned by the modal.
        InputUpdate::handled()
    }

    fn inline_picker_editor_owns_key(&self) -> bool {
        let editor = self.router.setup().editor();
        let planning_option = self.engagement.planning_picker().option_edit().is_some();
        matches!(
            editor,
            Some(SetupEditor::Budget | SetupEditor::ThreatModel | SetupEditor::Details)
        ) || planning_option
            || (editor == Some(SetupEditor::Credentials)
                && self.router.auth_picker().is_api_key_row())
    }

    pub(crate) fn picker_surface_accepts_composer_input(&self) -> bool {
        self.is_picker_view()
            && !matches!(self.shell_view(), ShellView::FilePicker)
            && self.current_picker_focus() != PickerFocus::Prompt
            && !self.inline_picker_editor_owns_key()
    }

    fn enter_picker_prompt_with_printable(&mut self, key: KeyEvent) -> bool {
        let Some(ch) = picker_command_char(key) else {
            return false;
        };
        if !self.picker_surface_accepts_composer_input() {
            return false;
        }
        self.enter_picker_prompt_focus();
        self.insert_printable_key(ch);
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
        self.is_picker_view()
            && (!picker_shell_chord(key.modifiers)
                || self.credential_picker_owns_shell_chord(key)
                || self.planning_picker_owns_shell_chord(key)
                || self.planning_option_editor_owns_key(key)
                || self.budget_editor_owns_key(key)
                || self.map_text_editor_owns_key(key)
                || self.file_picker_owns_edit_key(key))
    }

    fn file_picker_owns_edit_key(&self, key: KeyEvent) -> bool {
        self.shell_view() == ShellView::FilePicker
            && !(key.modifiers == KeyModifiers::CONTROL
                && matches!(key.code, KeyCode::Char('c' | 'd')))
    }

    fn planning_picker_owns_shell_chord(&self, key: KeyEvent) -> bool {
        matches!(
            self.shell_view(),
            ShellView::PlanningPicker | ShellView::Setup
        ) && self.current_picker_focus() == PickerFocus::OptionsPane
            && key.modifiers == KeyModifiers::CONTROL
            && key.code == KeyCode::Char('s')
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

    pub(super) fn enter_picker_prompt_focus(&mut self) {
        self.set_current_picker_focus(PickerFocus::Prompt);
        self.set_input_mode(InputMode::Prompt);
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
            KeyCode::Up => {
                self.move_model_picker_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down => {
                self.move_model_picker_cursor(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => InputUpdate::handled_with_effects(self.accept_model_picker_choice()),
            KeyCode::Esc => {
                self.defer_model_picker();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn handle_setup_key(&mut self, key: KeyEvent) -> InputUpdate {
        match self.router.setup().editor() {
            Some(SetupEditor::Details) => return self.handle_setup_details_key(key),
            Some(SetupEditor::Model) => return self.handle_model_picker_key(key.code),
            Some(SetupEditor::Credentials) => return self.handle_auth_picker_key(key),
            Some(SetupEditor::Plan) => return self.handle_planning_picker_key(key),
            Some(SetupEditor::ThreatModel) => return self.handle_map_run_config_key(key),
            _ => {}
        }
        let code = key.code;
        if self.router.setup().editor() == Some(SetupEditor::Budget) {
            return self.handle_setup_budget_key(key);
        }
        match code {
            KeyCode::Tab => {
                self.router.setup_mut().begin_editor(SetupEditor::Details);
                InputUpdate::handled()
            }
            KeyCode::Up => {
                self.router.setup_mut().move_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down => {
                self.router.setup_mut().move_cursor(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => self.activate_setup_row(),
            KeyCode::Esc => {
                self.open_workbench();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn handle_map_run_config_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.map_scope_picker_open() {
            return self.handle_map_scope_key(key);
        }
        if self.router.setup().map_run_config().text().is_some() {
            return self.handle_map_text_key(key);
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.router.setup_mut().map_run_config_mut().move_cursor(-1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.router.setup_mut().map_run_config_mut().move_cursor(1)
            }
            KeyCode::Enter | KeyCode::Char(' ') => return self.activate_map_run_config_row(),
            KeyCode::Esc => self.router.setup_mut().finish_editor(),
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    fn activate_map_run_config_row(&mut self) -> InputUpdate {
        let row = self.router.setup().map_run_config().row();
        let result = match row {
            crate::app::MapRunConfigRowId::Methodology => self.cycle_map_methodology(),
            crate::app::MapRunConfigRowId::Scope => self.open_map_scope_picker(),
            crate::app::MapRunConfigRowId::DesignDocs | crate::app::MapRunConfigRowId::Context => {
                self.begin_map_text_edit(row);
                return InputUpdate::handled();
            }
        };
        self.set_map_run_config_result(result);
        InputUpdate::handled()
    }

    pub(super) fn commit_map_run_text_input(&mut self) -> InputUpdate {
        let result = self.commit_map_text_edit();
        self.set_map_run_config_result(result);
        InputUpdate::handled()
    }

    pub(super) fn set_map_run_config_result(&mut self, result: anyhow::Result<()>) {
        match result {
            Ok(()) => self.router.setup_mut().map_run_config_mut().clear_error(),
            Err(error) => self
                .router
                .setup_mut()
                .map_run_config_mut()
                .set_error(format!("{error:#}")),
        }
    }

    fn activate_setup_row(&mut self) -> InputUpdate {
        match self.router.setup().row() {
            SetupRowId::Target => {
                self.router.setup_mut().begin_editor(SetupEditor::Target);
                self.open_target_picker();
                InputUpdate::handled()
            }
            SetupRowId::Plan => self.open_setup_plan_editor(),
            SetupRowId::ThreatModel if self.context_import_selected() => {
                self.open_setup_import_options()
            }
            SetupRowId::ThreatModel => match self.open_map_run_config() {
                Ok(()) => InputUpdate::handled(),
                Err(error) => {
                    self.set_warn_notice(
                        "setup",
                        format!("Map configuration unavailable: {error:#}"),
                    );
                    InputUpdate::handled()
                }
            },
            SetupRowId::Model => {
                self.router.setup_mut().begin_editor(SetupEditor::Model);
                self.open_model_picker();
                InputUpdate::handled()
            }
            SetupRowId::Credentials => self.open_setup_credentials_editor(),
            SetupRowId::Prompt => self.open_setup_prompt_editor(),
            SetupRowId::Budget => {
                if let Some(update) = self.review_setup_allowance() {
                    return update;
                }
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
            self.set_warn_notice("setup", format!("Start Map blocked: {blocker}"));
            return InputUpdate::handled();
        }
        self.router.setup_mut().clear_launch_failure();
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
        let choices = visible_model_choices(self.config());
        let ids = choices.iter().map(|choice| choice.id).collect::<Vec<_>>();
        self.router.model_picker_mut().move_selection(delta, &ids);
    }

    fn accept_model_picker_choice(&mut self) -> Vec<ShellEffect> {
        let choice = self
            .router
            .model_picker()
            .selected_id()
            .and_then(crate::app::model_choice_index_by_id)
            .and_then(|index| crate::app::model_choices().get(index))
            .filter(|choice| choice.catalog_note.is_none());
        let Some(choice) = choice else {
            self.log(
                "error",
                "selected model is not offered; reopen /model and choose a current model",
            );
            return Vec::new();
        };
        self.config_mut().model = Some(choice.id.to_string());
        self.set_session_thinking_level(Some(choice.thinking_level.to_string()));
        self.log(
            "model",
            format!(
                "{} selected; saving as the global model",
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
        if self.restore_model_picker_config_origin() {
            return;
        }
        if self.router.setup().editor() == Some(SetupEditor::Model) {
            self.return_to_setup_from_editor();
            return;
        }
        // A credentialed provider with no wired credentials opens the inline
        // credential-entry step with compatible auth methods instead of
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
            KeyCode::Up => {
                self.move_target_picker_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down => {
                self.move_target_picker_cursor(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => InputUpdate::handled_with_effects(self.accept_target_picker_choice()),
            KeyCode::Esc => {
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
        self.router.target_picker_mut().clear_pending_intent();
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
        self.log("onboarding", "model selection unchanged");
        if self.restore_model_picker_config_origin() {
            return;
        }
        if self.router.setup().editor() == Some(SetupEditor::Model) {
            self.return_to_setup_from_editor();
        } else {
            self.open_workbench();
        }
    }

    pub(super) fn close_model_picker_if_open(&mut self) -> bool {
        if self.shell_view() != ShellView::Setup
            || self.router.setup().editor() != Some(SetupEditor::Model)
        {
            return false;
        }
        self.defer_model_picker();
        true
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
            KeyCode::Up => {
                self.move_auth_picker_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down => {
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
            return self.accept_pasted_auth_api_key(api_key_provider);
        }
        if self.api_key_ready_for_picker(api_key_provider)
            && !self.pending_api_key_replacement_required()
        {
            self.engagement.satisfy_pending_credential_requirement();
            self.set_success_notice(
                "onboarding",
                format!(
                    "{} already available; value hidden",
                    api_key_env_var(api_key_provider)
                ),
            );
            return self.transition_after_auth_ready();
        }
        let env_var = api_key_env_var(api_key_provider);
        let message = if self.pending_api_key_replacement_required() {
            format!(
                "The previous {env_var} was rejected · paste a replacement, then press Enter; it stays session-only and hidden"
            )
        } else {
            format!(
                "API key is empty · paste {env_var}, then press Enter; it stays session-only and hidden"
            )
        };
        self.set_warn_notice("onboarding", message);
        Vec::new()
    }

    fn accept_pasted_auth_api_key(&mut self, api_key_provider: &str) -> Vec<ShellEffect> {
        let env_var = api_key_env_var(api_key_provider);
        let key = self.router.auth_picker_mut().take_key_draft_trimmed();
        self.session_mut()
            .mark_session_api_key_ready(api_key_provider);
        self.engagement.satisfy_pending_credential_requirement();
        self.set_success_notice(
            "onboarding",
            format!("{env_var} accepted for this session; value hidden"),
        );
        let mut effects = vec![ShellEffect::SetSessionEnv(SessionEnvVar {
            key: env_var.to_string(),
            value: key,
        })];
        effects.extend(self.transition_after_auth_ready());
        effects
    }

    /// An OAuth choice that would change the model waits for explicit consent.
    fn accept_auth_oauth_choice(&mut self, provider: &str) -> Vec<ShellEffect> {
        let reuse = self.oauth_choice_reuses_stored_credential(provider);
        if let Some(selection) = oauth_model_switch_for_provider(provider) {
            self.request_oauth_model_switch_consent(provider, &selection, reuse);
            return Vec::new();
        }
        self.continue_oauth_choice(provider, reuse)
    }

    fn oauth_choice_reuses_stored_credential(&self, provider: &str) -> bool {
        !self.pending_oauth_reconnect_required()
            && oauth_credential_is_ready(self.config(), oauth_credential_provider(provider))
    }

    /// Reuse the stored OAuth connection, or start its login; either way the
    /// provider's model switch (if any) has already been consented to.
    pub(crate) fn continue_oauth_choice(
        &mut self,
        provider: &str,
        reuse: bool,
    ) -> Vec<ShellEffect> {
        if reuse {
            return self
                .reuse_auth_oauth_choice(provider, oauth_model_switch_for_provider(provider));
        }
        self.clear_credential_notice();
        self.log(
            "onboarding",
            format!(
                "dispatching OAuth login for {}; complete it in the browser and Kuzushi will resume automatically",
                auth_provider_label(provider)
            ),
        );
        self.reduce_picker_auth_login(provider)
    }

    fn reuse_auth_oauth_choice(
        &mut self,
        provider: &str,
        model_switch: Option<AuthModelSwitch>,
    ) -> Vec<ShellEffect> {
        let destination = model_switch
            .as_ref()
            .map(|selection| {
                format!(
                    "; switching to {}",
                    display_model_selector(&selection.model)
                )
            })
            .unwrap_or_default();
        self.set_success_notice(
            "onboarding",
            format!(
                "{} OAuth connection reused{destination}; credentials hidden",
                auth_provider_label(provider),
            ),
        );
        let Some(mut model_effects) = self.apply_auth_model_switch(model_switch) else {
            return Vec::new();
        };
        let mut effects = self.select_oauth_transport_effects(provider);
        effects.append(&mut model_effects);
        self.engagement.satisfy_pending_credential_requirement();
        effects.extend(self.transition_after_auth_ready());
        effects
    }

    fn api_key_ready_for_picker(&self, provider: &str) -> bool {
        self.session().session_api_key_ready(provider)
            || env_credential_is_ready(api_key_env_var(provider))
    }

    pub(crate) fn select_oauth_transport_effects(&mut self, provider: &str) -> Vec<ShellEffect> {
        if provider != "anthropic" || !self.api_key_ready_for_picker(provider) {
            return Vec::new();
        }
        self.session_mut().clear_session_api_key_ready(provider);
        self.log(
            "auth",
            "Anthropic OAuth selected explicitly; ignoring ANTHROPIC_API_KEY for this session",
        );
        vec![ShellEffect::SetSessionEnv(SessionEnvVar {
            key: api_key_env_var(provider).to_string(),
            value: String::new(),
        })]
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

    fn return_to_model_picker(&mut self) {
        self.router.auth_picker_mut().clear_key_draft();
        if let Some(pending) = self.engagement.take_pending_credential_continuation() {
            self.router.setup_mut().finish_editor();
            self.engagement.set_phase(pending.phase);
            if let PendingCredentialWork::DeferredStep(step) = pending.work {
                self.engagement.push_expanded_step_front(step);
                self.engagement.pause_planning_queue();
            }
            self.set_shell_view(ShellView::PlanningPicker);
            self.set_warn_notice(
                "planning",
                "Scan not started · credentials are still missing; selection kept.",
            );
            return;
        }
        if self.router.setup().editor() == Some(SetupEditor::Credentials) {
            self.return_to_setup_from_editor();
        } else {
            self.open_model_picker();
        }
    }

    pub(crate) fn transition_after_auth_ready(&mut self) -> Vec<ShellEffect> {
        if self.engagement.pending_credential_continuation().is_some() {
            self.router.setup_mut().finish_editor();
            return vec![ShellEffect::ResumeCredentialContinuation];
        }
        if self.router.setup().editor() == Some(SetupEditor::Credentials) {
            self.return_to_setup_from_editor();
        } else {
            self.open_fresh_planner_or_workbench();
        }
        Vec::new()
    }

    fn return_to_setup_from_editor(&mut self) {
        self.router.setup_mut().finish_editor();
        self.engagement.clear_phase();
        self.set_shell_view(ShellView::Setup);
    }

    fn handle_planning_picker_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.handle_planning_option_edit_key(key) {
            return InputUpdate::handled();
        }
        match self.engagement.planning_picker().focus() {
            PickerFocus::List => self.handle_planning_step_key(key.code),
            PickerFocus::OptionsPane => self.handle_planning_options_key(key),
            PickerFocus::Prompt => InputUpdate::ignored(),
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
            && matches!(code, KeyCode::Left | KeyCode::Right)
        {
            self.log(
                "setup",
                "Setup edits the Map plan only; Start Map before moving phases",
            );
            return true;
        }
        match code {
            KeyCode::Up => {
                self.move_planning_cursor(-1);
                true
            }
            KeyCode::Down => {
                self.move_planning_cursor(1);
                true
            }
            KeyCode::Left => {
                self.move_planning_phase(-1);
                true
            }
            KeyCode::Right => {
                self.move_planning_phase(1);
                true
            }
            _ => false,
        }
    }

    fn handle_planning_step_selection_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char(' ') => {
                self.cycle_planning_current_row();
                true
            }
            _ => false,
        }
    }

    fn handle_planning_step_action_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::F(5) => {
                self.cycle_planning_current_row();
                InputUpdate::handled()
            }
            KeyCode::Tab | KeyCode::BackTab => {
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
            KeyCode::Esc => {
                self.close_planning_picker();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn handle_planning_options_key(&mut self, key: KeyEvent) -> InputUpdate {
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('s') {
            return InputUpdate::handled_with_effects(
                self.reduce_persist_selected_planning_option_override(),
            );
        }
        let code = key.code;
        match code {
            KeyCode::Up => {
                self.move_planning_option_cursor(-1);
                InputUpdate::handled()
            }
            KeyCode::Down => {
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
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Esc => {
                self.leave_planning_options_pane();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
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
        let page = WorkbenchPage::from_phase(current);
        match page.investigation_neighbor(delta < 0) {
            Some(next) => self.open_guided_phase_planner(next.phase()),
            None if delta > 0 => self.open_report_from_current_origin(),
            None => self.log("phase", format!("already at {}", current.label())),
        }
    }

    fn cycle_planning_current_row(&mut self) {
        let Some(task) = self
            .engagement
            .planning_picker()
            .current_row()
            .map(|row| row.id)
        else {
            return;
        };
        let tasks = self.engagement.planning_picker().tasks().to_vec();
        // Bind the cycled row before the toggle so the disposition below reads
        // the same row the cursor named, without a second lookup.
        let Some(cycled) = tasks.iter().find(|row| row.id == task).cloned() else {
            return;
        };
        let picker = self.engagement.planning_picker_mut();
        let (selected, rebuild) = picker.outcome_sets_mut();
        let outcome = cycle_planning_row(task, &tasks, selected, rebuild);
        let disposition = row_disposition(&cycled, picker.selected(), picker.rebuild());
        self.log_cycle_outcome(&outcome, disposition);
    }

    fn log_cycle_outcome(&mut self, outcome: &ToggleOutcome, disposition: RowDisposition) {
        if toggle_outcome_is_refusal(outcome) {
            self.log_toggle_outcome(outcome);
            return;
        }
        self.log("planning", cycle_outcome_message(outcome, disposition));
    }

    fn log_toggle_outcome(&mut self, outcome: &ToggleOutcome) {
        let message = toggle_outcome_message(outcome);
        if toggle_outcome_is_refusal(outcome) {
            self.set_warn_notice("planning", message.clone());
            return;
        }
        self.log("planning", message);
    }

    pub(crate) fn accept_planning_picker(&mut self) -> InputUpdate {
        if let Some(update) = self.planning_accept_navigation() {
            return update;
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
        if let Some(update) = self.planning_execution_gate(&plan) {
            return update;
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

    fn planning_execution_gate(&mut self, plan: &[PlanningTaskId]) -> Option<InputUpdate> {
        if let Err(error) = self.validate_context_import_plan(plan) {
            self.set_warn_notice(
                "planning",
                format!("Map plan needs review: {error}. No jobs started."),
            );
            return Some(InputUpdate::handled());
        }
        if let Some(update) = self.review_model_backed_map(plan) {
            return Some(update);
        }
        if let Some(update) = self.review_selected_triage_plan(plan) {
            return Some(update);
        }
        self.open_credentials_for_planning_plan(plan)
            .then(InputUpdate::handled)
    }

    fn planning_accept_navigation(&mut self) -> Option<InputUpdate> {
        if self.engagement.planning_picker().returns_to_setup() {
            self.return_to_setup_from_editor();
            return Some(InputUpdate::handled());
        }
        self.open_file_picker_for_attach_only_plan()
            .then(InputUpdate::handled)
    }

    fn open_credentials_for_planning_plan(&mut self, plan: &[PlanningTaskId]) -> bool {
        if !plan.iter().any(|task| task.is_model_backed()) {
            return false;
        }
        match self.planning_credential_gate(plan) {
            PlanningCredentialGate::Ready => false,
            PlanningCredentialGate::Blocked => true,
            PlanningCredentialGate::Recover(context) => {
                self.open_planning_credential_recovery(plan, context);
                true
            }
        }
    }

    fn planning_credential_gate(&mut self, plan: &[PlanningTaskId]) -> PlanningCredentialGate {
        if !plan
            .iter()
            .copied()
            .any(|task| self.planning_task_uses_config_model(task))
        {
            return PlanningCredentialGate::Ready;
        }
        let Some(model) = self.config().model.clone() else {
            self.set_warn_notice(
                "planning",
                "This plan needs a model before it can start; choose one in Model.",
            );
            self.open_model_picker();
            return PlanningCredentialGate::Blocked;
        };
        if self.configured_model_auth_ready() {
            return PlanningCredentialGate::Ready;
        }
        let Some(target) = self.target_owned() else {
            self.set_error_notice(
                "planning",
                "Return to Target and select a target before starting this Scan.",
            );
            return PlanningCredentialGate::Blocked;
        };
        let Some(phase) = self.engagement.current_phase() else {
            self.set_error_notice(
                "planning",
                "Reopen Scan before continuing; this selection has not started.",
            );
            return PlanningCredentialGate::Blocked;
        };
        PlanningCredentialGate::Recover(Self::planning_credential_context(target, phase, model))
    }

    fn planning_task_uses_config_model(&self, task: PlanningTaskId) -> bool {
        if !task.is_model_backed() {
            return false;
        }
        self.resolved_input_for_planning_task(task)
            .ok()
            .is_some_and(|input| {
                !input
                    .get("model")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|model| !model.trim().is_empty())
            })
    }

    fn planning_credential_context(
        target: PathBuf,
        phase: WorkflowPhase,
        model: String,
    ) -> PlanningCredentialContext {
        let provider = model
            .split_once(':')
            .map(|(provider, _)| provider)
            .unwrap_or_default()
            .to_string();
        let guidance = AuthProvider::from_scene_provider(&provider)
            .map(|auth| auth.missing_credential_guidance(&model, &provider))
            .unwrap_or_else(|| format!("{model} has no compatible configured credential"));
        PlanningCredentialContext {
            target,
            phase,
            model,
            provider,
            guidance,
        }
    }

    fn open_planning_credential_recovery(
        &mut self,
        plan: &[PlanningTaskId],
        context: PlanningCredentialContext,
    ) {
        self.engagement
            .set_pending_credential_continuation(PendingCredentialContinuation {
                target: context.target,
                phase: context.phase,
                model: context.model,
                model_binding: PendingCredentialModelBinding::Config,
                credential_requirement: PendingCredentialRequirement::AnyCompatible,
                work: PendingCredentialWork::CommittedPlan(plan.to_vec()),
            });
        self.open_credential_recovery(context.provider);
        self.set_warn_notice(
            "planning",
            format!(
                "{} plan ready · {}. Add credentials to continue this {}-step plan.",
                context.phase.label(),
                context.guidance,
                plan.len()
            ),
        );
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
            if self.record_current_phase_skip() {
                self.log("phase", format!("nothing selected · skipping {phase}"));
                return self.advance_to_next_phase();
            }
            return Vec::new();
        }
        self.log(
            "phase",
            format!(
                "nothing to run · all {} checked {} are cached and will be reused; \
                 press Space on a cached task to run it fresh, or skip every task and press Enter",
                self.engagement.planning_picker().selected().len(),
                task_word(self.engagement.planning_picker().selected().len())
            ),
        );
        Vec::new()
    }

    fn close_planning_picker(&mut self) {
        if self.engagement.planning_picker().returns_to_setup() {
            self.return_to_setup_from_editor();
            return;
        }
        let origin_page = self
            .engagement
            .planning_picker_mut()
            .take_origin_workbench_page();
        let origin_view = self
            .engagement
            .planning_picker_mut()
            .take_origin_shell_view();
        let phase = self
            .engagement
            .current_phase()
            .map(|phase| phase.label())
            .unwrap_or("planning");
        self.log("phase", format!("closed {phase} picker"));
        self.restore_planning_picker_origin(origin_view, origin_page);
    }

    fn restore_planning_picker_origin(
        &mut self,
        origin_view: Option<ShellView>,
        origin_page: Option<WorkbenchPage>,
    ) {
        // Setup owns a Map-only projection of the shared planner. A phase
        // detour replaces those rows, so a bare view restore would leak the
        // foreign phase into Setup readiness and the embedded Map editor.
        // Re-enter through the canonical Setup hydrator instead.
        if origin_view == Some(ShellView::Setup) {
            self.open_setup();
            return;
        }
        // Esc means "never mind" — restore the exact view the operator came
        // from. Non-workbench origins (Threat view, Home, a contextual
        // detour) go straight back; workbench origins restore their page,
        // since the findings refresh inside `open_workbench` may have
        // re-derived a different one.
        if let Some(view) = origin_view
            .filter(|view| !matches!(view, ShellView::Workbench | ShellView::PlanningPicker))
        {
            self.set_shell_view(view);
            return;
        }
        self.open_workbench();
        if let Some(page) = origin_page {
            self.set_workbench_page(page);
        }
    }
}

fn picker_shell_chord(modifiers: KeyModifiers) -> bool {
    modifiers.contains(KeyModifiers::CONTROL) || modifiers.contains(KeyModifiers::ALT)
}

fn picker_command_char(key: KeyEvent) -> Option<char> {
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return None;
    }
    match key.code {
        KeyCode::Char(ch) if !ch.is_control() && !ch.is_whitespace() => Some(ch),
        _ => None,
    }
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

fn cycle_outcome_message(outcome: &ToggleOutcome, disposition: RowDisposition) -> String {
    let task = match outcome {
        ToggleOutcome::On { task, .. } | ToggleOutcome::Off { task } => *task,
        _ => return toggle_outcome_message(outcome),
    };
    let verb = match disposition {
        RowDisposition::WillRun => "run",
        RowDisposition::Reused => "reuse",
        RowDisposition::Off => "skip",
        RowDisposition::Unavailable => "blocked",
    };
    let dependencies = match outcome {
        ToggleOutcome::On { auto_added, .. } if !auto_added.is_empty() => {
            format!(" · includes {}", planning_task_labels(auto_added))
        }
        _ => String::new(),
    };
    format!("[{verb}] {}{dependencies}", task.label())
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
    fn printable_picker_key_moves_losslessly_into_the_composer() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::TargetPicker);
        app.router.target_picker_mut().open(Vec::new());

        let update = app.reduce_key(plain_key(KeyCode::Char('q')));

        assert!(update.handled);
        assert_eq!(app.shell_view(), ShellView::TargetPicker);
        assert!(app.picker_prompt_focused());
        assert_eq!(app.input(), "q");
    }

    #[test]
    fn composer_input_is_limited_to_unfocused_non_file_pickers() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::TargetPicker);
        app.router.target_picker_mut().open(Vec::new());
        assert!(app.picker_surface_accepts_composer_input());

        app.router
            .target_picker_mut()
            .set_focus(PickerFocus::Prompt);
        assert!(!app.picker_surface_accepts_composer_input());

        app.set_shell_view(ShellView::FilePicker);
        assert!(!app.picker_surface_accepts_composer_input());

        app.set_shell_view(ShellView::Workbench);
        assert!(!app.picker_surface_accepts_composer_input());
    }

    #[test]
    fn api_key_editor_keeps_printable_input_ownership() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_credential_entry("anthropic".to_string());

        let update = app.reduce_key(plain_key(KeyCode::Char('d')));

        assert!(update.handled);
        assert!(!app.picker_prompt_focused());
        assert_eq!(app.router.auth_picker().key_draft(), "d");
        assert!(app.input().is_empty());
    }

    #[test]
    fn budget_and_planning_option_editors_keep_first_refusal() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::Setup);
        app.router.setup_mut().begin_budget_edit(None);

        assert!(app.reduce_key(plain_key(KeyCode::Char('q'))).handled);
        assert!(app.input().is_empty());
        assert_eq!(app.router.setup().budget_draft(), "q");

        app.set_shell_view(ShellView::PlanningPicker);
        app.engagement
            .planning_picker_mut()
            .set_option_edit(Some(PlanningOptionEdit::new(
                PlanningTaskId::GatherRepoContext,
                "scope",
                "",
            )));
        assert!(app.reduce_key(plain_key(KeyCode::Char(':'))).handled);
        assert_eq!(
            app.engagement
                .planning_picker()
                .option_edit()
                .map(|edit| edit.field.text()),
            Some(":")
        );
        assert!(app.input().is_empty());
    }

    #[test]
    fn api_key_editor_keeps_colon_in_the_secret_draft() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.open_auth_method_picker("anthropic".to_string());

        let update = app.reduce_key(plain_key(KeyCode::Char(':')));

        assert!(update.handled);
        assert!(!app.picker_prompt_focused());
        assert_eq!(app.router.auth_picker().key_draft(), ":");
        app.reduce_key(plain_key(KeyCode::Char('j')));
        assert!(app.input().is_empty());
        assert_eq!(app.router.auth_picker().key_draft(), ":j");
    }

    #[test]
    fn accepting_api_key_preserves_model_and_thinking_level() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.config_mut().model = Some("openai-codex:gpt-5.4".to_string());
        app.set_session_thinking_level(Some("medium".to_string()));
        app.open_auth_method_picker("openai-codex".to_string());
        app.router.auth_picker_mut().push_key_str("sk-session");

        let effects = app.accept_pasted_auth_api_key("openai");

        assert_eq!(app.config().model.as_deref(), Some("openai-codex:gpt-5.4"));
        assert_eq!(app.session_thinking_level(), Some("medium"));
        assert!(matches!(
            effects.as_slice(),
            [ShellEffect::SetSessionEnv(_)]
        ));
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, ShellEffect::PersistGlobalModelSelection(_))));
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

    #[test]
    fn closing_foreign_phase_picker_back_to_setup_rehydrates_map_plan() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));

        app.open_setup();
        assert_eq!(app.shell_view(), ShellView::Setup);
        assert!(app.engagement.planning_picker().returns_to_setup());
        assert!(app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .all(|row| row.id.phase() == WorkflowPhase::Map));

        assert!(app.try_open_phase_picker(WorkflowPhase::Scan));
        assert_eq!(app.shell_view(), ShellView::PlanningPicker);
        assert!(!app.engagement.planning_picker().returns_to_setup());
        assert!(app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .all(|row| row.id.phase() == WorkflowPhase::Scan));

        app.close_planning_picker();

        assert_eq!(app.shell_view(), ShellView::Setup);
        assert!(app.engagement.current_phase().is_none());
        assert!(app.engagement.planning_picker().returns_to_setup());
        assert!(!app.engagement.planning_picker().tasks().is_empty());
        assert!(app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .all(|row| row.id.phase() == WorkflowPhase::Map));
    }
}
