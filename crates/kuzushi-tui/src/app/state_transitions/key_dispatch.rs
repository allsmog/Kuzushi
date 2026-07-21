use super::confirmation_keys::{
    confirm_key_action, confirm_key_modifiers_allowed, ConfirmKeyAction,
};
use super::control_keys::control_key_action;
use super::*;

#[derive(Clone, Copy)]
enum JourneyPhaseEntry {
    Workbench,
    Planner,
}

impl ShellApp {
    pub(crate) fn reduce_key(&mut self, key: KeyEvent) -> InputUpdate {
        let key = normalize_back_tab(key);
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
        if let Some(update) = self.reduce_priority_non_modal_key(key, modifiers) {
            return update;
        }
        self.reduce_mode_control_or_navigation_key(key, modifiers)
    }

    fn reduce_priority_non_modal_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> Option<InputUpdate> {
        if self.guided_scan_question_is_open() && !guided_question_yields_to_control_c(key) {
            return Some(self.reduce_guided_scan_key(key));
        }
        if let Some(update) = self.handle_autonomy_key(key, modifiers) {
            return Some(update);
        }

        self.reduce_phase_result_or_shell_key(key)
    }

    fn reduce_phase_result_or_shell_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if let Some(update) = self.reduce_configured_phase_result_key(key) {
            return Some(update);
        }
        if let Some(update) = self.reduce_default_phase_result_key(key) {
            return Some(update);
        }

        self.reduce_configured_shell_or_mode_cycle(key)
    }

    fn reduce_configured_phase_result_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if let Some(update) = self.handle_configured_phase_result_key(key) {
            return Some(update);
        }
        self.handle_configured_phase_result_prompt_mode(key)
    }

    fn reduce_default_phase_result_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if let Some(update) = self.handle_phase_result_escape(key) {
            return Some(update);
        }
        if let Some(update) = self.handle_phase_result_key(key) {
            return Some(update);
        }
        (self.phase_result_is_open() && !guided_question_yields_to_control_c(key))
            .then(InputUpdate::handled)
    }

    fn handle_configured_phase_result_prompt_mode(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.phase_result_is_open() {
            return None;
        }
        match self
            .ui_mut()
            .handle_configured_context_key("composer", key, Instant::now())
        {
            ConfiguredKeyResult::Action(ViewHotkeyAction::EnterPromptMode) => {
                self.enter_prompt_mode();
                Some(InputUpdate::handled())
            }
            ConfiguredKeyResult::Action(_) | ConfiguredKeyResult::Pending => {
                Some(InputUpdate::handled())
            }
            ConfiguredKeyResult::NoMatch => None,
        }
    }

    fn handle_phase_result_escape(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.phase_result_is_open()
            || !key.modifiers.is_empty()
            || key.code != KeyCode::Esc
            || !self.default_composer_action_enabled("prompt_mode")
        {
            return None;
        }
        self.enter_prompt_mode();
        Some(InputUpdate::handled())
    }

    fn reduce_configured_shell_or_mode_cycle(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let view = self.shell_view();
        let inactive_action = inactive_composer_mode_action(self.input_mode());
        let configured =
            self.ui_mut()
                .handle_configured_shell_key(view, key, Instant::now(), inactive_action);
        if let Some(update) = configured_shell_key_update(self, configured) {
            return Some(update);
        }

        // Workbench mode cycling is available from both Prompt and Navigate.
        // It runs after every modal/editor owner has had first refusal, but
        // before Prompt's line editor or Navigate's pane bindings can consume
        // BackTab. The shared editor state is intentionally left untouched.
        if self.handle_workbench_mode_cycle_key(key) {
            return Some(InputUpdate::handled());
        }
        None
    }

    fn apply_configured_key_action(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        match action {
            ViewHotkeyAction::OpenCommandPalette => {
                self.open_command_palette();
                InputUpdate::handled()
            }
            ViewHotkeyAction::OpenHelp => self.reduce_hotkey_command(ShellCommand::Help(None)),
            ViewHotkeyAction::EnterNavigateMode => {
                self.enter_navigate_mode();
                InputUpdate::handled()
            }
            ViewHotkeyAction::EnterPromptMode => {
                self.enter_prompt_mode();
                InputUpdate::handled()
            }
            ViewHotkeyAction::CompleteComposer => {
                self.apply_completion();
                InputUpdate::handled()
            }
            ViewHotkeyAction::PhaseResult(command) => self.apply_phase_result_command(command),
            _ => self.apply_view_hotkey(action),
        }
    }

    fn reduce_mode_control_or_navigation_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        let update = self.handle_mode_or_control_key(key, modifiers);
        if update.handled {
            return update;
        }
        self.reduce_navigation_or_text_key(key, modifiers)
    }

    fn handle_phase_result_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.shell_view() != ShellView::Workbench
            || self.input_mode() != InputMode::Navigate
            || !key.modifiers.is_empty()
        {
            return None;
        }
        let command = PhaseResultCommand::from_default_key(key.code)?;
        if self
            .ui()
            .keymap_overrides_action("phase_result", command.action_id())
        {
            return Some(InputUpdate::handled());
        }
        self.phase_result_command_is_available(command)
            .then(|| self.apply_phase_result_command(command))
    }

    fn handle_configured_phase_result_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.phase_result_is_open() {
            return None;
        }
        let result =
            self.ui_mut()
                .handle_configured_context_key("phase_result", key, Instant::now());
        match result {
            ConfiguredKeyResult::Action(ViewHotkeyAction::PhaseResult(command)) => {
                Some(self.apply_phase_result_command(command))
            }
            ConfiguredKeyResult::Action(_) | ConfiguredKeyResult::Pending => {
                Some(InputUpdate::handled())
            }
            ConfiguredKeyResult::NoMatch => self
                .phase_result_default_is_overridden(key)
                .then(InputUpdate::handled),
        }
    }

    fn phase_result_default_is_overridden(&self, key: KeyEvent) -> bool {
        if !key.modifiers.is_empty() {
            return false;
        }
        PhaseResultCommand::from_default_key(key.code).is_some_and(|command| {
            self.ui()
                .keymap_overrides_action("phase_result", command.action_id())
        })
    }

    fn phase_result_is_open(&self) -> bool {
        if self.shell_view() != ShellView::Workbench || self.input_mode() != InputMode::Navigate {
            return false;
        }
        let phase = crate::ui_view_models::active_workbench_page(self).phase();
        self.engagement.unresolved_phase_attempt(phase).is_some()
    }

    fn phase_result_command_is_available(&self, command: PhaseResultCommand) -> bool {
        let phase = crate::ui_view_models::active_workbench_page(self).phase();
        self.projected_phase_result_policy(phase)
            .is_some_and(|policy| {
                policy
                    .actions
                    .into_iter()
                    .any(|action| command.matches(action))
            })
    }

    pub(crate) fn apply_phase_result_command(
        &mut self,
        command: PhaseResultCommand,
    ) -> InputUpdate {
        if !self.phase_result_command_is_available(command) {
            return InputUpdate::handled();
        }
        match command {
            PhaseResultCommand::Select => self.record_phase_result_selection(false),
            PhaseResultCommand::Continue => self.record_phase_result_selection(true),
            PhaseResultCommand::Discard => self.discard_phase_result(),
            PhaseResultCommand::Open => self.open_phase_result_runs(),
            PhaseResultCommand::RunAgain => self.draft_phase_rerun(None),
            PhaseResultCommand::Refine => self.draft_phase_rerun(Some(
                kuzushi_core::workflow_attempts::PhaseAttemptDerivation::Refine,
            )),
            PhaseResultCommand::Regenerate => self.draft_phase_rerun(Some(
                kuzushi_core::workflow_attempts::PhaseAttemptDerivation::Regenerate,
            )),
        }
    }

    fn record_phase_result_selection(&mut self, continue_after: bool) -> InputUpdate {
        use kuzushi_core::workflow_attempts::{
            PhaseAttemptDisposition, PhaseAttemptDispositionRecorded, PhaseAttemptOutcome,
        };
        let phase = crate::ui_view_models::active_workbench_page(self).phase();
        let Some(record) = self.engagement.unresolved_phase_attempt(phase).cloned() else {
            return InputUpdate::handled();
        };
        if !self.materialize_phase_result_reality(phase, &record) {
            return InputUpdate::handled();
        }
        let Some(selected_fix_patch) = self.phase_result_selection_patch(phase, &record) else {
            return InputUpdate::handled();
        };
        let acknowledged_partial = record.completed.outcome == PhaseAttemptOutcome::Partial;
        let disposition = PhaseAttemptDispositionRecorded::new(
            record.completed.attempt_id.clone(),
            PhaseAttemptDisposition::Selected {
                acknowledged_partial,
            },
        );
        if !self.append_phase_disposition(disposition) {
            return InputUpdate::handled();
        }
        self.finish_phase_result_selection(phase, &record, selected_fix_patch, continue_after);
        InputUpdate::handled()
    }

    fn materialize_phase_result_reality(
        &mut self,
        phase: WorkflowPhase,
        record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
    ) -> bool {
        if phase != WorkflowPhase::Prove {
            return true;
        }
        let Some(target) = self.target_owned() else {
            self.log("workflow", "Prove selection requires an active target");
            return false;
        };
        match self.materialize_selected_proof(&target, record) {
            Ok(()) => true,
            Err(error) => {
                self.log("error", format!("Prove selection blocked: {error}"));
                false
            }
        }
    }

    fn materialize_selected_proof(
        &mut self,
        target: &std::path::Path,
        record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
    ) -> anyhow::Result<()> {
        let workspace = kuzushi_core::WorkspaceTarget::new(target)?;
        kuzushi_core::verification::application::materialize_selected_proof_attempt(
            &workspace,
            &record.completed,
        )?;
        self.refresh_findings_preserving_active_filter(false);
        self.invalidate_view_hydration();
        Ok(())
    }

    fn phase_result_selection_patch(
        &mut self,
        phase: WorkflowPhase,
        record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
    ) -> Option<Option<PendingPatch>> {
        if phase != WorkflowPhase::Fix || self.verified_remediation_result_is_open(phase) {
            return Some(None);
        }
        self.preflight_fix_attempt_selection(record).map(Some)
    }

    fn finish_phase_result_selection(
        &mut self,
        phase: WorkflowPhase,
        record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
        selected_fix_patch: Option<PendingPatch>,
        continue_after: bool,
    ) {
        self.engagement.clear_attempt_lineage(phase);
        self.log(
            "workflow",
            format!(
                "selected {} attempt {}",
                phase.label(),
                record.completed.attempt_id
            ),
        );
        if let Some(patch) = selected_fix_patch {
            self.engagement.set_pending_patch(patch);
        }
        if self.finish_guided_result_selection(phase, continue_after) {
            return;
        }
        if continue_after {
            self.open_rederived_journey_destination();
        }
    }

    fn finish_guided_result_selection(
        &mut self,
        phase: WorkflowPhase,
        continue_after: bool,
    ) -> bool {
        if !self.guided_scan_is_awaiting(phase) {
            return false;
        }
        if continue_after {
            return self.continue_guided_scan_after_result(phase);
        }
        self.clear_guided_scan();
        false
    }

    fn preflight_fix_attempt_selection(
        &mut self,
        record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
    ) -> Option<PendingPatch> {
        let target = self.target_owned()?;
        let workspace = match kuzushi_core::WorkspaceTarget::new(&target) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("patch", format!("Fix selection blocked: {error}"));
                return None;
            }
        };
        match validate_fix_attempt_candidate(&workspace, record) {
            Ok(patch) => Some(patch),
            Err(error) => {
                self.log("patch", format!("Fix selection blocked: {error}"));
                None
            }
        }
    }

    fn discard_phase_result(&mut self) -> InputUpdate {
        use kuzushi_core::workflow_attempts::{
            PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
        };
        let phase = crate::ui_view_models::active_workbench_page(self).phase();
        let Some(record) = self.engagement.unresolved_phase_attempt(phase).cloned() else {
            return InputUpdate::handled();
        };
        let disposition = PhaseAttemptDispositionRecorded::new(
            record.completed.attempt_id.clone(),
            PhaseAttemptDisposition::Discarded,
        );
        if self.append_phase_disposition(disposition) {
            self.engagement.clear_attempt_lineage(phase);
            if self.guided_scan_is_awaiting(phase) {
                self.clear_guided_scan();
            }
            // The card vanishes on discard, so a visible receipt is the only
            // on-screen acknowledgement that the keypress resolved the
            // attempt rather than deleting it. One verb: Discard.
            self.set_info_notice(
                "workflow",
                format!(
                    "discarded attempt {} — run evidence retained",
                    record.completed.attempt_id
                ),
            );
        }
        InputUpdate::handled()
    }

    fn append_phase_disposition(
        &mut self,
        disposition: kuzushi_core::workflow_attempts::PhaseAttemptDispositionRecorded,
    ) -> bool {
        let Some(target) = self.target_owned() else {
            self.log("workflow", "phase result requires an active target");
            return false;
        };
        match kuzushi_core::workflow_attempts::append_phase_attempt_disposition(
            &target,
            disposition,
        ) {
            Ok(_) => {
                self.refresh_phase_attempt_projection();
                self.refresh_journey_ledger_projection();
                true
            }
            Err(error) => {
                self.log(
                    "workflow",
                    format!("phase result could not be recorded: {error}"),
                );
                false
            }
        }
    }

    pub(crate) fn open_next_journey_destination(&mut self) -> bool {
        self.open_rederived_journey_destination_with(JourneyPhaseEntry::Planner)
    }

    pub(crate) fn open_rederived_journey_destination(&mut self) {
        self.open_rederived_journey_destination_with(JourneyPhaseEntry::Workbench);
    }

    fn open_rederived_journey_destination_with(&mut self, phase_entry: JourneyPhaseEntry) -> bool {
        let Some(journey) = crate::ui_view_models::journey_model(self) else {
            return false;
        };
        match journey.destination {
            crate::ui_view_models::JourneyDestination::Phase(phase) => {
                self.open_journey_phase(phase, phase_entry);
            }
            crate::ui_view_models::JourneyDestination::Report(_) => {
                self.open_report_from_current_origin();
            }
        }
        true
    }

    fn open_journey_phase(&mut self, phase: WorkflowPhase, entry: JourneyPhaseEntry) {
        match entry {
            JourneyPhaseEntry::Workbench => {
                self.set_workbench_page(WorkbenchPage::from_phase(phase));
            }
            JourneyPhaseEntry::Planner => self.open_phase_picker(phase),
        }
    }

    fn current_phase_result_record(
        &self,
    ) -> Option<kuzushi_core::workflow_attempts::PhaseAttemptRecord> {
        let phase = crate::ui_view_models::active_workbench_page(self).phase();
        self.engagement.unresolved_phase_attempt(phase).cloned()
    }

    fn open_phase_result_runs(&mut self) -> InputUpdate {
        let Some(record) = self.current_phase_result_record() else {
            return InputUpdate::handled();
        };
        let Some(run_id) = record.completed.run_refs.last().cloned() else {
            self.log("workflow", "phase attempt has no canonical run reference");
            return InputUpdate::handled();
        };
        self.push_nav_history(self.shell_view());
        self.router.replay_mut().open(run_id.clone());
        self.set_shell_view(ShellView::Replay);
        self.log("replay", format!("opened phase attempt run {run_id}"));
        InputUpdate::handled()
    }

    fn draft_phase_rerun(
        &mut self,
        derivation: Option<kuzushi_core::workflow_attempts::PhaseAttemptDerivation>,
    ) -> InputUpdate {
        if let Some(draft) = self.phase_rerun_draft(derivation) {
            self.apply_phase_rerun_draft(draft);
        }
        InputUpdate::handled()
    }

    fn phase_rerun_draft(
        &mut self,
        derivation: Option<kuzushi_core::workflow_attempts::PhaseAttemptDerivation>,
    ) -> Option<PhaseRerunDraft> {
        let record = self.current_phase_result_record()?;
        let target = self.target_owned()?;
        let Some((tool, input)) = record
            .completed
            .run_refs
            .iter()
            .rev()
            .find_map(|run_id| rerun_specification(&target, run_id))
        else {
            self.log(
                "workflow",
                "exact rerun unavailable — no referenced run has a readable tool input",
            );
            return None;
        };
        Some(PhaseRerunDraft {
            phase: record.completed.phase,
            parent_attempt_id: record.completed.attempt_id,
            tool,
            input,
            derivation,
        })
    }

    fn apply_phase_rerun_draft(&mut self, draft: PhaseRerunDraft) {
        match draft.derivation {
            Some(derivation) => {
                self.engagement.arm_attempt_lineage(
                    draft.phase,
                    draft.parent_attempt_id,
                    derivation,
                );
            }
            None => self.engagement.clear_attempt_lineage(draft.phase),
        }
        self.set_input(format!("run {} {}", draft.tool, draft.input));
        self.set_input_mode(InputMode::Prompt);
        self.log(
            "workflow",
            format!(
                "{} loaded from canonical input.json — edit canonical input or press Enter",
                phase_rerun_action(draft.derivation)
            ),
        );
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
        if let Some(update) = self.handle_primary_modal_key(key) {
            return update;
        }
        if self.prompt_document_is_open() {
            return self.reduce_prompt_document_key(key);
        }
        self.handle_remaining_modal_key(key)
    }

    fn handle_primary_modal_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.advisory().pending_confirm.is_some() {
            return Some(self.handle_confirm_key(key));
        }
        if self.handle_contextual_surface_key(key) {
            return Some(InputUpdate::handled());
        }
        self.handle_modal_editor_key(key)
    }

    fn handle_modal_editor_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let question_update = self.handle_operator_question_key(key);
        if question_update.handled {
            return Some(question_update);
        }
        let report_update = self.handle_report_modal_key(key);
        if report_update.handled {
            return Some(report_update);
        }
        let steer_update = self.handle_run_focus_steer_editor_key(key);
        if steer_update.handled {
            return Some(steer_update);
        }
        None
    }

    fn prompt_document_is_open(&self) -> bool {
        matches!(self.shell_view(), ShellView::PromptsEditor)
            && self.router.prompts().document().is_some()
    }

    fn handle_remaining_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        let prereq_update = self.handle_prereq_prompt_key(key);
        if prereq_update.handled {
            return prereq_update;
        }
        if self.handle_overlay_key(key) {
            return InputUpdate::handled();
        }
        self.handle_shared_modal_key(key)
    }

    fn handle_contextual_surface_key(&mut self, key: KeyEvent) -> bool {
        if !key.modifiers.is_empty() {
            return false;
        }
        let contextual_utility = matches!(
            self.shell_view(),
            ShellView::Catalog
                | ShellView::Keymap
                | ShellView::Help
                | ShellView::Jobs
                | ShellView::Campaign
                | ShellView::Replay
                | ShellView::Trace
                | ShellView::Scene
        );
        if !contextual_utility {
            return false;
        }
        if key.code == KeyCode::Esc {
            return self.restore_contextual_surface_origin();
        }
        false
    }

    fn handle_report_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !matches!(self.shell_view(), ShellView::Report) {
            return InputUpdate::ignored();
        }
        if self.router.report().editing_path() {
            return self.handle_report_path_edit_key(key);
        }
        self.handle_report_escape_key(key)
    }

    fn handle_report_escape_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.input_mode() == InputMode::Navigate && key.code == KeyCode::Esc {
            self.close_report_to_origin();
            return InputUpdate::handled();
        }
        InputUpdate::ignored()
    }

    fn handle_report_path_edit_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
            return InputUpdate::handled();
        }
        self.apply_report_path_edit_key(key.code);
        InputUpdate::handled()
    }

    fn apply_report_path_edit_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc | KeyCode::Enter => {
                self.router.report_mut().set_editing_path(false);
            }
            KeyCode::Backspace => {
                self.router.report_mut().path_draft_mut().pop();
            }
            KeyCode::Char(ch) => self.router.report_mut().path_draft_mut().push(ch),
            _ => {}
        }
    }

    fn handle_run_focus_steer_editor_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !self.run_focus_steer_editor_is_open() {
            return InputUpdate::ignored();
        }
        if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
            return InputUpdate::handled();
        }
        self.apply_run_focus_steer_editor_key(key.code);
        InputUpdate::handled()
    }

    fn run_focus_steer_editor_is_open(&self) -> bool {
        matches!(self.shell_view(), ShellView::Activity)
            && self.router.activity().steer_editor.is_some()
    }

    fn apply_run_focus_steer_editor_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.router.activity_mut().close_steer_editor(),
            KeyCode::Enter => self.submit_run_focus_steer_editor(),
            _ => self.edit_run_focus_steer_input(code),
        }
    }

    fn edit_run_focus_steer_input(&mut self, code: KeyCode) {
        let Some(editor) = self.router.activity_mut().steer_editor.as_mut() else {
            return;
        };
        match code {
            KeyCode::Backspace => {
                editor.input.pop();
                editor.error = None;
            }
            KeyCode::Char(ch) => {
                editor.input.push(ch);
                editor.error = None;
            }
            _ => {}
        }
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
        if self.is_picker_view() && self.handle_notice_dismiss_key(key) {
            return InputUpdate::handled();
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
            ShellView::Keymap | ShellView::Help => self.handle_keymap_overlay_key(key),
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
        if self.advisory().pending_confirm.is_none() || is_quit_chord(key) {
            return InputUpdate::ignored();
        }
        if let Some(action) = self.applicable_confirm_action(key) {
            return self.apply_confirm_key_action(action);
        }
        InputUpdate::handled()
    }

    fn applicable_confirm_action(&self, key: KeyEvent) -> Option<ConfirmKeyAction> {
        confirm_key_modifiers_allowed(key)
            .then(|| confirm_key_action(key.code))
            .flatten()
            .filter(|action| {
                self.advisory()
                    .pending_confirm
                    .as_ref()
                    .is_some_and(|confirm| {
                        confirm.kind.allows_action(action.outcome, action.remember)
                    })
            })
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
        // Tab keeps the completion cycle alive (it's the cycle's input), and
        // Workbench BackTab changes only the selected mode. Esc owns
        // the cycle teardown via `esc_clear_input_or_completion` (M3 §3.3) so the
        // popup can restore the operator's original prefix instead of
        // losing it to a blanket reset.
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab | KeyCode::Esc) {
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
        if key.code == KeyCode::Char('g')
            && self
                .ui()
                .keymap_overrides_action("global", "command_palette")
        {
            return InputUpdate::handled();
        }
        let Some(action) = control_key_action(key.code) else {
            return InputUpdate::ignored();
        };
        action.apply(self)
    }

    fn handle_input_mode_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        if !modifiers.no_modifiers || key.code != KeyCode::Esc {
            return false;
        }
        // Esc toggles the composer mode: with a draft or completion popup the
        // line editor consumes Esc first (clear/restore), so Navigate entry
        // only fires on an empty prompt.
        match self.input_mode() {
            InputMode::Prompt => {
                if self.input().is_empty()
                    && self.default_composer_action_enabled("navigate_mode")
                {
                    self.enter_navigate_mode();
                    return true;
                }
            }
            InputMode::Navigate => {
                if self.default_composer_action_enabled("prompt_mode") {
                    self.enter_prompt_mode();
                    return true;
                }
            }
        }
        false
    }

    fn default_composer_action_enabled(&self, action: &str) -> bool {
        !self.ui().keymap_overrides_action("composer", action)
    }

    fn handle_workbench_mode_cycle_key(&mut self, key: KeyEvent) -> bool {
        if self.shell_view() != ShellView::Workbench
            || self
                .ui()
                .keymap_overrides_action("workbench", "cycle_phase")
            || !HotkeyTrigger::BackTab.matches(key)
        {
            return false;
        }
        self.cycle_workbench_page_mode();
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
        self.log("input", "prompt mode — Esc on an empty prompt returns to navigation");
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

/// Terminals speaking an enhanced keyboard protocol (kitty CSI-u,
/// modifyOtherKeys, tmux extended-keys) report Shift+Tab as `Tab` with the
/// SHIFT modifier instead of the legacy `ESC [ Z` BackTab that every binding
/// in this crate matches. Fold that encoding into the canonical BackTab
/// before dispatch so Shift+Tab behaves the same on every terminal.
fn normalize_back_tab(mut key: KeyEvent) -> KeyEvent {
    if key.code == KeyCode::Tab && key.modifiers.contains(KeyModifiers::SHIFT) {
        key.code = KeyCode::BackTab;
    }
    key
}

fn guided_question_yields_to_control_c(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')
}

fn configured_shell_key_update(
    app: &mut ShellApp,
    result: ConfiguredKeyResult,
) -> Option<InputUpdate> {
    match result {
        ConfiguredKeyResult::Action(action) => Some(app.apply_configured_key_action(action)),
        ConfiguredKeyResult::Pending => Some(InputUpdate::handled()),
        ConfiguredKeyResult::NoMatch => None,
    }
}

fn inactive_composer_mode_action(mode: InputMode) -> ViewHotkeyAction {
    match mode {
        InputMode::Prompt => ViewHotkeyAction::EnterPromptMode,
        InputMode::Navigate => ViewHotkeyAction::EnterNavigateMode,
    }
}

struct PhaseRerunDraft {
    phase: WorkflowPhase,
    parent_attempt_id: String,
    tool: String,
    input: String,
    derivation: Option<kuzushi_core::workflow_attempts::PhaseAttemptDerivation>,
}

fn rerun_specification(target: &std::path::Path, run_id: &str) -> Option<(String, String)> {
    let summary = kuzushi_core::load_run_summary(target, run_id).ok()?;
    let tool = summary.tool?;
    let kuzushi_core::RunArtifactRead::Ready { value, .. } =
        kuzushi_core::read_run_artifact_text(target, run_id, "input.json")
    else {
        return None;
    };
    let input: serde_json::Value = serde_json::from_str(&value).ok()?;
    Some((tool, input.to_string()))
}

fn phase_rerun_action(
    derivation: Option<kuzushi_core::workflow_attempts::PhaseAttemptDerivation>,
) -> &'static str {
    use kuzushi_core::workflow_attempts::PhaseAttemptDerivation::{Original, Refine, Regenerate};
    match derivation {
        Some(Refine) => "refine",
        Some(Regenerate) => "regenerate",
        Some(Original) | None => "run again",
    }
}

#[cfg(test)]
fn phase_result_command_allowed(
    completed: &kuzushi_core::workflow_attempts::PhaseAttemptCompleted,
    command: PhaseResultCommand,
) -> bool {
    completed_attempt_actions(completed)
        .into_iter()
        .any(|action| command.matches(action))
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

    fn pending_descriptor_confirm() -> PendingConfirm {
        PendingConfirm {
            kind: ConfirmKind::DescriptorEffect,
            tool: "recon:nmap".to_string(),
            target: "127.0.0.1".to_string(),
            rationale: None,
            allowlist: None,
            actor: None,
            remembered: false,
        }
    }

    fn completed_phase_attempt(
        phase: WorkflowPhase,
        outcome: kuzushi_core::workflow_attempts::PhaseAttemptOutcome,
    ) -> kuzushi_core::workflow_attempts::PhaseAttemptCompleted {
        use kuzushi_core::workflow_attempts::{PhaseAttemptCompleted, PhaseTargetSnapshot};
        PhaseAttemptCompleted::new(
            phase,
            vec!["run".to_string()],
            PhaseTargetSnapshot {
                target: "/target".to_string(),
                revision: None,
                dirty: false,
            },
            outcome,
        )
    }

    fn app_with_unresolved_map_result(config: V2Config) -> (tempfile::TempDir, ShellApp, String) {
        use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;
        let target = tempfile::tempdir().unwrap();
        seed_indexed_map_run(target.path(), "map-run");
        let completed = crate::test_support::append_typed_attempt(
            target.path(),
            WorkflowPhase::Map,
            "map-run",
            PhaseAttemptOutcome::Completed,
        );
        let attempt_id = completed.attempt_id.clone();
        let mut app = ShellApp::new(config, None);
        app.set_target(Some(target.path().to_path_buf()));
        app.refresh_phase_attempt_projection();
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Map));
        app.set_input_mode(InputMode::Navigate);
        (target, app, attempt_id)
    }

    fn seed_indexed_map_run(target: &std::path::Path, run_id: &str) {
        crate::test_support::record_indexed_run(
            target,
            run_id,
            "context:build",
            serde_json::json!({
                "ok": true,
                "data": {"snapshot": {"filesIndexed": 1}}
            }),
        );
    }

    struct FixResultFixture {
        target: tempfile::TempDir,
        attempt_id: String,
    }

    fn seed_verified_fix_result(
        attempt_run_id: &str,
        attempt_tool: &str,
        lifecycle_run_id: &str,
    ) -> FixResultFixture {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding = seed_fix_result_findings(&store, workspace.root());
        seed_verified_patch_lifecycle(&store, &workspace, &finding, lifecycle_run_id);
        write_completed_fix_run_summary(&workspace, attempt_run_id, attempt_tool);
        let attempt_id = append_fix_result_attempt(&workspace, attempt_run_id);
        FixResultFixture { target, attempt_id }
    }

    fn seed_fix_result_findings(
        store: &kuzushi_core::FindingStore,
        target: &std::path::Path,
    ) -> kuzushi_core::Finding {
        use kuzushi_core::{Finding, Severity};

        store
            .record_run_started("scan-fix-result", target, "completed")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "rust/sql-injection",
            "src/auth.rs",
            17,
            None,
            Severity::High,
            "query reaches the database",
        );
        store.insert_finding("scan-fix-result", &finding).unwrap();
        let unrelated_finding = Finding::new_tool(
            "semgrep",
            "rust/path-traversal",
            "src/unrelated.rs",
            9,
            None,
            Severity::Medium,
            "unrelated finding",
        );
        store
            .insert_finding("scan-fix-result", &unrelated_finding)
            .unwrap();
        store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap()
    }

    fn seed_verified_patch_lifecycle(
        store: &kuzushi_core::FindingStore,
        workspace: &kuzushi_core::WorkspaceTarget,
        finding: &kuzushi_core::Finding,
        lifecycle_run_id: &str,
    ) {
        use kuzushi_core::{PatchLifecycleRecord, PatchLifecycleState};

        store
            .insert_patch_lifecycle_record(&PatchLifecycleRecord {
                application_id: "application-fix-result".to_string(),
                stable_fp: store
                    .patch_lifecycle_stable_fp(&finding.fingerprint)
                    .unwrap(),
                fingerprint: finding.fingerprint.clone(),
                finding_scan_id: finding.scan_id.clone(),
                patch_run_id: "patch-candidate-run".to_string(),
                target: workspace.root().display().to_string(),
                diff_hash: "diff-sha256".to_string(),
                base_commit: None,
                touched_files: Vec::new(),
                state: PatchLifecycleState::Verified,
                reverify_run_id: Some(lifecycle_run_id.to_string()),
                detail: Some("re-verification passed".to_string()),
                actor: "operator".to_string(),
                application_started_at: "1".to_string(),
                applied_at: Some("2".to_string()),
                updated_at: "3".to_string(),
            })
            .unwrap();
    }

    fn write_completed_fix_run_summary(
        workspace: &kuzushi_core::WorkspaceTarget,
        attempt_run_id: &str,
        attempt_tool: &str,
    ) {
        let mut summary = kuzushi_core::RunSummary::running(
            attempt_run_id,
            "tool",
            Some(attempt_tool.to_string()),
            workspace.root().display().to_string(),
        );
        summary.status = "complete".to_string();
        summary.completed_at_unix = Some(summary.started_at_unix);
        kuzushi_core::write_run_summary(workspace.root(), &summary).unwrap();
    }

    fn append_fix_result_attempt(
        workspace: &kuzushi_core::WorkspaceTarget,
        attempt_run_id: &str,
    ) -> String {
        use kuzushi_core::workflow_attempts::{
            append_phase_attempt_completed, PhaseAttemptCompleted, PhaseAttemptOutcome,
            PhaseTargetSnapshot,
        };

        let completed = PhaseAttemptCompleted::new(
            WorkflowPhase::Fix,
            vec![attempt_run_id.to_string()],
            PhaseTargetSnapshot::capture(workspace.root()),
            PhaseAttemptOutcome::Completed,
        )
        .with_receipt(fix_result_receipt());
        let attempt_id = completed.attempt_id.clone();
        append_phase_attempt_completed(workspace.root(), completed).unwrap();
        attempt_id
    }

    fn fix_result_receipt() -> kuzushi_core::workflow_attempts::PhaseAttemptReceipt {
        use kuzushi_core::workflow_attempts::{PhaseAttemptReceipt, PhaseResultAction};

        PhaseAttemptReceipt {
            run_count: 1,
            elapsed_secs: 1,
            cost: "$0.0000".to_string(),
            changed_findings: 0,
            changed_artifacts: Vec::new(),
            interaction_count: 0,
            rerun_specification: None,
            actions: vec![
                PhaseResultAction::Select,
                PhaseResultAction::Open,
                PhaseResultAction::Refine,
                PhaseResultAction::Regenerate,
                PhaseResultAction::Discard,
            ],
            recommended_next: Some(
                "review the candidate; Apply remains separately authorized".to_string(),
            ),
        }
    }

    fn restart_fix_result_app(target: &std::path::Path) -> ShellApp {
        let workspace = kuzushi_core::WorkspaceTarget::new(target).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings(false);
        app.refresh_phase_attempt_projection();
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Fix));
        app.set_input_mode(InputMode::Navigate);
        let finding = app
            .findings()
            .iter()
            .find(|finding| finding.file_path == "src/auth.rs")
            .cloned()
            .unwrap();
        app.set_selected_finding(Some(finding.clone()));
        let target_revision = app
            .engagement
            .phase_target_snapshot()
            .and_then(|snapshot| snapshot.revision.clone());
        app.hydrate_view_keys_blocking(
            workspace.root(),
            vec![
                ViewHydrationKey::RunSummaryEntries,
                ViewHydrationKey::FindingPatchTruth {
                    fingerprint: finding.fingerprint,
                    finding_scan_id: finding.scan_id,
                    target_revision,
                },
            ],
        );
        app
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
        assert_eq!(app.autonomy(), AutonomyPosture::Scan);
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
        app.set_autonomy(AutonomyPosture::Scan);
        app.reduce_key(plain_key(KeyCode::Up));
        assert_eq!(app.autonomy(), AutonomyPosture::Scan);
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
    fn descriptor_confirm_consumes_shift_y_without_resolving() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(pending_descriptor_confirm());

        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('Y'), KeyModifiers::SHIFT));

        assert!(update.handled);
        assert!(update.effects.is_empty());
        assert!(app.advisory().pending_confirm.is_some());
        assert!(app.engagement.confirm_allowlist().is_empty());
    }

    #[test]
    fn descriptor_confirm_keeps_once_allow_and_remembered_deny() {
        let mut allowed = ShellApp::new(V2Config::default(), None);
        allowed.advisory_mut().pending_confirm = Some(pending_descriptor_confirm());
        let allow = allowed.reduce_key(plain_key(KeyCode::Char('y')));
        assert!(allow.handled);
        assert!(allowed.advisory().pending_confirm.is_none());
        assert!(allowed.engagement.confirm_allowlist().is_empty());

        let mut denied = ShellApp::new(V2Config::default(), None);
        denied.advisory_mut().pending_confirm = Some(pending_descriptor_confirm());
        let deny = denied.reduce_key(KeyEvent::new(KeyCode::Char('N'), KeyModifiers::SHIFT));
        assert!(deny.handled);
        assert!(denied.advisory().pending_confirm.is_none());
        assert!(denied
            .engagement
            .confirm_denylist()
            .contains("recon:nmap 127.0.0.1"));
    }

    #[test]
    fn pending_confirm_owns_unrelated_keys_before_composer() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(pending_network_confirm());
        app.editor_mut()
            .replace_command_history(vec!["prior command".to_string()]);
        app.set_input("existing draft");

        for key in [
            plain_key(KeyCode::Char('a')),
            KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT),
            KeyEvent::new(KeyCode::Char('!'), KeyModifiers::SHIFT),
            plain_key(KeyCode::Char('界')),
            plain_key(KeyCode::Char(' ')),
            plain_key(KeyCode::Tab),
            plain_key(KeyCode::Backspace),
            plain_key(KeyCode::Left),
            plain_key(KeyCode::Right),
            plain_key(KeyCode::Up),
            plain_key(KeyCode::Down),
        ] {
            let update = app.reduce_key(key);
            assert!(update.handled);
            assert_eq!(app.input(), "existing draft");
            assert!(app.advisory().pending_confirm.is_some());
        }
    }

    #[test]
    fn pending_confirm_still_yields_ctrl_c_to_the_global_quit_chord() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(pending_network_confirm());
        app.set_input("existing draft");

        let update = app.reduce_key(ctrl_key(KeyCode::Char('c')));

        assert!(update.handled);
        assert!(app.ctrl_c_armed());
        assert_eq!(app.input(), "existing draft");
        assert!(app.advisory().pending_confirm.is_some());
    }

    #[test]
    fn pending_confirm_consumes_ctrl_modified_uppercase_choices() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(pending_network_confirm());

        let update = app.handle_confirm_key(KeyEvent::new(
            KeyCode::Char('Y'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ));

        assert!(update.handled);
        assert!(app.advisory().pending_confirm.is_some());
        assert!(app.engagement.confirm_allowlist().is_empty());
        assert!(app.engagement.confirm_denylist().is_empty());
    }

    #[test]
    fn scan_and_review_result_keys_match_the_typed_action_contract() {
        use kuzushi_core::workflow_attempts::PhaseAttemptOutcome::{Completed, Failed};
        assert!(phase_result_command_allowed(
            &completed_phase_attempt(WorkflowPhase::Scan, Completed),
            PhaseResultCommand::RunAgain
        ));
        assert!(!phase_result_command_allowed(
            &completed_phase_attempt(WorkflowPhase::Review, Completed),
            PhaseResultCommand::RunAgain
        ));
        assert!(phase_result_command_allowed(
            &completed_phase_attempt(WorkflowPhase::Review, Completed),
            PhaseResultCommand::Regenerate
        ));
        assert!(!phase_result_command_allowed(
            &completed_phase_attempt(WorkflowPhase::Scan, Failed),
            PhaseResultCommand::Select
        ));
    }

    #[test]
    fn prove_and_fix_result_keys_match_the_typed_action_contract() {
        use kuzushi_core::workflow_attempts::PhaseAttemptOutcome::{Completed, Failed};
        assert!(!phase_result_command_allowed(
            &completed_phase_attempt(WorkflowPhase::Prove, Completed),
            PhaseResultCommand::Discard
        ));
        assert!(phase_result_command_allowed(
            &completed_phase_attempt(WorkflowPhase::Scan, Failed),
            PhaseResultCommand::Discard
        ));
        assert!(!phase_result_command_allowed(
            &completed_phase_attempt(WorkflowPhase::Fix, Completed),
            PhaseResultCommand::Continue
        ));
    }

    fn assert_verified_fix_result_card(app: &ShellApp, expected_attempt_id: &str) {
        use kuzushi_core::workflow_attempts::PhaseResultAction;

        let model = crate::ui_view_models::phase_cockpit_model_for_phase(app, WorkflowPhase::Fix);
        let card = model.header.result_card.expect("unresolved Fix result");
        let crate::ui_view_models::PhaseCockpitBody::Fix(fix) = model.body else {
            panic!("expected Fix body");
        };
        assert_eq!(card.attempt_id, expected_attempt_id);
        assert_eq!(
            fix.remediation.stage,
            crate::ui_view_models::RemediationLifecycleStage::Verified
        );
        assert_eq!(
            card.actions,
            vec![
                PhaseResultAction::Select,
                PhaseResultAction::Open,
                PhaseResultAction::RunAgain,
                PhaseResultAction::Discard,
            ]
        );
        assert!(card.control_hint.contains("u Acknowledge verified"));
        assert!(!card.control_hint.contains("Select patch"));
        assert!(!card.control_hint.contains("Refine"));
        assert_eq!(
            card.recommended,
            "re-verification passed; acknowledge this verified remediation"
        );
    }

    fn select_unrelated_fix_finding(app: &mut ShellApp) {
        let unrelated = app
            .findings()
            .iter()
            .find(|finding| finding.file_path == "src/unrelated.rs")
            .cloned()
            .unwrap();
        app.set_selected_finding(Some(unrelated));
    }

    #[test]
    fn restart_projects_matching_verified_reverify_as_acknowledgement() {
        let fixture = seed_verified_fix_result(
            "reverify-result-run",
            "patch:reverify",
            "reverify-result-run",
        );
        let mut app = restart_fix_result_app(fixture.target.path());
        assert_verified_fix_result_card(&app, &fixture.attempt_id);
        select_unrelated_fix_finding(&mut app);
        assert_verified_fix_result_card(&app, &fixture.attempt_id);

        let update = app.reduce_key(plain_key(KeyCode::Char('f')));
        assert!(update.handled);
        assert!(app.input().is_empty());
        assert!(app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Fix)
            .is_some());
        drop(app);

        let mut restarted = restart_fix_result_app(fixture.target.path());
        let update = restarted.reduce_key(plain_key(KeyCode::Char('u')));
        assert!(update.handled);
        assert!(restarted
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Fix)
            .is_none());
        assert!(restarted.engagement.pending_patch().is_none());
    }

    #[test]
    fn unrelated_verified_lifecycle_does_not_relabel_a_patch_candidate() {
        let fixture = seed_verified_fix_result(
            "patch-candidate-result",
            "patch:finding",
            "different-reverify-run",
        );
        let app = restart_fix_result_app(fixture.target.path());
        let card = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Fix)
            .header
            .result_card
            .expect("unresolved Fix result");

        assert!(card.control_hint.contains("u Select patch"));
        assert!(card.control_hint.contains("f Refine"));
        assert!(!card.control_hint.contains("Acknowledge verified"));
        assert_eq!(
            card.recommended,
            "review the candidate; Apply remains separately authorized"
        );
        assert!(app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Fix)
            .is_some());
    }

    #[test]
    fn non_reverify_run_cannot_inherit_a_matching_verified_lifecycle_id() {
        let fixture = seed_verified_fix_result(
            "mismatched-tool-run",
            "patch:finding",
            "mismatched-tool-run",
        );
        let app = restart_fix_result_app(fixture.target.path());
        let card = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Fix)
            .header
            .result_card
            .expect("unresolved Fix result");

        assert!(card.control_hint.contains("u Select patch"));
        assert!(!card.control_hint.contains("Acknowledge verified"));
        assert_eq!(
            card.recommended,
            "review the candidate; Apply remains separately authorized"
        );
    }

    #[test]
    fn restored_receipt_actions_override_legacy_phase_key_guesses() {
        use kuzushi_core::workflow_attempts::{
            PhaseAttemptCompleted, PhaseAttemptOutcome, PhaseAttemptReceipt, PhaseResultAction,
            PhaseTargetSnapshot,
        };
        let completed = PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["scan-run".to_string()],
            PhaseTargetSnapshot {
                target: "/target".to_string(),
                revision: None,
                dirty: false,
            },
            PhaseAttemptOutcome::Completed,
        )
        .with_receipt(PhaseAttemptReceipt {
            run_count: 1,
            elapsed_secs: 1,
            cost: "cost unavailable".to_string(),
            changed_findings: 0,
            changed_artifacts: Vec::new(),
            interaction_count: 0,
            rerun_specification: None,
            actions: vec![PhaseResultAction::Open],
            recommended_next: None,
        });

        assert!(phase_result_command_allowed(
            &completed,
            PhaseResultCommand::Open
        ));
        assert!(!phase_result_command_allowed(
            &completed,
            PhaseResultCommand::RunAgain
        ));
    }

    #[test]
    fn remapped_phase_result_key_replaces_the_default_in_dispatch() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "phase_result".to_string(),
            action: "select".to_string(),
            bindings: vec!["x".to_string()],
        }];
        let (_target, mut app, _attempt_id) = app_with_unresolved_map_result(config);

        assert!(app.reduce_key(plain_key(KeyCode::Char('u'))).handled);
        assert!(app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Map)
            .is_some());
        assert!(app.reduce_key(plain_key(KeyCode::Char('x'))).handled);
        assert!(app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Map)
            .is_none());
    }

    #[test]
    fn phase_result_escape_returns_to_prompt_without_resolving_the_result() {
        let (_target, mut app, attempt_id) = app_with_unresolved_map_result(V2Config::default());

        assert!(app.reduce_key(plain_key(KeyCode::Esc)).handled);
        assert_eq!(app.input_mode(), InputMode::Prompt);
        assert_eq!(
            app.engagement
                .unresolved_phase_attempt(WorkflowPhase::Map)
                .map(|record| record.completed.attempt_id.as_str()),
            Some(attempt_id.as_str())
        );
    }

    #[test]
    fn remapped_prompt_mode_escapes_phase_result_without_resolving_it() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "composer".to_string(),
            action: "prompt_mode".to_string(),
            bindings: vec!["x".to_string()],
        }];
        let (_target, mut app, attempt_id) = app_with_unresolved_map_result(config);

        assert!(app.reduce_key(plain_key(KeyCode::Esc)).handled);
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert!(app.reduce_key(plain_key(KeyCode::Char('a'))).handled);
        assert!(app.input().is_empty());
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert!(app.reduce_key(plain_key(KeyCode::Char('x'))).handled);
        assert_eq!(app.input_mode(), InputMode::Prompt);
        assert_eq!(
            app.engagement
                .unresolved_phase_attempt(WorkflowPhase::Map)
                .map(|record| record.completed.attempt_id.as_str()),
            Some(attempt_id.as_str())
        );
    }

    #[test]
    fn remapped_prompt_mode_key_only_owns_input_while_navigating() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "composer".to_string(),
            action: "prompt_mode".to_string(),
            bindings: vec!["x".to_string()],
        }];
        let mut app = ShellApp::new(config, None);
        app.set_shell_view(ShellView::Workbench);
        app.set_input_mode(InputMode::Navigate);

        assert!(app.reduce_key(plain_key(KeyCode::Char('x'))).handled);
        assert_eq!(app.input_mode(), InputMode::Prompt);
        for ch in "maxIterations".chars() {
            assert!(app.reduce_key(plain_key(KeyCode::Char(ch))).handled);
        }
        assert_eq!(app.input(), "maxIterations");
    }

    #[test]
    fn inactive_prompt_mode_chord_prefix_remains_editable_text() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "composer".to_string(),
            action: "prompt_mode".to_string(),
            bindings: vec!["x y".to_string()],
        }];
        let mut app = ShellApp::new(config, None);
        app.set_shell_view(ShellView::Workbench);
        app.set_input_mode(InputMode::Prompt);

        assert!(app.reduce_key(plain_key(KeyCode::Char('x'))).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Char('y'))).handled);
        assert_eq!(app.input(), "xy");
    }

    #[test]
    fn selecting_proof_materializes_reality_and_restart_reconstructs_fix() {
        let mut fixture = proof_selection_fixture("tool-proof-selection-restart");
        assert_eq!(journey_phase(&fixture.app), Some(WorkflowPhase::Prove));

        assert!(
            fixture
                .app
                .reduce_key(plain_key(KeyCode::Char('u')))
                .handled
        );
        assert!(fixture
            .app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Prove)
            .is_none());
        assert_eq!(journey_phase(&fixture.app), Some(WorkflowPhase::Fix));

        let mut restarted = ShellApp::new(V2Config::default(), Some(&fixture.workspace));
        restarted.refresh_findings(false);
        assert_eq!(journey_phase(&restarted), Some(WorkflowPhase::Fix));
        assert_selected_proof_persisted(&fixture);
    }

    #[test]
    fn blocked_proof_selection_is_visible_and_keeps_reality_unresolved() {
        let mut fixture = proof_selection_fixture("tool-proof-selection-tampered");
        let result_path = kuzushi_core::run_artifacts::run_artifact_path(
            fixture.workspace.root(),
            fixture.run_id,
            "result.json",
        );
        std::fs::write(result_path, "{\"ok\":true,\"status\":\"completed\"}").unwrap();

        assert!(
            fixture
                .app
                .reduce_key(plain_key(KeyCode::Char('u')))
                .handled
        );
        let notice = fixture
            .app
            .advisory()
            .notice
            .as_ref()
            .expect("visible error");
        assert_eq!(notice.severity, crate::NoticeSeverity::Error);
        assert_eq!(notice.source, "workbench");
        assert!(notice.message.contains("Prove selection blocked:"));
        assert!(notice.message.contains("result digest does not match"));
        assert!(fixture
            .app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Prove)
            .is_some());
        assert_selection_left_no_durable_mutation(&fixture);
    }

    struct ProofSelectionFixture {
        _target: tempfile::TempDir,
        workspace: kuzushi_core::WorkspaceTarget,
        finding: kuzushi_core::Finding,
        run_id: &'static str,
        attempt_id: String,
        app: ShellApp,
    }

    fn proof_selection_fixture(run_id: &'static str) -> ProofSelectionFixture {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        workspace.ensure_state_dir().unwrap();
        let finding = seed_current_proof_finding(&workspace);
        record_test_model_proof(&workspace, run_id, &finding);
        let attempt_id = append_unresolved_proof_attempt(&workspace, run_id);
        let app = unresolved_proof_app(&workspace);
        ProofSelectionFixture {
            _target: target,
            workspace,
            finding,
            run_id,
            attempt_id,
            app,
        }
    }

    fn seed_current_proof_finding(
        workspace: &kuzushi_core::WorkspaceTarget,
    ) -> kuzushi_core::Finding {
        use kuzushi_core::{Finding, FindingStore, Severity, TriageOutcome, TriageVerdict};
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("scan-current", workspace.root(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "proof-test",
            "proof-test/rule",
            "src/main.rs",
            1,
            None,
            Severity::High,
            "proof candidate",
        );
        let finding_id = store.insert_finding("scan-current", &finding).unwrap();
        store
            .record_auto_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 1.0,
                    rationale: "confirmed".to_string(),
                    ..TriageOutcome::default()
                },
            )
            .unwrap();
        store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap()
    }

    fn append_unresolved_proof_attempt(
        workspace: &kuzushi_core::WorkspaceTarget,
        run_id: &str,
    ) -> String {
        use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;
        let completed = crate::test_support::append_typed_attempt(
            workspace.root(),
            WorkflowPhase::Prove,
            run_id,
            PhaseAttemptOutcome::Completed,
        );
        completed.attempt_id.clone()
    }

    fn unresolved_proof_app(workspace: &kuzushi_core::WorkspaceTarget) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), Some(workspace));
        app.refresh_findings(false);
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Prove));
        app.set_input_mode(InputMode::Navigate);
        app
    }

    fn journey_phase(app: &ShellApp) -> Option<WorkflowPhase> {
        match crate::ui_view_models::journey_model(app)?.destination {
            crate::ui_view_models::JourneyDestination::Phase(phase) => Some(phase),
            crate::ui_view_models::JourneyDestination::Report(_) => None,
        }
    }

    fn assert_selected_proof_persisted(fixture: &ProofSelectionFixture) {
        let restored = kuzushi_core::FindingStore::open(fixture.workspace.findings_db_path())
            .unwrap()
            .get_finding_by_fingerprint(&fixture.finding.fingerprint)
            .unwrap()
            .unwrap();
        let proof = restored.verification.unwrap();
        assert_eq!(proof.verification_run_id.as_deref(), Some(fixture.run_id));
        assert_eq!(proof.verified_scan_id.as_deref(), Some("scan-current"));
    }

    fn assert_selection_left_no_durable_mutation(fixture: &ProofSelectionFixture) {
        let recovered = kuzushi_core::workflow_attempts::load_phase_attempt_ledger_recovering(
            fixture.workspace.root(),
        )
        .unwrap();
        assert!(recovered.is_degraded());
        let ledger = recovered.ledger;
        assert!(ledger
            .attempt(&fixture.attempt_id)
            .is_some_and(|record| record.disposition.is_none()));
        let restored = kuzushi_core::FindingStore::open(fixture.workspace.findings_db_path())
            .unwrap()
            .get_finding_by_fingerprint(&fixture.finding.fingerprint)
            .unwrap()
            .unwrap();
        assert!(restored.verification.is_none());
    }

    fn record_test_model_proof(
        workspace: &kuzushi_core::WorkspaceTarget,
        run_id: &str,
        finding: &kuzushi_core::Finding,
    ) {
        let candidate = serde_json::json!({
            "fingerprint": finding.fingerprint.clone(),
            "verifiedScanId": "scan-current",
            "identityId": finding.identity_id.clone(),
            "exploitable": true,
            "confidence": 0.99,
            "proofLevel": 3,
            "proofVerdict": "exploited"
        });
        let mut data = candidate.clone();
        data["verification"] = candidate.clone();
        data["proof"] = candidate.clone();
        crate::test_support::record_indexed_run_with_input(
            workspace.root(),
            run_id,
            "verify:finding",
            serde_json::json!({"fingerprint": finding.fingerprint.clone()}),
            serde_json::json!({
                "ok": true,
                "status": "completed",
                "summary": "verify:finding complete (VULNERABLE)",
                "output": "verified",
                "data": data,
                "proof": candidate,
                "errors": [],
                "warnings": [],
                "artifacts": [],
                "costUsd": 0.125
            }),
        );
    }

    #[test]
    fn phase_rerun_actions_preserve_the_derivation_label() {
        use kuzushi_core::workflow_attempts::PhaseAttemptDerivation::{
            Original, Refine, Regenerate,
        };

        assert_eq!(phase_rerun_action(None), "run again");
        assert_eq!(phase_rerun_action(Some(Original)), "run again");
        assert_eq!(phase_rerun_action(Some(Refine)), "refine");
        assert_eq!(phase_rerun_action(Some(Regenerate)), "regenerate");
    }
}
