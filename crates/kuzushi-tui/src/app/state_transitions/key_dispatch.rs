use super::confirmation_keys::{
    confirm_key_action, confirm_key_modifiers_allowed, ConfirmKeyAction,
};
use super::control_keys::control_key_action;
use super::*;
use anyhow::Context;
use kuzushi_core::modules::OptionType;
use serde_json::Value;

#[derive(Clone, Copy)]
enum JourneyPhaseEntry {
    Workbench,
    Planner,
}

impl ShellApp {
    pub(crate) fn reduce_key(&mut self, key: KeyEvent) -> InputUpdate {
        if key.kind != KeyEventKind::Press {
            return InputUpdate::ignored();
        }
        let key = normalize_terminal_key_encoding(key);
        let update = self.reduce_key_without_recording(key);
        if update.handled {
            self.record_operator_interaction();
        }
        update
    }

    fn reduce_key_without_recording(&mut self, key: KeyEvent) -> InputUpdate {
        self.expire_resolved_result_key(key);
        if let Some(update) = self.reduce_owned_key(key) {
            return update;
        }

        if self.handle_story_toggle_key(key) {
            return InputUpdate::handled();
        }

        self.reduce_non_modal_key(key)
    }

    fn reduce_owned_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.editor_mut().handle_paste_inspection_key(key) {
            return Some(InputUpdate::handled());
        }
        let budget_update = self.handle_budget_key(key);
        if budget_update.handled {
            return Some(budget_update);
        }
        if let Some(update) = self.reduce_modal_key(key) {
            return Some(update);
        }
        None
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
        if let Some(update) = self.handle_answer_key(key) {
            return Some(update);
        }
        if let Some(update) = self.handle_autonomy_key(key, modifiers) {
            return Some(update);
        }

        self.reduce_phase_result_or_shell_key(key)
    }

    fn reduce_phase_result_or_shell_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if let Some(update) = self.reduce_on_screen_phase_result_key(key) {
            return Some(update);
        }

        self.reduce_configured_shell_or_mode_cycle(key)
    }

    fn reduce_on_screen_phase_result_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let update = self
            .reduce_configured_phase_result_key(key)
            .or_else(|| self.reduce_default_phase_result_key(key))?;
        self.settle_claimed_phase_result_key(key);
        Some(update)
    }

    fn reduce_configured_phase_result_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.input_mode() != InputMode::Navigate {
            return None;
        }
        self.handle_configured_phase_result_key(key)
    }

    fn reduce_default_phase_result_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.input_mode() != InputMode::Navigate {
            return None;
        }
        self.handle_phase_result_key(key)
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
        if self.handle_threat_tab_digit_key(key) {
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
        if self.input_mode() != InputMode::Navigate
            || !self.phase_result_is_open()
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
        Some(if self.phase_result_command_is_available(command) {
            self.apply_phase_result_command(command)
        } else {
            InputUpdate::handled()
        })
    }

    fn handle_configured_phase_result_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.input_mode() != InputMode::Navigate || !self.phase_result_is_open() {
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
        if self.shell_view() != ShellView::Workbench {
            return false;
        }
        self.phase_result_target_phase().is_some()
    }

    /// Phase whose unresolved RESULT READY attempt the result-card keys act
    /// on. Prefer the page in view; when reality derivation has moved the
    /// page away from the phase that actually finished (e.g. a Map result
    /// while prior findings derive Review), fall back to the earliest phase
    /// with an unresolved attempt — advertised keys must work where
    /// advertised.
    pub(crate) fn phase_result_target_phase(&self) -> Option<WorkflowPhase> {
        if self.prove_detail_owns_controls() {
            return None;
        }
        let page_phase = crate::ui_view_models::active_workbench_page(self).phase();
        if self
            .engagement
            .unresolved_phase_attempt(page_phase)
            .is_some()
        {
            return Some(page_phase);
        }
        WorkflowPhase::INVESTIGATION_ORDER
            .iter()
            .copied()
            .find(|phase| self.engagement.unresolved_phase_attempt(*phase).is_some())
    }

    fn phase_result_command_is_available(&self, command: PhaseResultCommand) -> bool {
        let Some(phase) = self.phase_result_target_phase() else {
            return false;
        };
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
            PhaseResultCommand::ContinueRun => self.continue_phase_result_run(),
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

    /// `c` on a failed result: resume the recorded run from its checkpoint
    /// via the shared `resume` mechanics (new run id, identical input; the
    /// dispatch boundary rediscovers the checkpoint automatically).
    fn continue_phase_result_run(&mut self) -> InputUpdate {
        let Some(phase) = self.phase_result_target_phase() else {
            return InputUpdate::handled();
        };
        let Some(record) = self.engagement.unresolved_phase_attempt(phase).cloned() else {
            return InputUpdate::handled();
        };
        let Some(run_id) = self.continuable_failed_run(&record.completed) else {
            self.refuse_phase_result_action(
                "no resumable checkpoint found for this attempt — use r to run again",
            );
            return InputUpdate::handled();
        };
        let effects = self.resume_session_effect(crate::app::ResumeSession {
            run_id: Some(run_id),
            from_start: false,
        });
        InputUpdate::handled_with_effects(effects)
    }

    fn record_phase_result_selection(&mut self, continue_after: bool) -> InputUpdate {
        use kuzushi_core::workflow_attempts::{
            PhaseAttemptDisposition, PhaseAttemptDispositionRecorded, PhaseAttemptOutcome,
        };
        let Some((phase, record)) = self.current_phase_result_selection() else {
            return InputUpdate::handled();
        };
        let Some(selected_fix_patch) = self.prepare_phase_result_selection(phase, &record) else {
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

    fn current_phase_result_selection(
        &mut self,
    ) -> Option<(
        WorkflowPhase,
        kuzushi_core::workflow_attempts::PhaseAttemptRecord,
    )> {
        let phase = self.phase_result_target_phase()?;
        let attempt_id = self
            .engagement
            .unresolved_phase_attempt(phase)?
            .completed
            .attempt_id
            .clone();
        self.refresh_phase_attempt_projection();
        let record = self
            .engagement
            .unresolved_phase_attempt_by_id(phase, &attempt_id)?
            .clone();
        if let Some(reason) = self.effective_phase_attempt_blocker(&record.completed) {
            self.refuse_phase_result_action(reason);
            return None;
        }
        Some((phase, record))
    }

    fn prepare_phase_result_selection(
        &mut self,
        phase: WorkflowPhase,
        record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
    ) -> Option<Option<crate::PendingPatch>> {
        if !self.materialize_phase_result_reality(phase, record) {
            return None;
        }
        self.phase_result_selection_patch(phase, record)
    }

    /// A refused result-card action leaves the card exactly as it was, so a
    /// transcript line under any other prefix cannot tell the operator their
    /// keypress was read at all. `log("error", ..)` is what already raises the
    /// Workbench banner, and result-card keys only dispatch on the Workbench,
    /// so every refusal here can reach it.
    fn refuse_phase_result_action(&mut self, reason: impl Into<String>) {
        self.log("error", reason);
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
            self.refuse_phase_result_action("Prove selection requires an active target");
            return false;
        };
        match self.materialize_selected_proof(&target, record) {
            Ok(()) => true,
            Err(error) => {
                self.refuse_phase_result_action(format!("Prove selection blocked: {error}"));
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
        self.reset_map_gallery_after_selection(phase);
        self.log(
            "workflow",
            format!(
                "selected {} attempt {}",
                phase.label(),
                record.completed.attempt_id
            ),
        );
        self.remember_selected_fix_patch(selected_fix_patch);
        if self.finish_guided_result_selection(phase, continue_after) {
            return;
        }
        if continue_after {
            self.open_rederived_journey_destination();
        }
    }

    fn reset_map_gallery_after_selection(&mut self, phase: WorkflowPhase) {
        if phase == WorkflowPhase::Map {
            let scene = self.router.scene_mut();
            scene.set_page(crate::scene3d::VizPage::Summary);
            scene.reset_summary_navigation();
        }
    }

    fn remember_selected_fix_patch(&mut self, patch: Option<PendingPatch>) {
        if let Some(patch) = patch {
            self.engagement.set_pending_patch(patch);
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
        let Some(target) = self.target_owned() else {
            self.refuse_phase_result_action(
                "Fix selection blocked: no active target — reopen the engagement against its target",
            );
            return None;
        };
        let workspace = match kuzushi_core::WorkspaceTarget::new(&target) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.refuse_phase_result_action(format!("Fix selection blocked: {error}"));
                return None;
            }
        };
        match validate_fix_attempt_candidate(&workspace, record) {
            Ok(patch) => Some(patch),
            Err(error) => {
                self.refuse_phase_result_action(format!("Fix selection blocked: {error}"));
                None
            }
        }
    }

    fn discard_phase_result(&mut self) -> InputUpdate {
        use kuzushi_core::workflow_attempts::{
            PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
        };
        let Some(phase) = self.phase_result_target_phase() else {
            return InputUpdate::handled();
        };
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
            self.refuse_phase_result_action("phase result requires an active target");
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
                self.refuse_phase_result_action(format!(
                    "phase result could not be recorded: {error}"
                ));
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
        let phase = self.phase_result_target_phase()?;
        self.engagement.unresolved_phase_attempt(phase).cloned()
    }

    fn open_phase_result_runs(&mut self) -> InputUpdate {
        let Some(record) = self.current_phase_result_record() else {
            return InputUpdate::handled();
        };
        let Some(run_id) = record.completed.run_refs.last().cloned() else {
            // Unreachable today: `validate_completed` rejects an empty
            // `run_refs` on append and again on every ledger load, so no
            // attempt reaches this code without one. Kept on the same helper
            // as the reachable refusals so the invariant holds uniformly if
            // that ever changes.
            self.refuse_phase_result_action("phase attempt has no canonical run reference");
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

    /// The tool and input an exact rerun would replay, taken from the latest
    /// referenced run that still has both. Refuses out loud, because `r` is
    /// advertised on the card whether or not a rerun can be reconstructed.
    fn rerun_specification_for(
        &mut self,
        record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
    ) -> Option<(String, Value)> {
        let Some(target) = self.target_owned() else {
            self.refuse_phase_result_action("rerun requires an active target");
            return None;
        };
        let specification = record
            .completed
            .run_refs
            .iter()
            .rev()
            .find_map(|run_id| rerun_specification(self.registry(), &target, run_id));
        if specification.is_none() {
            // `rerun_specification` also refuses a run whose tool is no longer
            // loaded, so the message names both halves of what it needs.
            self.refuse_phase_result_action(
                "exact rerun unavailable — no referenced run has a readable input for a loaded tool",
            );
        }
        specification
    }

    fn phase_rerun_draft(
        &mut self,
        derivation: Option<kuzushi_core::workflow_attempts::PhaseAttemptDerivation>,
    ) -> Option<PhaseRerunDraft> {
        let record = self.current_phase_result_record()?;
        let (tool, input) = self.rerun_specification_for(&record)?;
        let overrides = phase_rerun_action_overrides(derivation, &tool);
        let prepared_input = self.phase_rerun_draft_input(&tool, input.clone(), overrides)?;
        let descriptor = self.registry().resolve_tool(&tool)?;
        Some(PhaseRerunDraft {
            review: PhaseRerunReview {
                phase: record.completed.phase,
                parent_attempt_id: record.completed.attempt_id,
                tool: tool.clone(),
                tool_description: descriptor.description.clone(),
                changed_options: rerun_option_review(descriptor, &prepared_input, overrides),
                original_input: input.clone(),
                draft_modified: prepared_input != input,
                prepared_input,
                option_editor_open: false,
                option_cursor: 0,
                option_edit: None,
                option_error: None,
                dispatch_error: None,
                derivation,
            },
            derivation,
        })
    }

    /// Resolves the input the review will show, announcing why a draft could
    /// not be opened instead of leaving the operator with an unexplained
    /// no-op on the result card.
    fn phase_rerun_draft_input(
        &mut self,
        tool: &str,
        input: Value,
        overrides: &[(&str, &str)],
    ) -> Option<Value> {
        let workspace = match self.phase_rerun_workspace() {
            Ok(workspace) => workspace,
            Err(reason) => {
                self.refuse_phase_result_action(format!("rerun draft not opened — {reason}"));
                return None;
            }
        };
        match self.prepare_phase_rerun_review_input(tool, input, overrides, &workspace) {
            Ok(prepared) => Some(prepared),
            Err(error) => {
                self.refuse_phase_result_action(format!("rerun input is invalid: {error}"));
                None
            }
        }
    }

    fn prepare_phase_rerun_review_input(
        &self,
        tool: &str,
        input: Value,
        overrides: &[(&str, &str)],
        workspace: &WorkspaceTarget,
    ) -> anyhow::Result<Value> {
        let candidate = input_with_phase_rerun_overrides(input, overrides)?;
        self.prepare_phase_rerun_input(tool, candidate, workspace)
    }

    fn prepare_phase_rerun_input(
        &self,
        tool: &str,
        input: Value,
        workspace: &WorkspaceTarget,
    ) -> anyhow::Result<Value> {
        let ctx = kuzushi_core::modules::ToolExecutionContext {
            config: self.config(),
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        self.registry().prepare_tool_input_for_dispatch(
            tool,
            input,
            &ctx,
            Some(self.option_store()),
        )
    }

    fn apply_phase_rerun_draft(&mut self, draft: PhaseRerunDraft) {
        self.engagement.set_pending_phase_rerun(draft.review);
        self.log(
            "workflow",
            format!(
                "{} review opened from saved run input · Enter dispatches the draft; e edits rerun options",
                phase_rerun_action(draft.derivation)
            ),
        );
    }

    fn handle_mode_or_control_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if let Some(update) = self.handle_terminal_run_focus_leave_key(key) {
            return update;
        }
        if self.composer_mode_toggle_is_visible() && self.handle_input_mode_key(key, modifiers) {
            return InputUpdate::handled();
        }
        self.handle_control_key(key, modifiers)
    }

    fn handle_terminal_run_focus_leave_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.composer_mode_toggle_is_visible() {
            return None;
        }
        let back = self
            .view_keybindings()
            .into_iter()
            .find(|binding| binding.action == ViewHotkeyAction::Back && binding.matches(key))?;
        Some(self.apply_view_hotkey(back.action))
    }

    /// Terminal Run Focus renders no composer row, so its mode toggle is
    /// invisible in both stored input modes. Its configured Back key leaves
    /// directly; a live run keeps the toggle while `Ctrl+C` cancels and `b`
    /// backgrounds it.
    fn composer_mode_toggle_is_visible(&self) -> bool {
        self.shell_view() != ShellView::Activity
            || !crate::ui_view_models::run_focus_is_terminal(self)
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
        let cursor_update = self.handle_cursor_key(key, modifiers);
        if cursor_update.handled {
            return cursor_update;
        }
        if self.handle_history_key(key, modifiers) {
            return InputUpdate::handled();
        }
        self.handle_text_key(key)
    }

    fn reduce_navigate_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> InputUpdate {
        let update = self.handle_empty_input_view_key(key, modifiers);
        if update.handled {
            return update;
        }
        if let Some(update) = self.reduce_unclaimed_phase_result_key(key) {
            return update;
        }
        if let Some(update) = self.type_printable_navigate_key(key, modifiers) {
            return update;
        }
        InputUpdate::handled_if(self.handle_unhandled_navigation_key(key, modifiers))
    }

    /// An unclaimed plain printable key in Navigate starts typing a prompt.
    fn type_printable_navigate_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> Option<InputUpdate> {
        let KeyCode::Char(ch) = key.code else {
            return None;
        };
        if !modifiers.plain {
            return None;
        }
        self.enter_prompt_mode();
        self.insert_printable_key(ch);
        Some(InputUpdate::handled())
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
        if self.engagement.pending_phase_rerun().is_some() {
            return Some(self.handle_phase_rerun_review_key(key));
        }
        if self.advisory().pending_confirm.is_some() {
            return Some(self.handle_confirm_key(key));
        }
        if self.handle_contextual_surface_key(key) {
            return Some(InputUpdate::handled());
        }
        self.handle_modal_editor_key(key)
    }

    fn handle_phase_rerun_review_key(&mut self, key: KeyEvent) -> InputUpdate {
        if is_quit_chord(key) {
            return InputUpdate::ignored();
        }
        if self
            .engagement
            .pending_phase_rerun()
            .is_some_and(|review| review.option_editor_open)
        {
            return self.handle_phase_rerun_option_key(key);
        }
        self.handle_closed_phase_rerun_review_key(key)
    }

    fn handle_closed_phase_rerun_review_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !key.modifiers.is_empty() {
            return InputUpdate::handled();
        }
        match key.code {
            KeyCode::Enter => self.dispatch_phase_rerun_review(),
            KeyCode::Char('e') => self.edit_phase_rerun_review(),
            KeyCode::Esc => self.cancel_phase_rerun_review(),
            _ => InputUpdate::handled(),
        }
    }

    fn edit_phase_rerun_review(&mut self) -> InputUpdate {
        let option_count = self.phase_rerun_editable_options().len();
        if option_count == 0 {
            if let Some(review) = self.engagement.pending_phase_rerun_mut() {
                review.option_error =
                    Some("this saved run has no primitive editable options".to_string());
            }
            return InputUpdate::handled();
        }
        if let Some(review) = self.engagement.pending_phase_rerun_mut() {
            review.option_editor_open = true;
            review.option_cursor = review.option_cursor.min(option_count.saturating_sub(1));
            review.option_error = None;
        }
        InputUpdate::handled()
    }

    fn handle_phase_rerun_option_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.phase_rerun_text_edit_is_open() {
            return self.handle_phase_rerun_text_edit_key(key);
        }
        if !key.modifiers.is_empty() {
            return InputUpdate::handled();
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_phase_rerun_option_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_phase_rerun_option_cursor(1),
            KeyCode::Char(' ') => self.cycle_phase_rerun_option(),
            KeyCode::Enter => self.begin_phase_rerun_text_edit(),
            KeyCode::Esc => self.close_phase_rerun_option_editor(),
            _ => {}
        }
        InputUpdate::handled()
    }

    fn phase_rerun_text_edit_is_open(&self) -> bool {
        self.engagement
            .pending_phase_rerun()
            .is_some_and(|review| review.option_edit.is_some())
    }

    fn handle_phase_rerun_text_edit_key(&mut self, key: KeyEvent) -> InputUpdate {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            || key.modifiers.contains(KeyModifiers::ALT)
        {
            return InputUpdate::handled();
        }
        self.handle_phase_rerun_text_edit_code(key.code);
        InputUpdate::handled()
    }

    fn handle_phase_rerun_text_edit_code(&mut self, code: KeyCode) {
        match code {
            KeyCode::Enter => self.commit_phase_rerun_text_edit(),
            KeyCode::Esc => self.cancel_phase_rerun_text_edit(),
            KeyCode::Backspace => self.edit_phase_rerun_draft(|draft| {
                draft.pop();
            }),
            KeyCode::Char(ch) => self.edit_phase_rerun_draft(|draft| draft.push(ch)),
            _ => {}
        }
    }

    fn cancel_phase_rerun_text_edit(&mut self) {
        if let Some(review) = self.engagement.pending_phase_rerun_mut() {
            review.option_edit = None;
            review.option_error = None;
        }
    }

    fn edit_phase_rerun_draft(&mut self, edit: impl FnOnce(&mut String)) {
        let Some(draft) = self
            .engagement
            .pending_phase_rerun_mut()
            .and_then(|review| review.option_edit.as_mut())
            .map(|edit| &mut edit.draft)
        else {
            return;
        };
        edit(draft);
    }

    fn move_phase_rerun_option_cursor(&mut self, delta: isize) {
        let count = self.phase_rerun_editable_options().len();
        let Some(review) = self.engagement.pending_phase_rerun_mut() else {
            return;
        };
        if count == 0 {
            return;
        }
        review.option_cursor = review
            .option_cursor
            .saturating_add_signed(delta)
            .min(count - 1);
        review.option_error = None;
    }

    fn close_phase_rerun_option_editor(&mut self) {
        if let Some(review) = self.engagement.pending_phase_rerun_mut() {
            review.option_editor_open = false;
            review.option_edit = None;
            review.option_error = None;
        }
    }

    fn phase_rerun_editable_options(&self) -> Vec<kuzushi_core::modules::OptionSpec> {
        let Some(review) = self.engagement.pending_phase_rerun() else {
            return Vec::new();
        };
        self.registry()
            .resolve_tool(&review.tool)
            .map(|descriptor| {
                descriptor
                    .options
                    .iter()
                    .filter(|spec| crate::app::option_is_operator_editable(spec))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn selected_phase_rerun_option(&self) -> Option<kuzushi_core::modules::OptionSpec> {
        let cursor = self.engagement.pending_phase_rerun()?.option_cursor;
        self.phase_rerun_editable_options().get(cursor).cloned()
    }

    fn begin_phase_rerun_text_edit(&mut self) {
        let Some(spec) = self.selected_phase_rerun_option() else {
            return;
        };
        if matches!(spec.option_type, OptionType::Bool | OptionType::Enum) {
            self.cycle_phase_rerun_option();
            return;
        }
        let draft = self
            .engagement
            .pending_phase_rerun()
            .and_then(|review| review.prepared_input.get(&spec.name))
            .map(crate::app::format_option_value)
            .unwrap_or_default();
        if let Some(review) = self.engagement.pending_phase_rerun_mut() {
            review.option_edit = Some(PhaseRerunOptionEdit {
                option_name: spec.name,
                draft,
            });
            review.option_error = None;
        }
    }

    fn commit_phase_rerun_text_edit(&mut self) {
        let Some(edit) = self
            .engagement
            .pending_phase_rerun()
            .and_then(|review| review.option_edit.clone())
        else {
            return;
        };
        let Some(spec) = self
            .phase_rerun_editable_options()
            .into_iter()
            .find(|spec| spec.name == edit.option_name)
        else {
            return;
        };
        match crate::app::coerce_raw_option_value(&spec, &edit.draft)
            .and_then(|value| self.apply_phase_rerun_option(&spec, value))
        {
            Ok(()) => {
                if let Some(review) = self.engagement.pending_phase_rerun_mut() {
                    review.option_edit = None;
                    review.option_error = None;
                }
            }
            Err(error) => {
                if let Some(review) = self.engagement.pending_phase_rerun_mut() {
                    review.option_error = Some(error.to_string());
                }
            }
        }
    }

    fn cycle_phase_rerun_option(&mut self) {
        let Some(spec) = self.selected_phase_rerun_option() else {
            return;
        };
        let current = self
            .engagement
            .pending_phase_rerun()
            .and_then(|review| review.prepared_input.get(&spec.name));
        let next = match next_phase_rerun_option_value(&spec, current) {
            Ok(next) => next,
            Err(error) => {
                self.set_phase_rerun_option_error(error.to_string());
                return;
            }
        };
        if let Err(error) = self.apply_phase_rerun_option(&spec, next) {
            self.set_phase_rerun_option_error(error.to_string());
        }
    }

    fn set_phase_rerun_option_error(&mut self, error: String) {
        if let Some(review) = self.engagement.pending_phase_rerun_mut() {
            review.option_error = Some(error);
        }
    }

    fn apply_phase_rerun_option(
        &mut self,
        spec: &kuzushi_core::modules::OptionSpec,
        value: Value,
    ) -> anyhow::Result<()> {
        let review = self
            .engagement
            .pending_phase_rerun()
            .context("rerun draft is unavailable")?;
        let tool = review.tool.clone();
        let derivation = review.derivation;
        let original = review.original_input.clone();
        let mut candidate = review.prepared_input.clone();
        candidate
            .as_object_mut()
            .context("saved rerun input is not an object")?
            .insert(spec.name.clone(), value);
        let target = self
            .target_owned()
            .context("rerun requires an active target")?;
        let workspace = WorkspaceTarget::new(target)?;
        let prepared = self.prepare_phase_rerun_input(&tool, candidate, &workspace)?;
        let descriptor = self
            .registry()
            .resolve_tool(&tool)
            .context("rerun tool descriptor disappeared")?;
        let overrides = phase_rerun_action_overrides(derivation, &tool);
        let changed_options = rerun_option_diff(descriptor, &original, &prepared, overrides);
        if let Some(review) = self.engagement.pending_phase_rerun_mut() {
            review.prepared_input = prepared;
            review.changed_options = changed_options;
            review.draft_modified = review.prepared_input != review.original_input;
            review.option_error = None;
            // The draft the last refusal described no longer exists.
            review.dispatch_error = None;
        }
        Ok(())
    }

    fn cancel_phase_rerun_review(&mut self) -> InputUpdate {
        self.engagement.clear_pending_phase_rerun();
        self.log(
            "workflow",
            "rerun review canceled — saved input was not changed",
        );
        InputUpdate::handled()
    }

    /// A refused launch must not cost the operator the draft they just
    /// reviewed, so the pending review is consumed only once a launch exists.
    fn dispatch_phase_rerun_review(&mut self) -> InputUpdate {
        let Some(review) = self.engagement.pending_phase_rerun().cloned() else {
            return InputUpdate::handled();
        };
        match self.phase_rerun_launch(review) {
            Ok(launch) => {
                self.engagement.clear_pending_phase_rerun();
                InputUpdate::handled_with_effects(vec![ShellEffect::DispatchRunTool(launch)])
            }
            Err(reason) => {
                self.refuse_phase_rerun_dispatch(reason);
                InputUpdate::handled()
            }
        }
    }

    fn refuse_phase_rerun_dispatch(&mut self, reason: String) {
        self.refuse_phase_result_action(format!("rerun not dispatched — {reason}"));
        if let Some(review) = self.engagement.pending_phase_rerun_mut() {
            review.dispatch_error = Some(reason);
        }
    }

    fn phase_rerun_launch(&mut self, review: PhaseRerunReview) -> Result<RunToolLaunch, String> {
        let workspace = self.phase_rerun_workspace()?;
        let current =
            kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(workspace.root());
        if let Some(reason) =
            self.phase_recovery_prerequisite_blocker_for_snapshot(review.phase, &current)
        {
            return Err(reason);
        }
        let prepared = self
            .prepare_background_tool_input(&review.tool, review.prepared_input.clone(), &workspace)
            .map_err(|error| format!("exact rerun is no longer valid: {error}"))?;
        phase_rerun_preparation_matches_review(&review.prepared_input, prepared.value())?;
        self.apply_phase_rerun_lineage(&review);
        let thinking_level = thinking_level_from_input(prepared.value())
            .or_else(|| self.session_thinking_level_owned());
        Ok(RunToolLaunch {
            tool_name: review.tool,
            input: prepared,
            workspace,
            thinking_level,
            authorization: ExecutionAuthorization::interactive_request(),
        })
    }

    fn phase_rerun_workspace(&self) -> Result<WorkspaceTarget, String> {
        let target = self
            .target_owned()
            .ok_or_else(|| "rerun requires an active target".to_string())?;
        WorkspaceTarget::new(&target).map_err(|_| "rerun target is unavailable".to_string())
    }

    fn apply_phase_rerun_lineage(&mut self, review: &PhaseRerunReview) {
        match review.derivation {
            Some(derivation) => self.engagement.arm_attempt_lineage(
                review.phase,
                review.parent_attempt_id.clone(),
                derivation,
            ),
            None => self.engagement.clear_attempt_lineage(review.phase),
        }
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
        if let Some(update) = self.handle_capture_modal_key(key) {
            return update;
        }
        if let Some(update) = self.handle_overlay_key(key) {
            return update;
        }
        self.handle_shared_modal_key(key)
    }

    fn handle_capture_modal_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let prereq_update = self.handle_prereq_prompt_key(key);
        if prereq_update.handled {
            return Some(prereq_update);
        }
        if self.handle_review_search_key(key) {
            return Some(InputUpdate::handled());
        }
        self.handle_logs_filter_key(key).then(InputUpdate::handled)
    }

    /// `/` on the Logs page opens an incremental filter over the session
    /// transcript. While open it owns every printable key, so typing never
    /// leaks into the composer. Enter keeps the filter; Esc clears it.
    fn handle_logs_filter_key(&mut self, key: KeyEvent) -> bool {
        if !self.router.logs().filter_capture() {
            return false;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let logs = self.router.logs_mut();
        match key.code {
            KeyCode::Esc => logs.close_filter_capture(false),
            KeyCode::Enter => logs.close_filter_capture(true),
            KeyCode::Backspace => logs.pop_filter_char(),
            KeyCode::Char('c') if ctrl => return false,
            KeyCode::Char(character) if !ctrl && !alt => logs.push_filter_char(character),
            _ => return false,
        }
        true
    }

    /// Item 13: `/` on the Review page opens a palette-style search capture
    /// over the findings queue. While open it owns every printable key —
    /// typing never leaks into the composer. Enter keeps the query active;
    /// Esc clears it.
    fn handle_review_search_key(&mut self, key: KeyEvent) -> bool {
        if !self.router.workbench().review().search_capture {
            return false;
        }
        let cursor_anchor = crate::ui_view_models::visible_finding_at_cursor(self)
            .map(|(_, finding)| review_search_anchor(&finding));
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let review = self.router.workbench_mut().review_mut();
        let projection_changed = match key.code {
            KeyCode::Esc => {
                review.close_search_capture(false);
                true
            }
            KeyCode::Enter => {
                review.close_search_capture(true);
                false
            }
            KeyCode::Backspace => {
                review.pop_search_char();
                true
            }
            KeyCode::Char('c') if ctrl => return false,
            KeyCode::Char(ch) if !ctrl && !alt => {
                review.push_search_char(ch);
                true
            }
            _ => return false,
        };
        if projection_changed {
            self.reanchor_review_search_cursor(cursor_anchor);
        }
        true
    }

    fn reanchor_review_search_cursor(&mut self, anchor: Option<String>) {
        let len = crate::ui_view_models::visible_findings_len(self);
        let position = anchor.and_then(|anchor| {
            (0..len).find(|index| {
                crate::ui_view_models::visible_finding_at_index(self, *index)
                    .is_some_and(|(_, finding)| review_search_anchor(&finding) == anchor)
            })
        });
        if let Some(position) = position {
            self.router.findings_mut().set_cursor(position);
        } else {
            self.router.findings_mut().clamp(len);
        }
    }

    fn handle_contextual_surface_key(&mut self, key: KeyEvent) -> bool {
        if !key.modifiers.is_empty() {
            return false;
        }
        let contextual_utility = self.contextual_navigation_owns_keys();
        if !contextual_utility {
            return false;
        }
        if key.code == KeyCode::Esc {
            return self.collapse_dfd_focus_or_restore_contextual_origin();
        }
        self.handle_catalog_expert_key(key)
    }

    fn contextual_navigation_owns_keys(&self) -> bool {
        if self.batch_config_open() {
            return false;
        }
        matches!(
            self.shell_view(),
            ShellView::Catalog
                | ShellView::Keymap
                | ShellView::Help
                | ShellView::Jobs
                | ShellView::Campaign
                | ShellView::Replay
                | ShellView::Trace
                | ShellView::RunDiff
                | ShellView::Scene
        )
    }

    fn collapse_dfd_focus_or_restore_contextual_origin(&mut self) -> bool {
        if self.shell_view() == ShellView::Scene && self.router.scene_mut().collapse_dfd_focus() {
            return true;
        }
        self.restore_contextual_surface_origin()
    }

    /// Catalog `e` toggles expert engines from BOTH input modes; a
    /// non-empty Prompt draft always wins so typing stays normal.
    fn handle_catalog_expert_key(&mut self, key: KeyEvent) -> bool {
        if self.shell_view() != ShellView::Catalog
            || key.code != KeyCode::Char('e')
            || !self.input().is_empty()
        {
            return false;
        }
        self.apply_view_hotkey(ViewHotkeyAction::CatalogToggleExpert)
            .handled
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
    fn handle_overlay_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if matches!(self.shell_view(), ShellView::CommandPalette) {
            return self.handle_command_palette_key(key);
        }
        if self.history_search().is_some() {
            return self
                .handle_history_search_key(key)
                .then(InputUpdate::handled);
        }
        None
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
    /// consumed here. Enter may dispatch a command, so its effects ride the
    /// returned update.
    fn handle_command_palette_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Esc => self.close_palette(),
            KeyCode::Enter => {
                return Some(InputUpdate {
                    handled: true,
                    effects: self.accept_palette(),
                })
            }
            KeyCode::Up => self.palette_move(-1),
            KeyCode::Down => self.palette_move(1),
            KeyCode::Char('p') if ctrl => self.palette_move(-1),
            KeyCode::Char('n') if ctrl => self.palette_move(1),
            KeyCode::Char('g') if ctrl => self.close_palette(),
            KeyCode::Char('c') if ctrl => return None,
            KeyCode::Backspace => self.palette_backspace(),
            KeyCode::Char(ch) if !ctrl && !alt => self.palette_input(ch),
            _ => return None,
        }
        Some(InputUpdate::handled())
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
        self.handle_picker_deferred_modal_key(key)
    }

    fn handle_picker_deferred_modal_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.handle_picker_notice_dismiss(key) {
            return InputUpdate::handled();
        }
        let update = self.handle_credential_recovery_escape(key);
        if update.handled {
            return update;
        }
        if let Some(update) = self.handle_batch_config_key(key) {
            return update;
        }
        self.handle_picker_key(key)
    }

    fn handle_picker_notice_dismiss(&mut self, key: KeyEvent) -> bool {
        self.is_picker_view() && self.handle_notice_dismiss_key(key)
    }

    fn handle_credential_recovery_escape(&mut self, key: KeyEvent) -> InputUpdate {
        let recovery_open = self.engagement.pending_credential_continuation().is_some();
        if key.code == KeyCode::Esc && recovery_open {
            return self.handle_picker_key(key);
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
            KeyCode::Down | KeyCode::Char('j') => self.scroll_current_view_down(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_current_view_up(1),
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
            self.router.set_quit_confirm_scroll(0);
            self.go_back();
            return InputUpdate::handled();
        }
        if key.modifiers.is_empty() {
            self.scroll_quit_disclosures(key.code);
            return InputUpdate::handled();
        }
        InputUpdate::ignored()
    }

    fn scroll_quit_disclosures(&mut self, code: KeyCode) {
        let viewport = crate::renderer::quit_disclosure_viewport(self);
        let offset = viewport.offset;
        let page = viewport.page_size.max(1);
        let next = match code {
            KeyCode::Up => offset.saturating_sub(1),
            KeyCode::Down => offset.saturating_add(1),
            KeyCode::PageUp => offset.saturating_sub(page),
            KeyCode::PageDown => offset.saturating_add(page),
            KeyCode::Home => 0,
            KeyCode::End => viewport.max_offset,
            _ => return,
        };
        self.router
            .set_quit_confirm_scroll(next.min(viewport.max_offset));
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

    /// Completion notices clear without taking Escape away from the active
    /// reader or editor. Alerts retain their explicit dismissal action.
    fn handle_notice_dismiss_key(&mut self, key: KeyEvent) -> bool {
        if key.code != KeyCode::Esc || !key.modifiers.is_empty() {
            return false;
        }
        let captures_escape = self.notice_captures_escape();
        self.clear_notice();
        captures_escape
    }

    pub(crate) fn notice_captures_escape(&self) -> bool {
        if self.phase_result_is_open() {
            return false;
        }
        self.advisory().notice.as_ref().is_some_and(|notice| {
            matches!(
                notice.severity,
                crate::NoticeSeverity::Error | crate::NoticeSeverity::Warn
            )
        })
    }

    pub(super) fn handle_confirm_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.advisory().pending_confirm.is_none() || is_quit_chord(key) {
            return InputUpdate::ignored();
        }
        if self.handle_allowance_review_key(key) {
            return InputUpdate::handled();
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
        if resolved
            .as_ref()
            .is_some_and(|confirm| confirm.kind == ConfirmKind::ModelSwitch)
        {
            let effects = self.resolve_model_switch_consent(action.outcome);
            return InputUpdate::handled_with_effects(effects);
        }
        if resolved.is_none() && self.advisory().pending_confirm.is_some() {
            return InputUpdate::handled();
        }
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
        if !self.is_budget_halted() || self.budget_editor_open() {
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

    pub(crate) fn prove_detail_owns_controls(&self) -> bool {
        self.shell_view() == ShellView::Workbench
            && crate::ui_view_models::active_workbench_page(self) == WorkbenchPage::Prove
            && self.router.workbench().prove_detail_is_open()
    }

    fn dismiss_prove_detail(&mut self) -> bool {
        if !self.prove_detail_owns_controls() {
            return false;
        }
        if self.input_mode() == InputMode::Prompt && self.esc_clear_input_or_completion() {
            return true;
        }
        self.router.workbench_mut().close_prove_detail();
        true
    }

    fn handle_input_mode_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        if !modifiers.no_modifiers || key.code != KeyCode::Esc {
            return false;
        }
        if self.dismiss_prove_detail() {
            return true;
        }
        self.toggle_composer_input_mode()
    }

    fn toggle_composer_input_mode(&mut self) -> bool {
        // Esc toggles the composer mode: with a draft or completion popup the
        // line editor consumes Esc first (clear/restore), so Navigate entry
        // only fires on an empty prompt.
        match self.input_mode() {
            InputMode::Prompt => {
                if self.input().is_empty() && self.default_composer_action_enabled("navigate_mode")
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

    /// Threat tab digits fire from BOTH input modes: Prompt mode yields them
    /// only while the composer is empty, so an in-progress draft ("model 1")
    /// keeps typing normally.
    fn handle_threat_tab_digit_key(&mut self, key: KeyEvent) -> bool {
        if self.shell_view() != ShellView::Threat
            || !key.modifiers.is_empty()
            || (self.input_mode() == InputMode::Prompt && !self.input().is_empty())
        {
            return false;
        }
        let KeyCode::Char(digit) = key.code else {
            return false;
        };
        let Some(view) = super::view_keybinding_groups::threat_view_for_digit(digit) else {
            return false;
        };
        self.apply_view_hotkey(ViewHotkeyAction::ThreatView(view))
            .handled
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
    }

    fn enter_prompt_mode(&mut self) {
        self.set_input_mode(InputMode::Prompt);
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

fn review_search_anchor(finding: &kuzushi_core::Finding) -> String {
    finding
        .identity_id
        .as_ref()
        .or(finding.dedup_key.as_ref())
        .unwrap_or(&finding.fingerprint)
        .clone()
}

/// Fold terminal-specific keystroke encodings into the canonical form every
/// binding in this crate matches, before any owner sees the key.
fn normalize_terminal_key_encoding(key: KeyEvent) -> KeyEvent {
    normalize_line_feed_enter(normalize_back_tab(key))
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

/// A line feed on stdin means Enter. Crossterm cannot tell `0x0A` apart from
/// Ctrl+J in raw mode and reports the chord, so an Enter that reached the tty
/// while the line discipline was still translating CR to LF — the startup
/// window before raw mode engages, and every external-process suspension —
/// arrives here as Ctrl+J. Canonicalise it so that Enter always submits
/// instead of typing a stray `j` into the composer.
fn normalize_line_feed_enter(key: KeyEvent) -> KeyEvent {
    if key.code == KeyCode::Char('j') && key.modifiers == KeyModifiers::CONTROL {
        return KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
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
    review: PhaseRerunReview,
    derivation: Option<kuzushi_core::workflow_attempts::PhaseAttemptDerivation>,
}

fn phase_rerun_action_overrides(
    action: Option<kuzushi_core::workflow_attempts::PhaseAttemptDerivation>,
    tool: &str,
) -> &'static [(&'static str, &'static str)] {
    use kuzushi_core::workflow_attempts::PhaseAttemptDerivation::{Refine, Regenerate};
    const REFINE: &[(&str, &str)] = &[("mode", "refine")];
    const REGENERATE: &[(&str, &str)] = &[("mode", "build"), ("seedMode", "fresh")];

    match (tool, action) {
        ("threat-model:build", Some(Refine)) => REFINE,
        ("threat-model:build", Some(Regenerate)) => REGENERATE,
        _ => &[],
    }
}

fn input_with_phase_rerun_overrides(
    mut input: Value,
    overrides: &[(&str, &str)],
) -> anyhow::Result<Value> {
    if overrides.is_empty() {
        return Ok(input);
    }
    let object = input
        .as_object_mut()
        .context("saved rerun input is not an object")?;
    object.extend(
        overrides
            .iter()
            .map(|(name, value)| ((*name).to_string(), Value::String((*value).to_string()))),
    );
    Ok(input)
}

fn rerun_specification(
    registry: &kuzushi_core::ModuleRegistry,
    target: &std::path::Path,
    run_id: &str,
) -> Option<(String, serde_json::Value)> {
    let summary = kuzushi_core::load_run_summary(target, run_id).ok()?;
    let tool = summary.tool?;
    let kuzushi_core::RunArtifactRead::Ready { value, .. } =
        kuzushi_core::read_run_artifact_text(target, run_id, "input.json")
    else {
        return None;
    };
    let input: serde_json::Value = serde_json::from_str(&value).ok()?;
    registry.resolve_tool(&tool)?;
    Some((tool, input))
}

fn next_phase_rerun_option_value(
    spec: &kuzushi_core::modules::OptionSpec,
    current: Option<&Value>,
) -> anyhow::Result<Value> {
    match spec.option_type {
        OptionType::Bool => Ok(Value::Bool(
            !current.and_then(Value::as_bool).unwrap_or(false),
        )),
        OptionType::Enum => next_phase_rerun_enum_value(spec, current),
        _ => anyhow::bail!("Enter edits this option; Space cycles yes/no and choices"),
    }
}

fn next_phase_rerun_enum_value(
    spec: &kuzushi_core::modules::OptionSpec,
    current: Option<&Value>,
) -> anyhow::Result<Value> {
    anyhow::ensure!(!spec.choices.is_empty(), "this option has no choices");
    let position = current
        .and_then(Value::as_str)
        .and_then(|value| spec.choices.iter().position(|choice| choice == value))
        .unwrap_or(spec.choices.len() - 1);
    Ok(Value::String(
        spec.choices[(position + 1) % spec.choices.len()].clone(),
    ))
}

fn rerun_option_review(
    descriptor: &kuzushi_core::modules::ToolDescriptor,
    input: &serde_json::Value,
    disclosed_overrides: &[(&str, &str)],
) -> Vec<PhaseRerunOptionReview> {
    let Some(input) = input.as_object() else {
        return Vec::new();
    };
    descriptor
        .options
        .iter()
        .filter_map(|option| {
            let value = input.get(&option.name)?;
            let action_override = disclosed_overrides
                .iter()
                .any(|(name, _)| *name == option.name);
            if option.default.as_ref() == Some(value) && !action_override {
                return None;
            }
            Some(PhaseRerunOptionReview {
                label: option.name.clone(),
                value: review_option_value(&option.name, value),
                description: option.description.clone(),
            })
        })
        .collect()
}

fn rerun_option_diff(
    descriptor: &kuzushi_core::modules::ToolDescriptor,
    original: &serde_json::Value,
    draft: &serde_json::Value,
    disclosed_overrides: &[(&str, &str)],
) -> Vec<PhaseRerunOptionReview> {
    descriptor
        .options
        .iter()
        .filter(|option| crate::app::option_is_operator_editable(option))
        .filter_map(|option| {
            let before = original
                .get(&option.name)
                .unwrap_or(&serde_json::Value::Null);
            let after = draft.get(&option.name).unwrap_or(&serde_json::Value::Null);
            let changed = before != after;
            let action_override = disclosed_overrides
                .iter()
                .any(|(name, _)| *name == option.name);
            (changed || action_override).then(|| PhaseRerunOptionReview {
                label: option.name.clone(),
                value: rerun_option_change_value(&option.name, before, after, changed),
                description: option.description.clone(),
            })
        })
        .collect()
}

fn rerun_option_change_value(
    name: &str,
    before: &serde_json::Value,
    after: &serde_json::Value,
    changed: bool,
) -> String {
    if !changed {
        return review_option_value(name, after);
    }
    format!(
        "{} -> {}",
        review_option_value(name, before),
        review_option_value(name, after)
    )
}

fn review_option_value(name: &str, value: &serde_json::Value) -> String {
    if sensitive_option_name(name) {
        return "<redacted>".to_string();
    }
    match value {
        serde_json::Value::Object(_) => "custom JSON value".to_string(),
        serde_json::Value::String(text) if text.chars().count() > 80 => {
            format!("custom text ({} characters)", text.chars().count())
        }
        _ => crate::app::format_option_value(value),
    }
}

fn sensitive_option_name(name: &str) -> bool {
    let name = name.replace(['_', '-'], "").to_ascii_lowercase();
    ["apikey", "token", "secret", "password", "credential"]
        .iter()
        .any(|needle| name.contains(needle))
}

/// An "exact rerun" is only exact when the input that will run is the input
/// the operator reviewed. Preparation can legitimately re-resolve under a
/// changed descriptor or workspace, so refuse instead of silently dispatching
/// input the review never showed.
fn phase_rerun_preparation_matches_review(
    reviewed_input: &serde_json::Value,
    prepared_input: &serde_json::Value,
) -> Result<(), String> {
    if prepared_input == reviewed_input {
        return Ok(());
    }
    Err("rerun input changed after review — reopen the rerun review before dispatching".to_string())
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
mod notice_keys_tests;

#[cfg(test)]
mod phase_result_tests;

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
    fn successful_input_mode_flips_do_not_write_the_transcript() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let baseline = app.log_lines().len();

        app.enter_navigate_mode();
        app.enter_prompt_mode();

        assert_eq!(app.log_lines().len(), baseline);

        app.set_input("unfinished");
        app.enter_navigate_mode();
        assert_eq!(app.input_mode(), InputMode::Prompt);
        assert_eq!(app.log_lines().len(), baseline + 1);
        assert!(app.log_lines()[baseline]
            .body
            .contains("finish or clear the prompt"));
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
        app_with_unresolved_map_result_input(config, serde_json::json!({}))
    }

    fn app_with_unresolved_map_result_input(
        config: V2Config,
        input: serde_json::Value,
    ) -> (tempfile::TempDir, ShellApp, String) {
        use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;
        let target = tempfile::tempdir().unwrap();
        seed_indexed_map_run(target.path(), "map-run", input);
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

    fn seed_indexed_map_run(target: &std::path::Path, run_id: &str, input: serde_json::Value) {
        crate::test_support::record_indexed_run_with_input(
            target,
            run_id,
            "context:build",
            input,
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
        seed_fix_source_identity(target.path());
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding = seed_fix_result_findings(&store, workspace.root());
        seed_verified_patch_lifecycle(&store, &workspace, &finding, lifecycle_run_id);
        write_completed_fix_run_summary(&workspace, attempt_run_id, attempt_tool);
        let attempt_id = append_fix_result_attempt(&workspace, attempt_run_id);
        FixResultFixture { target, attempt_id }
    }

    fn seed_fix_source_identity(target: &std::path::Path) {
        std::fs::write(target.join("input.rs"), "fn fixture() {}\n").unwrap();
        run_fix_fixture_git(target, &["init", "--quiet"]);
        kuzushi_core::WorkspaceTarget::new(target).unwrap();
        for args in [
            vec!["add", "."],
            vec![
                "-c",
                "user.name=Kuzushi Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        ] {
            run_fix_fixture_git(target, &args);
        }
    }

    fn run_fix_fixture_git(target: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
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

        let mut record = PatchLifecycleRecord {
            application_id: "application-fix-result".to_string(),
            stable_fp: store
                .patch_lifecycle_stable_fp(&finding.fingerprint)
                .unwrap(),
            fingerprint: finding.fingerprint.clone(),
            finding_scan_id: finding.scan_id.clone(),
            patch_run_id: "patch-candidate-run".to_string(),
            target: workspace.root().display().to_string(),
            diff_hash: "diff-sha256".to_string(),
            base_commit: Some("source-commit".to_string()),
            touched_files: Vec::new(),
            state: PatchLifecycleState::Verified,
            reverify_run_id: Some(lifecycle_run_id.to_string()),
            reverify_evidence: None,
            detail: Some("re-verification passed".to_string()),
            actor: "operator".to_string(),
            application_started_at: "1".to_string(),
            applied_at: Some("2".to_string()),
            updated_at: "3".to_string(),
        };
        crate::test_support::attach_verified_patch_receipt(workspace, &mut record);
        store.insert_patch_lifecycle_record(&record).unwrap();
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
        summary.status = "completed".to_string();
        summary.completed_at_unix = Some(summary.started_at_unix);
        kuzushi_core::write_run_summary(workspace.root(), &summary).unwrap();
        write_completed_fix_lifecycle(workspace.root(), attempt_run_id, attempt_tool);
    }

    fn write_completed_fix_lifecycle(target: &std::path::Path, run_id: &str, tool: &str) {
        use kuzushi_core::run_lifecycle::*;
        let observation = RunObservationHandle::jsonl(target, run_id).unwrap();
        let mut plan = observation
            .start_plan("Fix finding", ["Prepare patch result".to_string()])
            .unwrap();
        let task = plan.tasks()[0].clone();
        plan.update_and_flush(RunItemStatus::Running).unwrap();
        task.update_and_flush(RunItemStatus::Running, None).unwrap();
        task.update_and_flush(RunItemStatus::Completed, None)
            .unwrap();
        plan.update_and_flush(RunItemStatus::Completed).unwrap();
        observation
            .emit_and_flush(RunItemRecord::new(
                RunItemId::new(),
                RunItemSource::Workflow,
                RunItemV1::TerminalOutcome {
                    status: RunItemStatus::Completed,
                    summary: SafeText::operator_visible("Patch candidate completed"),
                    cost: kuzushi_core::runtime::RuntimeCostReport::known(
                        kuzushi_core::runtime::RuntimeCost::ZERO,
                    ),
                    continuation: WorkflowContinuation::NoFurtherAction {
                        reason: SafeText::operator_visible(if tool == "patch:reverify" {
                            "re-verification passed; acknowledge this verified remediation"
                        } else {
                            "review the candidate; Apply remains separately authorized"
                        }),
                    },
                },
            ))
            .unwrap();
    }

    fn append_fix_result_attempt(
        workspace: &kuzushi_core::WorkspaceTarget,
        attempt_run_id: &str,
    ) -> String {
        use kuzushi_core::workflow_attempts::{
            PhaseAttemptCompleted, PhaseAttemptOutcome, PhaseTargetSnapshot,
        };

        let completed = PhaseAttemptCompleted::new(
            WorkflowPhase::Fix,
            vec![attempt_run_id.to_string()],
            PhaseTargetSnapshot::capture(workspace.root()),
            PhaseAttemptOutcome::Completed,
        )
        .with_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new().to_string())
        .with_receipt(fix_result_receipt());
        let attempt_id = completed.attempt_id.clone();
        kuzushi_core::workflow_attempts::append_phase_attempt_completed_with_v2(
            workspace.root(),
            completed,
        )
        .unwrap();
        attempt_id
    }

    fn fix_result_receipt() -> kuzushi_core::workflow_attempts::PhaseAttemptReceipt {
        use kuzushi_core::workflow_attempts::{PhaseAttemptReceipt, PhaseResultAction};

        PhaseAttemptReceipt {
            run_count: 1,
            elapsed_secs: 1,
            cost: "$0.0000".to_string(),
            changed_findings: 0,
            finding_delta_observed: None,
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
    fn line_feed_submits_the_composer_instead_of_typing_a_j() {
        let mut app = ShellApp::new(V2Config::default(), None);
        for ch in "demo".chars() {
            app.reduce_key(plain_key(KeyCode::Char(ch)));
        }
        assert_eq!(app.input(), "demo");

        // A CR that reached the tty before raw mode engaged arrives as LF,
        // which crossterm reports as Ctrl+J.
        let update = app.reduce_key(ctrl_key(KeyCode::Char('j')));

        assert!(update.handled);
        assert!(
            app.input().is_empty(),
            "Ctrl+J must submit the line, not type into it: {:?}",
            app.input()
        );
    }

    #[test]
    fn unbound_ctrl_chords_do_not_type_their_letter_into_the_composer() {
        let mut app = ShellApp::new(V2Config::default(), None);
        for ch in "demo".chars() {
            app.reduce_key(plain_key(KeyCode::Char(ch)));
        }

        app.reduce_key(ctrl_key(KeyCode::Char('y')));

        assert_eq!(app.input(), "demo");
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
    fn pending_confirm_yields_ctrl_c_to_volatile_state_disclosure() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(pending_network_confirm());
        app.set_input("existing draft");

        let update = app.reduce_key(ctrl_key(KeyCode::Char('c')));

        assert!(update.handled);
        assert!(update.effects.is_empty());
        assert_eq!(app.shell_view(), ShellView::QuitConfirm);
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
            ],
            "{}",
            card.recommended
        );
        assert!(card.control_hint.contains("u Acknowledge verified"));
        assert!(!card.control_hint.contains("Select patch"));
        assert!(!card.control_hint.contains("Refine"));
        assert_eq!(
            card.recommended,
            "none · re-verification passed; acknowledge this verified remediation"
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
        assert_eq!(
            card.actions,
            vec![
                kuzushi_core::workflow_attempts::PhaseResultAction::Select,
                kuzushi_core::workflow_attempts::PhaseResultAction::Open,
                kuzushi_core::workflow_attempts::PhaseResultAction::RunAgain,
            ]
        );
        assert!(!card.control_hint.contains("Acknowledge verified"));
        assert_eq!(
            card.recommended,
            "none · review the candidate; Apply remains separately authorized"
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
            "none · review the candidate; Apply remains separately authorized"
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
            finding_delta_observed: None,
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
    fn result_keys_resolve_the_unresolved_attempt_even_when_the_page_drifted() {
        // Prior findings can re-derive the active page to Review while the
        // Map result is still unresolved; the advertised `u` must resolve
        // the Map attempt anyway instead of dying as a silent no-op.
        let (_target, mut app, attempt_id) = app_with_unresolved_map_result(V2Config::default());
        app.router.workbench_mut().set_page(None);
        app.router
            .scene_mut()
            .set_page(crate::scene3d::VizPage::Dfd);

        assert_eq!(app.phase_result_target_phase(), Some(WorkflowPhase::Map));
        assert!(app.reduce_key(plain_key(KeyCode::Char('u'))).handled);

        assert!(
            app.engagement
                .unresolved_phase_attempt(WorkflowPhase::Map)
                .is_none(),
            "attempt {attempt_id} must be resolved by the advertised key"
        );
        assert_eq!(
            app.router.scene().page(),
            crate::scene3d::VizPage::Summary,
            "accepting a new Map returns its embedded gallery to Summary"
        );
    }

    #[test]
    fn phase_result_shortcuts_never_steal_prompt_text() {
        let (_target, mut app, _) = app_with_unresolved_map_result(V2Config::default());
        app.set_input_mode(InputMode::Prompt);

        for key in ['n', 'u', 'o', 'r', 'c', 'x'] {
            assert!(app.reduce_key(plain_key(KeyCode::Char(key))).handled);
        }
        assert_eq!(app.input(), "nuorcx");
        assert!(app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Map)
            .is_some());
    }

    #[test]
    fn unresolved_result_keeps_prompt_editing_and_escape_semantics() {
        let (_target, mut app, _) = app_with_unresolved_map_result(V2Config::default());
        app.set_input("preserved draft".to_string());
        app.set_input_mode(InputMode::Prompt);

        assert!(app.reduce_key(plain_key(KeyCode::Char('x'))).handled);
        assert_eq!(app.input(), "preserved draftx");
        assert!(app.reduce_key(plain_key(KeyCode::Backspace)).handled);
        assert_eq!(app.input(), "preserved draft");
        assert_eq!(app.input_mode(), InputMode::Prompt);
        let card = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Map)
            .header
            .result_card
            .unwrap();
        assert_eq!(
            card.control_hint,
            "Esc Navigate after finishing or clearing prompt draft"
        );

        assert!(app.reduce_key(plain_key(KeyCode::Esc)).handled);
        assert!(app.input().is_empty());
        assert_eq!(app.input_mode(), InputMode::Prompt);
        assert!(app.reduce_key(plain_key(KeyCode::Esc)).handled);
        assert_eq!(app.input_mode(), InputMode::Navigate);
    }

    #[test]
    fn failed_map_result_cannot_be_skipped_before_resolution() {
        let (_target, mut app, _) = app_with_unresolved_map_result(V2Config::default());

        assert!(!app.record_current_phase_skip());

        assert!(!app.engagement.phase_is_skipped(WorkflowPhase::Map));
        assert!(app.log_lines().iter().any(|line| {
            line.body.contains("REFUSED · RESULT")
                && line.body.contains("resolve the Map result")
                && line.body.contains("inspect, rerun, or discard")
        }));
    }

    #[test]
    fn rerun_review_is_human_readable_and_enter_dispatches_exact_saved_input() {
        let input = rerun_review_input();
        let (_target, mut app, _) =
            app_with_unresolved_map_result_input(V2Config::default(), input.clone());

        assert!(app.reduce_key(plain_key(KeyCode::Char('r'))).handled);
        assert_human_readable_rerun_review(&app);
        assert!(app.input().is_empty());
        assert_exact_saved_input_dispatch(&mut app, &input);
        assert!(app.input().is_empty());
    }

    #[test]
    fn rerun_dispatch_rechecks_stale_prerequisites_after_review_opens() {
        use kuzushi_core::workflow_attempts::{
            PhaseAttemptCompleted, PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
            PhaseAttemptEvent, PhaseAttemptLedger, PhaseAttemptOutcome, PhaseTargetSnapshot,
        };
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut projected = PhaseTargetSnapshot::capture(target.path());
        projected.revision = Some("projected-revision".to_string());
        let map = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["map-run".to_string()],
            projected.clone(),
            PhaseAttemptOutcome::Completed,
        );
        let ledger = PhaseAttemptLedger::from_events([
            PhaseAttemptEvent::PhaseAttemptCompleted(map.clone()),
            PhaseAttemptEvent::PhaseAttemptDispositionRecorded(
                PhaseAttemptDispositionRecorded::new(
                    map.attempt_id,
                    PhaseAttemptDisposition::Selected {
                        acknowledged_partial: false,
                    },
                ),
            ),
        ])
        .unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.engagement
            .set_phase_attempt_projection(Some(projected), ledger);
        let review = PhaseRerunReview {
            phase: WorkflowPhase::Scan,
            parent_attempt_id: "scan-attempt".to_string(),
            tool: "context:build".to_string(),
            tool_description: "build context".to_string(),
            original_input: serde_json::json!({}),
            prepared_input: serde_json::json!({}),
            changed_options: Vec::new(),
            option_editor_open: false,
            option_cursor: 0,
            option_edit: None,
            option_error: None,
            dispatch_error: None,
            draft_modified: false,
            derivation: None,
        };
        app.engagement.set_pending_phase_rerun(review);

        assert!(app.dispatch_phase_rerun_review().effects.is_empty());
        assert!(app.log_lines().iter().any(|line| {
            line.body
                .contains("rerun Map because the accepted Map is stale, then retry Scan")
        }));
        let review = app
            .engagement
            .pending_phase_rerun()
            .expect("a refused dispatch must leave the reviewed draft open");
        assert!(
            review
                .dispatch_error
                .as_deref()
                .is_some_and(|reason| reason.contains("the accepted Map is stale")),
            "the refusal reason must reach the card, not only the transcript"
        );
    }

    /// The review card is the only place the operator's edited draft lives, so
    /// a refused launch has to keep it — and say why on the card itself.
    #[test]
    fn a_refused_rerun_dispatch_keeps_the_reviewed_draft_and_discloses_why() {
        let input = rerun_review_input();
        let (_target, mut app, _) =
            app_with_unresolved_map_result_input(V2Config::default(), input.clone());
        assert!(app.reduce_key(plain_key(KeyCode::Char('r'))).handled);
        // Losing the target is the plainest way a launch stops being possible
        // after the review opened.
        app.set_target(None);

        let update = app.reduce_key(plain_key(KeyCode::Enter));

        assert!(update.handled);
        assert!(
            update.effects.is_empty(),
            "a refused rerun must not dispatch a tool"
        );
        let review = app
            .engagement
            .pending_phase_rerun()
            .expect("a refused dispatch must leave the reviewed draft open");
        assert_eq!(review.prepared_input, input);
        assert_eq!(
            review.dispatch_error.as_deref(),
            Some("rerun requires an active target")
        );
        assert!(
            app.log_lines()
                .iter()
                .any(|line| line.body.contains("rerun not dispatched")),
            "a refused rerun must be recorded, not silent"
        );
    }

    fn rerun_review_input() -> serde_json::Value {
        serde_json::json!({
            "sampleLimit": 12,
            "discovery": "auto",
            "enrichment": false,
            "scope": "all"
        })
    }

    fn assert_human_readable_rerun_review(app: &ShellApp) {
        let review = app
            .engagement
            .pending_phase_rerun()
            .expect("human rerun review");
        assert_eq!(review.tool, "context:build");
        assert_eq!(review.changed_options.len(), 1);
        assert_eq!(review.changed_options[0].label, "sampleLimit");
        assert!(review.changed_options[0]
            .description
            .contains("Maximum source files"));
        let card = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Map)
            .header
            .result_card
            .unwrap();
        assert!(card.detail.contains("sampleLimit = 12"), "{}", card.detail);
        assert!(
            !card.detail.contains("{"),
            "raw JSON leaked: {}",
            card.detail
        );
    }

    fn assert_exact_saved_input_dispatch(app: &mut ShellApp, input: &serde_json::Value) {
        let update = app.reduce_key(plain_key(KeyCode::Enter));
        let [ShellEffect::DispatchRunTool(launch)] = update.effects.as_slice() else {
            panic!("expected exact rerun dispatch");
        };
        assert_eq!(launch.tool_name, "context:build");
        assert_eq!(launch.input.value(), input);
    }

    #[test]
    fn rerun_review_edits_primitive_draft_in_place_without_touching_composer() {
        let input = rerun_review_input();
        let (_target, mut app, _) =
            app_with_unresolved_map_result_input(V2Config::default(), input);
        assert!(app.reduce_key(plain_key(KeyCode::Char('r'))).handled);

        assert!(app.reduce_key(plain_key(KeyCode::Char('e'))).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Enter)).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Backspace)).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Backspace)).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Char('2'))).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Char('5'))).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Enter)).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Char('j'))).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Char('j'))).handled);
        assert!(app.reduce_key(plain_key(KeyCode::Char(' '))).handled);

        assert_ne!(app.shell_view(), ShellView::Options);
        assert!(app.input().is_empty());
        let review = app.engagement.pending_phase_rerun().unwrap();
        assert!(review.option_editor_open);
        assert_eq!(
            review
                .prepared_input
                .get("sampleLimit")
                .and_then(serde_json::Value::as_u64),
            Some(25)
        );
        assert_eq!(
            review
                .prepared_input
                .get("enrichment")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(review.draft_modified);

        assert!(app.reduce_key(plain_key(KeyCode::Esc)).handled);
        let update = app.reduce_key(plain_key(KeyCode::Enter));
        let [ShellEffect::DispatchRunTool(launch)] = update.effects.as_slice() else {
            panic!("expected edited rerun dispatch");
        };
        assert_eq!(
            launch
                .input
                .value()
                .get("sampleLimit")
                .and_then(serde_json::Value::as_u64),
            Some(25)
        );
        assert_eq!(
            launch
                .input
                .value()
                .get("enrichment")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
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
    fn phase_result_escape_enters_navigate_without_resolving_the_result() {
        let (_target, mut app, attempt_id) = app_with_unresolved_map_result(V2Config::default());
        app.set_input_mode(InputMode::Prompt);

        assert!(app.phase_result_is_open());
        assert!(app.default_composer_action_enabled("navigate_mode"));
        assert!(app.reduce_key(plain_key(KeyCode::Esc)).handled);
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert!(app.input().is_empty());
        assert_eq!(
            app.engagement
                .unresolved_phase_attempt(WorkflowPhase::Map)
                .map(|record| record.completed.attempt_id.as_str()),
            Some(attempt_id.as_str())
        );
    }

    #[test]
    fn remapped_navigate_mode_key_works_while_a_phase_result_is_open() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "composer".to_string(),
            action: "navigate_mode".to_string(),
            bindings: vec!["ctrl+x".to_string()],
        }];
        let (_target, mut app, _) = app_with_unresolved_map_result(config);
        app.set_input_mode(InputMode::Prompt);

        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::CONTROL))
                .handled
        );
        assert_eq!(app.input_mode(), InputMode::Navigate);
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
    fn selecting_model_proof_materializes_non_runtime_reality_without_opening_fix() {
        let mut fixture = proof_selection_fixture("tool-proof-selection-restart");
        assert_eq!(journey_phase(&fixture.app), None);

        assert!(
            fixture
                .app
                .reduce_key(plain_key(KeyCode::Char('u')))
                .handled
        );
        assert!(
            fixture
                .app
                .engagement
                .unresolved_phase_attempt(WorkflowPhase::Prove)
                .is_none(),
            "{}",
            fixture
                .app
                .log_lines()
                .iter()
                .map(|line| format!("{}: {}", line.prefix, line.body))
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert_eq!(journey_phase(&fixture.app), None);

        let mut restarted = ShellApp::new(V2Config::default(), Some(&fixture.workspace));
        restarted.refresh_findings(false);
        assert_eq!(journey_phase(&restarted), None);
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
        assert!(
            notice.message.contains("phase result ledger is degraded"),
            "{}",
            notice.message
        );
        assert!(fixture.app.log_lines().iter().any(|line| {
            line.prefix == "workflow"
                && line
                    .body
                    .contains("typed phase receipt validation is degraded:")
        }));
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
        assert_eq!(
            proof.proof_verdict,
            kuzushi_core::PersistedProofVerdict::NotAttempted
        );
        assert_eq!(proof.backend, kuzushi_core::PersistedSandboxBackend::Model);
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
        let indexed = kuzushi_core::incremental_index::index_workspace_snapshot(workspace).unwrap();
        let candidate = serde_json::json!({
            "fingerprint": finding.fingerprint.clone(),
            "verifiedScanId": "scan-current",
            "identityId": finding.identity_id.clone(),
            "sourceIdentity": {
                "kind": "indexed_snapshot",
                "snapshot_hash": indexed.snapshot_hash,
                "tree_hash": indexed.tree_hash
            },
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
