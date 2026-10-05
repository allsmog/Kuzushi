use super::*;
use kuzushi_core::incremental_index::WorkspaceChange;

#[derive(Debug)]
pub struct ShellApp {
    pub(crate) editor: EditorState,
    pub(crate) session: SessionState,
    pub(crate) domain: DomainCache,
    /// Engagement-scoped planning runtime state: current phase, queued steps,
    /// failures/retries, target classification, planning picker route state,
    /// and per-run option overlays.
    pub(crate) engagement: EngagementState,
    /// Route-local scroll/filter state for simple stacked shell surfaces.
    pub(crate) router: RouterState,
    pub(crate) ui: UiPrefs,
    pub(crate) runtime_state: RuntimeState,
    #[cfg(test)]
    pub(crate) option_persistence_enabled_for_test: bool,
}

#[derive(Debug, Default)]
struct ExternalTargetStateChanges {
    config: bool,
    options: bool,
    project_scopes: bool,
}

impl ExternalTargetStateChanges {
    fn classify(target: &std::path::Path, relative_paths: &[std::path::PathBuf]) -> Self {
        let broad = std::path::Path::new(".kuzushi/v3");
        let config = kuzushi_core::workspace_config_path(target);
        let options = kuzushi_core::workspace_options_path(target);
        let scopes = target.join(".kuzushi/v3/project-model/scopes.json");
        Self {
            config: changed_path(target, relative_paths, broad, &config),
            options: changed_path(target, relative_paths, broad, &options),
            project_scopes: changed_path(target, relative_paths, broad, &scopes),
        }
    }
}

fn changed_path(
    target: &std::path::Path,
    relative_paths: &[std::path::PathBuf],
    broad: &std::path::Path,
    expected: &std::path::Path,
) -> bool {
    relative_paths
        .iter()
        .any(|relative| relative == broad || target.join(relative) == expected)
}

impl ShellApp {
    #[doc(hidden)]
    pub fn shell_view(&self) -> ShellView {
        self.router.current()
    }

    #[doc(hidden)]
    pub fn set_shell_view(&mut self, view: ShellView) {
        let current = self.shell_view();
        if contextual_surface_view(view) && !contextual_surface_view(current) {
            self.router.set_overlay_origin(Some(current));
            self.router.set_overlay_input_mode(Some(self.input_mode()));
        } else if !contextual_surface_view(view) {
            self.router.set_overlay_origin(None);
            self.router.set_overlay_input_mode(None);
        }
        if !matches!(
            view,
            ShellView::Workbench | ShellView::Activity | ShellView::Report
        ) && !contextual_surface_view(view)
        {
            self.router.workbench_mut().clear_zoom();
        }
        self.router.set_current(view);
        if current != view {
            self.refresh_planning_picker_on_return(view);
            self.record_session_event(
                kuzushi_core::session_transcript::SessionEvent::ViewChanged {
                    from: Some(format!("{current:?}")),
                    to: format!("{view:?}"),
                },
            );
        }
    }

    /// Returning to a planning surface (the picker itself or Setup's embedded
    /// Map plan) must re-derive row artifact reality — tools may have completed
    /// while Activity or another view was on screen. Gated on the staleness
    /// flag so a plan nothing ran under is left untouched.
    fn refresh_planning_picker_on_return(&mut self, view: ShellView) {
        if !matches!(view, ShellView::PlanningPicker | ShellView::Setup)
            || !self.engagement.planning_picker().artifacts_stale()
        {
            return;
        }
        let Some(target) = self.target_owned() else {
            return;
        };
        self.engagement
            .planning_picker_mut()
            .refresh_artifact_states(&target);
    }

    pub(crate) fn restore_contextual_surface_origin(&mut self) -> bool {
        let Some(origin) = self.router.overlay_origin() else {
            return false;
        };
        let input_mode = self
            .router
            .overlay_input_mode()
            .unwrap_or(InputMode::Prompt);
        self.set_shell_view(origin);
        self.set_input_mode(input_mode);
        self.router.navigation_mut().accept_back_transition(origin);
        true
    }

    pub(crate) fn open_report_from_current_origin(&mut self) {
        if self.shell_view() != ShellView::Report {
            let origin = self.current_non_nested_origin();
            if origin.view != ShellView::Report {
                self.router.report_mut().set_origin(origin);
            }
        }
        self.set_shell_view(ShellView::Report);
        self.set_input_mode(InputMode::Navigate);
    }

    pub(crate) fn close_report_to_origin(&mut self) {
        let origin = {
            let report = self.router.report_mut();
            report.set_editing_path(false);
            report.take_origin()
        };
        let Some(origin) = origin else {
            self.close_report_to_review_fallback();
            return;
        };
        self.set_shell_view(origin.view);
        self.set_input_mode(origin.input_mode);
        self.router
            .navigation_mut()
            .accept_back_transition(origin.view);
    }

    fn current_non_nested_origin(&self) -> ReportOrigin {
        let current = self.shell_view();
        if contextual_surface_view(current) {
            return ReportOrigin {
                view: self.router.overlay_origin().unwrap_or(current),
                input_mode: self
                    .router
                    .overlay_input_mode()
                    .unwrap_or(self.input_mode()),
            };
        }
        ReportOrigin {
            view: current,
            input_mode: self.input_mode(),
        }
    }

    fn close_report_to_review_fallback(&mut self) {
        self.set_shell_view(ShellView::Workbench);
        self.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Review));
        self.router
            .workbench_mut()
            .set_focus(crate::ui_view_models::PhaseSurfaceId::ReviewQueue);
        self.set_input_mode(InputMode::Navigate);
    }

    pub(crate) fn editor(&self) -> &EditorState {
        &self.editor
    }

    pub(crate) fn editor_mut(&mut self) -> &mut EditorState {
        &mut self.editor
    }

    pub fn log(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        let prefix = prefix.into();
        let body = body.into();
        let surface_workbench_error =
            prefix == "error" && self.shell_view() == ShellView::Workbench;
        self.domain.push_log(prefix.clone(), body.clone());
        if prefix != ">" {
            self.record_session_event(kuzushi_core::session_transcript::SessionEvent::LogEmitted {
                level: prefix.clone(),
                message: body.clone(),
            });
        }
        if surface_workbench_error {
            self.advisory_mut().notice = Some(Notice {
                source: "workbench".to_string(),
                message: body,
                severity: NoticeSeverity::Error,
                since: std::time::Instant::now(),
            });
        }
    }

    /// Add an operational diagnostic to the live activity view without
    /// persisting arbitrary worker stderr into the durable session transcript.
    pub(crate) fn log_ephemeral(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        self.domain.push_log(prefix, body);
    }

    pub fn log_lines(&self) -> &[LogLine] {
        self.domain.log_lines()
    }

    pub fn log_len(&self) -> usize {
        self.domain.log_len()
    }

    /// Lines aged out of the live cache; they remain readable in the durable
    /// session transcript that the Logs view pages into.
    pub fn log_evicted(&self) -> usize {
        self.domain.log_evicted()
    }

    pub fn clear_log(&mut self) {
        self.domain.clear_log();
    }

    pub(crate) fn auth_screen_snapshot(&self) -> Option<&AuthScreenSnapshot> {
        self.router.auth_screen_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_auth_screen_snapshot_for_test(&mut self, snapshot: Option<AuthScreenSnapshot>) {
        self.router.set_auth_screen_snapshot(snapshot);
    }

    pub(crate) fn boot_splash_snapshot(&self) -> Option<&BootSplashSnapshot> {
        self.router.boot_splash_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_boot_splash_snapshot_for_test(&mut self, snapshot: Option<BootSplashSnapshot>) {
        self.router.set_boot_splash_snapshot(snapshot);
    }

    pub(crate) fn command_palette_snapshot(&self) -> Option<&CommandPaletteSnapshot> {
        self.router.command_palette_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_command_palette_snapshot_for_test(
        &mut self,
        snapshot: Option<CommandPaletteSnapshot>,
    ) {
        self.router.set_command_palette_snapshot(snapshot);
    }

    pub(crate) fn config_screen_snapshot(&self) -> Option<&ConfigScreenSnapshot> {
        self.router.config_screen_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_config_screen_snapshot_for_test(
        &mut self,
        snapshot: Option<ConfigScreenSnapshot>,
    ) {
        self.router.set_config_screen_snapshot(snapshot);
    }

    pub(crate) fn context_screen_snapshot(&self) -> Option<&ContextScreenSnapshot> {
        self.router.context_screen_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_context_screen_snapshot_for_test(
        &mut self,
        snapshot: Option<ContextScreenSnapshot>,
    ) {
        self.router.set_context_screen_snapshot(snapshot);
    }

    pub(crate) fn cost_screen_snapshot(&self) -> Option<&CostScreenSnapshot> {
        self.router.cost_screen_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_cost_screen_snapshot_for_test(&mut self, snapshot: Option<CostScreenSnapshot>) {
        self.router.set_cost_screen_snapshot(snapshot);
    }

    pub(crate) fn confirm_dialog_snapshot(&self) -> Option<&ConfirmDialogSnapshot> {
        self.router.confirm_dialog_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_confirm_dialog_snapshot_for_test(
        &mut self,
        snapshot: Option<ConfirmDialogSnapshot>,
    ) {
        self.router.set_confirm_dialog_snapshot(snapshot);
    }

    pub(crate) fn health_snapshot(&self) -> Option<&HealthSnapshot> {
        self.router.health_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_health_snapshot_for_test(&mut self, snapshot: Option<HealthSnapshot>) {
        self.router.set_health_snapshot(snapshot);
    }

    pub(crate) fn help_screen_snapshot(&self) -> Option<&HelpScreenSnapshot> {
        self.router.help_screen_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_help_screen_snapshot_for_test(&mut self, snapshot: Option<HelpScreenSnapshot>) {
        self.router.set_help_screen_snapshot(snapshot);
    }

    pub(crate) fn interruption_snapshot(&self) -> Option<&InterruptionSnapshot> {
        self.router.interruption_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_interruption_snapshot_for_test(
        &mut self,
        snapshot: Option<InterruptionSnapshot>,
    ) {
        self.router.set_interruption_snapshot(snapshot);
    }

    pub(crate) fn keymap_snapshot(&self) -> Option<&KeymapSnapshot> {
        self.router.keymap_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_keymap_snapshot_for_test(&mut self, snapshot: Option<KeymapSnapshot>) {
        self.router.set_keymap_snapshot(snapshot);
    }

    pub(crate) fn options_screen_snapshot(&self) -> Option<&OptionsScreenSnapshot> {
        self.router.options_screen_snapshot()
    }

    #[doc(hidden)]
    pub fn open_options_for_test(&mut self, options: OptionsView) {
        self.router.set_options(options);
        self.set_shell_view(ShellView::Options);
    }

    #[doc(hidden)]
    pub fn open_auth_method_picker_for_test(&mut self, provider: impl Into<String>) {
        self.open_auth_method_picker(provider.into());
    }

    #[doc(hidden)]
    pub fn open_threat_view_for_test(&mut self, view: ThreatView) {
        self.router.threat_mut().open(view);
        self.set_shell_view(ShellView::Threat);
    }

    #[doc(hidden)]
    pub fn open_patch_for_test(&mut self, alias: impl Into<String>) {
        self.router.patch_mut().open(alias);
        self.set_shell_view(ShellView::Patch);
    }

    #[doc(hidden)]
    pub fn open_run_diff_for_test(&mut self, left: impl Into<String>, right: impl Into<String>) {
        self.router.run_diff_mut().open(left, right);
        self.set_shell_view(ShellView::RunDiff);
    }

    #[doc(hidden)]
    pub fn open_replay_for_test(&mut self, run_id: impl Into<String>) {
        self.router.replay_mut().open(run_id);
        self.set_shell_view(ShellView::Replay);
    }

    #[doc(hidden)]
    pub fn open_trace_for_test(&mut self, run_id: impl Into<String>) {
        self.router.trace_mut().open(run_id);
        self.set_shell_view(ShellView::Trace);
    }

    #[doc(hidden)]
    pub fn open_interruption_for_test(&mut self, view: InterruptionView) {
        self.router.interruption_mut().open(view);
        self.set_shell_view(ShellView::Interruption);
    }

    #[doc(hidden)]
    pub fn replace_options_screen_snapshot_for_test(
        &mut self,
        snapshot: Option<OptionsScreenSnapshot>,
    ) {
        self.router.set_options_screen_snapshot(snapshot);
    }

    pub(crate) fn quit_confirm_snapshot(&self) -> Option<&QuitConfirmSnapshot> {
        self.router.quit_confirm_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_quit_confirm_snapshot_for_test(
        &mut self,
        snapshot: Option<QuitConfirmSnapshot>,
    ) {
        self.router.set_quit_confirm_snapshot(snapshot);
    }

    pub(crate) fn sast_tasks_snapshot(&self) -> Option<&SastTasksSnapshot> {
        self.router.sast_tasks_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_sast_tasks_snapshot_for_test(&mut self, snapshot: Option<SastTasksSnapshot>) {
        self.router.set_sast_tasks_snapshot(snapshot);
    }

    pub(crate) fn theme_picker_snapshot(&self) -> Option<&ThemePickerSnapshot> {
        self.router.theme_picker_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_theme_picker_snapshot_for_test(
        &mut self,
        snapshot: Option<ThemePickerSnapshot>,
    ) {
        self.router.set_theme_picker_snapshot(snapshot);
    }

    pub(crate) fn update_available_snapshot(&self) -> Option<&UpdateAvailableSnapshot> {
        self.router.update_available_snapshot()
    }

    #[doc(hidden)]
    pub fn replace_update_available_snapshot_for_test(
        &mut self,
        snapshot: Option<UpdateAvailableSnapshot>,
    ) {
        self.router.set_update_available_snapshot(snapshot);
    }

    pub fn focused_module(&self) -> Option<&str> {
        self.router.focused_module()
    }

    pub(crate) fn focused_module_owned(&self) -> Option<String> {
        self.router.focused_module_owned()
    }

    #[doc(hidden)]
    pub fn set_focused_module(&mut self, module: Option<String>) {
        self.bump_command_provider_generation();
        self.router.set_focused_module(module);
    }

    pub(crate) fn clear_focused_module(&mut self) {
        self.bump_command_provider_generation();
        self.router.clear_focused_module();
    }

    pub(crate) fn config(&self) -> &V2Config {
        self.session.config()
    }

    pub(crate) fn config_mut(&mut self) -> &mut V2Config {
        self.session.config_mut()
    }

    pub(crate) fn registry(&self) -> &ModuleRegistry {
        self.session.registry()
    }

    pub(crate) fn registry_mut(&mut self) -> &mut ModuleRegistry {
        self.bump_command_provider_generation();
        self.session.registry_mut()
    }

    pub(crate) fn option_store(&self) -> &ToolOptionStore {
        self.session.option_store()
    }

    pub(crate) fn option_store_mut(&mut self) -> &mut ToolOptionStore {
        self.session.option_store_mut()
    }

    #[doc(hidden)]
    pub fn replace_option_store_for_test(&mut self, option_store: ToolOptionStore) {
        self.session.set_option_store(option_store);
    }

    #[cfg(test)]
    pub(crate) fn disable_option_persistence_for_test(&mut self) {
        self.option_persistence_enabled_for_test = false;
    }

    #[doc(hidden)]
    pub fn replace_log_for_test(&mut self, lines: Vec<LogLine>) {
        self.domain.replace_log_for_test(lines);
    }

    #[doc(hidden)]
    pub fn log_lines_mut_for_test(&mut self) -> &mut [LogLine] {
        self.domain.log_lines_mut_for_test()
    }

    pub fn target(&self) -> Option<&std::path::Path> {
        self.session.target()
    }

    pub(crate) fn target_path_buf(&self) -> Option<&PathBuf> {
        self.session.target_path_buf()
    }

    pub(crate) fn target_owned(&self) -> Option<PathBuf> {
        self.session.target_owned()
    }

    pub fn set_target(&mut self, target: Option<PathBuf>) {
        let changed = self.target() != target.as_deref();
        if changed {
            let prior = self.target_owned();
            self.router
                .answers_mut()
                .switch_target(prior, target.clone());
            self.invalidate_view_hydration();
            let campaign = self.router.campaign_mut();
            campaign.batch_scan_config = None;
            campaign.clear_active_batch();
        }
        self.session.set_target(target.clone());
        if changed {
            self.record_session_event(match target {
                Some(target) => kuzushi_core::session_transcript::SessionEvent::TargetActivated {
                    target,
                    source: "operator".to_string(),
                },
                None => kuzushi_core::session_transcript::SessionEvent::TargetCleared {
                    source: "operator".to_string(),
                },
            });
            self.refresh_phase_attempt_projection();
            self.start_answer_recovery();
        }
    }

    pub(crate) fn refresh_phase_attempt_projection(&mut self) {
        let previous = self.pending_prove_result_id().map(str::to_string);
        self.read_phase_attempt_projection();
        if self.pending_prove_result_id() != previous.as_deref() {
            self.router
                .workbench_mut()
                .scroll_mut()
                .set(crate::ui_view_models::PhaseSurfaceId::ProveResult, 0);
        }
    }

    fn pending_prove_result_id(&self) -> Option<&str> {
        self.engagement
            .unresolved_phase_attempt(WorkflowPhase::Prove)
            .map(|record| record.completed.attempt_id.as_str())
    }

    fn read_phase_attempt_projection(&mut self) {
        let Some(target) = self.target_owned() else {
            self.engagement.set_phase_attempt_projection(
                None,
                kuzushi_core::workflow_attempts::PhaseAttemptLedger::default(),
            );
            return;
        };
        let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(&target);
        match kuzushi_core::workflow_attempts::load_phase_attempt_ledger_recovering(&target) {
            Ok(recovered) => self.apply_recovered_phase_attempts(snapshot, recovered),
            Err(error) => self.apply_unreadable_phase_attempts(snapshot, error),
        }
    }

    fn apply_recovered_phase_attempts(
        &mut self,
        snapshot: kuzushi_core::workflow_attempts::PhaseTargetSnapshot,
        recovered: kuzushi_core::workflow_attempts::RecoveredPhaseAttemptLedger,
    ) {
        let degraded = recovered.is_degraded();
        self.engagement.set_phase_attempt_projection_health(
            Some(snapshot),
            recovered.ledger,
            degraded,
        );
        if let Some(line) = recovered.malformed_line {
            self.log(
                "workflow",
                format!(
                    "phase result ledger is degraded at line {line}; advancement is blocked until repaired"
                ),
            );
        }
        if let Some(reason) = recovered.degraded_reason {
            self.log(
                "workflow",
                format!("typed phase receipt validation is degraded: {reason}"),
            );
        }
    }

    fn apply_unreadable_phase_attempts(
        &mut self,
        snapshot: kuzushi_core::workflow_attempts::PhaseTargetSnapshot,
        error: impl std::fmt::Display,
    ) {
        self.engagement.set_phase_attempt_projection_health(
            Some(snapshot),
            kuzushi_core::workflow_attempts::PhaseAttemptLedger::default(),
            true,
        );
        self.log(
            "workflow",
            format!("phase result ledger is unreadable: {error}"),
        );
    }

    pub(crate) fn record_current_phase_skip(&mut self) -> bool {
        let unresolved = WorkflowPhase::INVESTIGATION_ORDER
            .iter()
            .copied()
            .find(|phase| self.engagement.unresolved_phase_attempt(*phase).is_some());
        if let Some(phase) = unresolved {
            self.log(
                "workflow",
                format!(
                    "REFUSED · RESULT · resolve the {} result before skipping it; inspect, rerun, or discard",
                    phase.title()
                ),
            );
            return false;
        }
        let Some(phase) = self.engagement.mark_current_phase_skipped() else {
            return false;
        };
        let Some(target) = self.target_owned() else {
            return false;
        };
        let checkpoint = kuzushi_core::workflow_attempts::PhaseCheckpointSkipped::new(
            phase,
            kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(&target),
        );
        match kuzushi_core::workflow_attempts::append_phase_checkpoint_skipped(&target, checkpoint)
        {
            Ok(_) => {
                self.refresh_phase_attempt_projection();
                true
            }
            Err(error) => {
                self.log(
                    "workflow",
                    format!("could not persist explicit {} skip: {error}", phase.label()),
                );
                false
            }
        }
    }

    /// Cached "YOUR TOOLS" shelf. Read-only; never triggers IO, so it is safe
    /// to call from per-frame view models.
    pub(crate) fn tool_shelf(&self) -> &kuzushi_core::workspace::ToolShelf {
        self.domain.tool_shelf()
    }

    /// Reload the shelf cache from the active target's `tool-shelf.json`. Call
    /// this on target wiring and after a favorite toggle — not per frame. With
    /// no target the shelf resets to empty (no cwd fallback).
    pub(crate) fn reload_tool_shelf(&mut self) {
        let shelf = self
            .target_owned()
            .and_then(|path| kuzushi_core::WorkspaceTarget::new(path).ok())
            .and_then(|target| kuzushi_core::workspace::load_tool_shelf(&target).ok())
            .unwrap_or_default();
        self.domain.set_tool_shelf(shelf);
    }

    /// Toggle a tool favorite: load-modify-save on disk, refresh the cache, and
    /// return the new favorite state. Errors when there is no active target.
    pub(crate) fn toggle_tool_favorite(&mut self, tool: &str) -> anyhow::Result<bool> {
        let path = self.target_owned().ok_or_else(|| {
            anyhow::anyhow!("favorites need a target; open one with `target <path>`")
        })?;
        let target = kuzushi_core::WorkspaceTarget::new(path)?;
        target.ensure_state_dir()?;
        let mut shelf = kuzushi_core::workspace::load_tool_shelf(&target)?;
        let now_favorite = shelf.toggle_favorite(tool);
        kuzushi_core::workspace::save_tool_shelf(&target, &shelf)?;
        self.domain.set_tool_shelf(shelf);
        Ok(now_favorite)
    }

    pub fn active_scope(&self) -> Option<&TargetCandidateScope> {
        self.session.active_scope()
    }

    pub fn set_active_scope(&mut self, scope: Option<TargetCandidateScope>) {
        self.session.set_active_scope(scope);
    }

    pub(crate) fn scan_cancel_token(&self) -> Option<&ScanCancellation> {
        self.runtime_state.scan_cancel()
    }

    pub(crate) fn set_scan_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.runtime_state.set_scan_cancel(cancel);
    }

    pub(crate) fn scan(&self) -> Option<&ScanPanelState> {
        self.domain.scan()
    }

    pub(crate) fn scan_mut(&mut self) -> Option<&mut ScanPanelState> {
        self.domain.scan_mut()
    }

    #[doc(hidden)]
    pub fn set_scan_panel(&mut self, scan: Option<ScanPanelState>) {
        let changed = self.scan().and_then(|scan| scan.run_id.as_deref())
            != scan.as_ref().and_then(|scan| scan.run_id.as_deref());
        self.domain.set_scan(scan);
        self.bump_completion_generation_when(changed);
    }

    pub(crate) fn set_scan_run_id(&mut self, run_id: String) {
        let changed = self.scan().and_then(|scan| scan.run_id.as_deref()) != Some(run_id.as_str());
        let Some(scan) = self.domain.scan_mut() else {
            return;
        };
        scan.run_id = Some(run_id);
        self.bump_completion_generation_when(changed);
    }

    #[cfg(test)]
    pub(crate) fn scan_is_none(&self) -> bool {
        self.domain.scan().is_none()
    }

    pub(crate) fn estimate_task_duration_secs(&self, task_id: &str) -> Option<u64> {
        self.domain.estimate_task_duration_secs(task_id)
    }

    pub(crate) fn record_task_duration_secs(&mut self, task_id: &str, secs: u64) {
        if let Err(error) = self.domain.record_task_duration_secs(task_id, secs) {
            self.log(
                "task-duration",
                format!("could not persist duration for {task_id}: {error}"),
            );
        }
    }

    pub(crate) fn agent_cancel_token(&self) -> Option<&ScanCancellation> {
        self.runtime_state.agent_cancel()
    }

    pub(crate) fn active_agent_run_id(&self) -> Option<&str> {
        if !self.jobs().is_running(JobKind::Agent) {
            return None;
        }
        self.agent_chat()
            .and_then(|agent| agent.run_id.as_deref())
            .or_else(|| {
                self.runtime_state
                    .cleared_agent_run()
                    .and_then(|run| run.run_id.as_deref())
            })
            .or_else(|| self.exclusive_agent_activity_run_id())
    }

    pub(crate) fn active_agent_is_auxiliary_read_only(&self) -> bool {
        if !self.jobs().is_running(JobKind::Agent) {
            return false;
        }
        self.jobs().is_running(JobKind::Run)
            || self
                .agent_chat()
                .is_some_and(|agent| agent.auxiliary_read_only)
            || self
                .runtime_state
                .cleared_agent_run()
                .is_some_and(|run| run.auxiliary_read_only)
    }

    fn exclusive_agent_activity_run_id(&self) -> Option<&str> {
        if self.jobs().is_running(JobKind::Run) {
            return None;
        }
        self.activity().map(|session| session.run_id.as_str())
    }

    pub(crate) fn set_agent_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.runtime_state.set_agent_cancel(cancel);
    }

    pub(crate) fn plan_cancel_token(&self) -> Option<&ScanCancellation> {
        self.runtime_state.plan_cancel()
    }

    pub(crate) fn set_plan_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.runtime_state.set_plan_cancel(cancel);
    }

    pub(crate) fn threat_cancel_token(&self) -> Option<&ScanCancellation> {
        self.runtime_state.threat_cancel()
    }

    pub(crate) fn set_threat_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.runtime_state.set_threat_cancel(cancel);
    }

    pub(crate) fn set_loop_wake(&mut self, wake: Option<TerminalLoopWake>) {
        self.runtime_state.set_loop_wake(wake);
    }

    #[cfg(test)]
    pub(crate) fn worker_handle_active_count_for_test(&self) -> usize {
        self.runtime_state.worker_handles().active_count()
    }

    pub(crate) fn jobs(&self) -> &JobHub {
        self.runtime_state.jobs()
    }

    pub(crate) fn jobs_mut(&mut self) -> &mut JobHub {
        self.runtime_state.jobs_mut()
    }

    pub(crate) fn tool_is_running(&self) -> bool {
        self.runtime_state.tool_run().is_running()
    }

    pub(crate) fn running_tool_name_owned(&self) -> Option<String> {
        self.runtime_state.tool_run().active_name_owned()
    }

    pub(crate) fn tool_cancel_token(&self) -> Option<&ScanCancellation> {
        self.runtime_state.tool_run().cancel()
    }

    pub(crate) fn active_tool_run_id(&self) -> Option<&str> {
        self.runtime_state.tool_run().run_id()
    }

    pub(crate) fn take_active_tool_run_id(&mut self) -> Option<String> {
        let run_id = self.runtime_state.tool_run_mut().take_run_id();
        self.bump_completion_generation_when(run_id.is_some());
        run_id
    }

    pub(crate) fn take_active_tool_target(&mut self) -> Option<PathBuf> {
        self.runtime_state.tool_run_mut().take_target()
    }

    pub(crate) fn active_model_override(&self) -> Option<&str> {
        self.runtime_state.tool_run().active_model_override()
    }

    pub(crate) fn set_active_model_override(&mut self, model: Option<String>) {
        self.runtime_state
            .tool_run_mut()
            .set_active_model_override(model);
    }

    pub(crate) fn start_tool_run(
        &mut self,
        tool_name: String,
        cancel: ScanCancellation,
        run_id: String,
        target: PathBuf,
        model_override: Option<String>,
    ) {
        let changed = self.active_tool_run_id() != Some(run_id.as_str());
        self.runtime_state
            .tool_run_mut()
            .start(tool_name, cancel, run_id, target, model_override);
        self.bump_completion_generation_when(changed);
    }

    pub(crate) fn finish_tool_run(&mut self) {
        self.runtime_state.tool_run_mut().finish();
    }

    pub(crate) fn clear_finished_tool_run_slot(&mut self) {
        self.runtime_state.tool_run_mut().clear_finished_run_slot();
    }

    pub(crate) fn request_tool_abort_flag(&mut self, reason: AbortReason) {
        self.runtime_state.tool_run_mut().request_abort(reason);
    }

    pub(crate) fn tool_abort_reason(&self) -> Option<AbortReason> {
        self.runtime_state.tool_run().abort_reason()
    }

    pub(crate) fn scan_abort_reason(&self) -> Option<AbortReason> {
        self.runtime_state.scan_abort_reason()
    }

    pub(crate) fn set_scan_abort_reason(&mut self, reason: Option<AbortReason>) {
        self.runtime_state.set_scan_abort_reason(reason);
    }

    pub(crate) fn input(&self) -> &str {
        self.editor.input()
    }

    pub(crate) fn cursor(&self) -> usize {
        self.editor.cursor()
    }

    pub(crate) fn command_history(&self) -> &[String] {
        self.editor.command_history()
    }

    #[cfg(test)]
    pub(crate) fn set_command_history(&mut self, history: Vec<String>) {
        self.editor.replace_command_history(history);
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.editor.set_cursor(cursor);
    }

    pub(crate) fn input_mode(&self) -> InputMode {
        self.editor.input_mode()
    }

    pub(crate) fn set_input_mode(&mut self, mode: InputMode) {
        self.editor.set_input_mode(mode);
    }

    pub(crate) fn history_search(&self) -> Option<&HistorySearch> {
        self.editor.history_search()
    }

    pub(crate) fn completion_cycle(&self) -> Option<&CompletionCycle> {
        self.editor.completion_cycle()
    }

    #[cfg(test)]
    pub(crate) fn last_cleared_input(&self) -> Option<&str> {
        self.editor.last_cleared_input()
    }

    pub(crate) fn set_last_cleared_input(&mut self, input: Option<String>) {
        self.editor.set_last_cleared_input(input);
    }

    pub fn should_quit(&self) -> bool {
        self.ui.should_quit()
    }

    pub(crate) fn request_shell_quit(&mut self) {
        self.ui.request_quit();
    }

    pub(crate) fn viewport(&self) -> TerminalViewport {
        self.ui.viewport()
    }

    pub(crate) fn set_viewport(&mut self, viewport: TerminalViewport) {
        self.ui.set_viewport(viewport);
    }

    pub(crate) fn domain(&self) -> &DomainCache {
        &self.domain
    }

    pub(crate) fn domain_mut(&mut self) -> &mut DomainCache {
        &mut self.domain
    }

    pub(crate) fn workbench_cache(&self) -> &std::cell::RefCell<WorkbenchCache> {
        self.domain.workbench_cache()
    }

    fn bump_completion_generation(&self) {
        self.workbench_cache()
            .borrow_mut()
            .bump_completion_generation();
    }

    pub(crate) fn bump_completion_generation_when(&self, changed: bool) {
        if changed {
            self.bump_completion_generation();
        }
    }

    fn bump_command_provider_generation(&self) {
        self.workbench_cache()
            .borrow_mut()
            .bump_command_provider_generation();
    }

    pub(crate) fn findings(&self) -> &[Finding] {
        self.domain.findings()
    }

    pub(crate) fn findings_total_count(&self) -> usize {
        self.domain.findings_total_count()
    }

    pub(crate) fn findings_are_partial(&self) -> bool {
        self.domain.findings_are_partial()
    }

    pub(crate) fn findings_read_watermark(&self) -> Option<u64> {
        self.domain.findings_read_watermark()
    }

    pub(crate) fn findings_mut(&mut self) -> &mut Vec<Finding> {
        self.domain.findings_mut()
    }

    pub(crate) fn findings_revision(&self) -> u64 {
        self.domain.findings_revision()
    }

    pub(crate) fn finding_aliases(&self) -> &[String] {
        self.domain.finding_aliases()
    }

    pub(crate) fn identity_fold_policy(&self) -> kuzushi_core::findings::IdentityFoldPolicy {
        self.domain.identity_fold_policy()
    }

    pub fn set_findings(&mut self, findings: Vec<Finding>) {
        let completion_values = finding_completion_values_from_findings(&findings);
        self.invalidate_finding_patch_truth(None);
        self.domain.set_findings(findings);
        self.cache_finding_completion_values(completion_values);
    }

    pub(crate) fn set_findings_projection(
        &mut self,
        findings: Vec<Finding>,
        aliases: Vec<String>,
        policy: kuzushi_core::findings::IdentityFoldPolicy,
    ) {
        let completion_values = finding_completion_values_from_findings(&findings);
        self.invalidate_finding_patch_truth(None);
        self.domain
            .set_findings_projection(findings, aliases, policy);
        self.cache_finding_completion_values(completion_values);
    }

    fn cache_finding_completion_values(&self, completion_values: Vec<String>) {
        if let Some(target) = self.target_owned() {
            self.workbench_cache()
                .borrow_mut()
                .store_finding_completion_values(&target, completion_values);
        }
    }

    pub(crate) fn set_findings_total_count(&mut self, total: usize) {
        self.domain.set_findings_total_count(total);
    }

    pub(crate) fn set_findings_read_watermark(&mut self, read_watermark: Option<u64>) {
        self.domain.set_findings_read_watermark(read_watermark);
    }

    pub(crate) fn workspace_stale(&self) -> Option<&WorkspaceStaleSummary> {
        self.domain.workspace_stale()
    }

    pub(crate) fn workspace_pending_changes(&self) -> Vec<WorkspaceChange> {
        self.workspace_stale()
            .map(|stale| stale.pending_changes().to_vec())
            .unwrap_or_default()
    }

    pub(crate) fn apply_workspace_changes(&mut self, changes: &[WorkspaceChange]) {
        self.invalidate_view_hydration();
        self.domain.apply_workspace_changes(changes);
        // Invalidate only — git metadata refills through async view
        // hydration. Refilling here ran `git status` on the UI thread for
        // every watcher-reported source change, which stalls input for
        // seconds on large targets.
        let mut cache = self.workbench_cache().borrow_mut();
        if changes_are_source_file_only(changes) {
            cache.invalidate_source_file_changes();
        } else {
            cache.invalidate_workspace_files();
        }
    }

    pub(crate) fn apply_external_workspace_state_change(
        &mut self,
        relative_paths: &[std::path::PathBuf],
    ) -> Vec<ShellEffect> {
        let Some(target) = self.target_owned() else {
            return Vec::new();
        };
        self.invalidate_view_hydration();
        let changes = ExternalTargetStateChanges::classify(&target, relative_paths);
        let (findings_changed, _run_summaries_changed) = {
            self.workbench_cache()
                .borrow_mut()
                .invalidate_state_artifact_paths(&target, relative_paths)
        };
        self.reload_external_target_settings(&target, changes.config, changes.options);
        if changes.project_scopes {
            self.reload_external_project_scope_tree(&target);
        }
        if !findings_changed || self.findings_projection_is_current(&target) {
            return Vec::new();
        }
        vec![ShellEffect::RefreshFindings(FindingsRefresh {
            announce: false,
            filter: self.active_findings_filter().clone(),
        })]
    }

    pub(crate) fn findings_projection_is_current(&self, target: &std::path::Path) -> bool {
        let Some(read_watermark) = self.findings_read_watermark() else {
            return false;
        };
        let path = target.join(".kuzushi/v3/index.sqlite3");
        kuzushi_core::FindingStore::open_read_only(path)
            .and_then(|store| store.projection_meta())
            .is_ok_and(|meta| meta.applied_seq == read_watermark)
    }

    pub(crate) fn clear_workspace_stale(&mut self) {
        self.domain.clear_workspace_stale();
    }

    pub(crate) fn review_decisions(&self) -> &[kuzushi_core::findings::ReviewDecisionRecord] {
        self.domain.review_decisions()
    }

    pub(crate) fn review_decisions_revision(&self) -> u64 {
        self.domain.review_decisions_revision()
    }

    pub(crate) fn set_review_decisions(
        &mut self,
        decisions: Vec<kuzushi_core::findings::ReviewDecisionRecord>,
    ) {
        self.domain.set_review_decisions(decisions);
    }

    pub(crate) fn active_findings_filter(&self) -> &Option<String> {
        self.router.findings().active_filter()
    }

    pub(crate) fn set_active_findings_filter(&mut self, filter: Option<String>) {
        self.router.findings_mut().set_active_filter(filter);
    }

    pub(crate) fn selected_finding(&self) -> &Option<Finding> {
        self.router.findings().selected_finding()
    }

    pub(crate) fn selected_finding_mut(&mut self) -> &mut Option<Finding> {
        self.router.findings_mut().selected_finding_mut()
    }

    pub(crate) fn set_selected_finding(&mut self, finding: Option<Finding>) {
        self.router.findings_mut().set_selected_finding(finding);
    }

    pub(crate) fn chain_aliases(&self) -> &[ExploitChain] {
        self.domain.chain_aliases()
    }

    pub(crate) fn set_chain_aliases(&mut self, aliases: Vec<ExploitChain>) {
        self.domain.set_chain_aliases(aliases);
    }

    pub(crate) fn pwn_view(&self) -> &PwnView {
        self.domain.pwn_view()
    }

    pub(crate) fn pwn_view_mut(&mut self) -> &mut PwnView {
        self.domain.pwn_view_mut()
    }

    pub fn activity(&self) -> Option<&ActivitySession> {
        self.domain.activity()
    }

    pub fn activity_mut(&mut self) -> Option<&mut ActivitySession> {
        self.domain.activity_mut()
    }

    pub fn activity_route(&self) -> &ActivityRouteState {
        self.router.activity()
    }

    pub fn activity_route_mut(&mut self) -> &mut ActivityRouteState {
        self.router.activity_mut()
    }

    pub fn set_activity(&mut self, activity: Option<ActivitySession>) {
        let changed = self.activity().map(|activity| activity.run_id.as_str())
            != activity.as_ref().map(|activity| activity.run_id.as_str());
        self.domain.set_activity(activity);
        self.bump_completion_generation_when(changed);
    }

    pub(crate) fn capture_run_focus_origin(&self, mut session: ActivitySession) -> ActivitySession {
        if let Some(prior) = self.activity().filter(|prior| {
            prior.run_focus_origin.is_some()
                && (self.shell_view() == ShellView::Activity
                    || prior.run_focus_terminal_pending
                    || prior.run_focus_backgrounded)
        }) {
            session.continue_run_focus_sequence_from(prior);
            return session;
        }
        if self.shell_view() == ShellView::Activity {
            return session;
        }
        session.run_focus_origin = Some(crate::app::RunFocusOrigin {
            view: self.shell_view(),
            input_mode: self.input_mode(),
            // Capturing an origin makes this a workflow-owned foreground
            // sequence. If the run is intentionally left in the background,
            // finalization also checks that Activity still owns the screen,
            // so this never redirects a background-only launch.
            auto_return: true,
        });
        session
    }

    pub(crate) fn run_focus_is_background_owned(&self) -> bool {
        self.activity()
            .is_some_and(|session| session.run_focus_backgrounded)
    }

    pub(crate) fn set_activity_run_id(&mut self, run_id: String) {
        let changed =
            self.activity().map(|activity| activity.run_id.as_str()) != Some(run_id.as_str());
        let Some(activity) = self.domain.activity_mut() else {
            return;
        };
        activity.run_id = run_id;
        self.bump_completion_generation_when(changed);
    }

    pub(crate) fn live_activity(&self) -> Option<&LiveActivity> {
        self.domain.live_activity()
    }

    pub(crate) fn set_live_activity_state(&mut self, activity: Option<LiveActivity>) {
        self.domain.set_live_activity(activity);
    }

    pub(crate) fn agent_chat(&self) -> Option<&AgentChatView> {
        self.domain.agent_chat()
    }

    pub(crate) fn agent_chat_history(&self) -> &[AgentChatView] {
        self.domain.agent_chat_history()
    }

    pub(crate) fn agent_chat_generation(&self) -> u64 {
        self.domain.agent_chat_generation()
    }

    pub(crate) fn agent_chat_mut(&mut self) -> Option<&mut AgentChatView> {
        self.domain.agent_chat_mut()
    }

    pub(crate) fn set_agent_chat(&mut self, agent: Option<AgentChatView>) {
        self.domain.set_agent_chat(agent);
    }

    pub(crate) fn agent_artifact_target_owned(&self) -> Option<std::path::PathBuf> {
        self.domain
            .agent_artifact_target()
            .map(std::path::Path::to_path_buf)
    }

    pub(crate) fn set_agent_artifact_target(&mut self, target: Option<std::path::PathBuf>) {
        self.domain.set_agent_artifact_target(target);
    }

    pub(crate) fn clear_agent_chat(&mut self) {
        self.domain.clear_agent_chat();
        *self.router.answers_mut() = Default::default();
    }

    pub(crate) fn agent_chat_or_default_mut(&mut self) -> &mut AgentChatView {
        self.domain.agent_chat_or_default_mut()
    }

    pub(crate) fn activity_or_insert_with<F>(&mut self, create: F) -> &mut ActivitySession
    where
        F: FnOnce() -> ActivitySession,
    {
        self.domain.activity_or_insert_with(create)
    }

    pub(crate) fn planner_running(&self) -> bool {
        self.engagement.planner_running()
    }

    pub(crate) fn set_planner_running(&mut self, running: bool) {
        self.engagement.set_planner_running(running);
    }

    pub(crate) fn plan_abort_requested(&self) -> bool {
        self.engagement.plan_abort_requested()
    }

    pub(crate) fn set_plan_abort_requested(&mut self, requested: bool) {
        self.engagement.set_plan_abort_requested(requested);
    }

    pub(crate) fn threat_worker_running(&self) -> bool {
        self.engagement.threat_worker_running()
    }

    pub(crate) fn set_threat_worker_running(&mut self, running: bool) {
        self.engagement.set_threat_worker_running(running);
    }

    pub(crate) fn threat_abort_requested(&self) -> bool {
        self.engagement.threat_abort_requested()
    }

    pub(crate) fn set_threat_abort_requested(&mut self, requested: bool) {
        self.engagement.set_threat_abort_requested(requested);
    }

    pub(crate) fn ui(&self) -> &UiPrefs {
        &self.ui
    }

    pub(crate) fn ui_mut(&mut self) -> &mut UiPrefs {
        &mut self.ui
    }

    pub(crate) fn advisory(&self) -> &AdvisoryState {
        self.ui.advisory()
    }

    pub(crate) fn advisory_mut(&mut self) -> &mut AdvisoryState {
        self.ui.advisory_mut()
    }

    pub(crate) fn session(&self) -> &SessionState {
        &self.session
    }

    pub(crate) fn session_mut(&mut self) -> &mut SessionState {
        &mut self.session
    }

    pub(crate) fn steer_queue(&self) -> &SteerQueue {
        self.session.steer_queue()
    }

    pub(crate) fn steer_queue_mut(&mut self) -> &mut SteerQueue {
        self.session.steer_queue_mut()
    }

    pub(crate) fn session_thinking_level(&self) -> Option<&str> {
        self.session.thinking_level()
    }

    pub(crate) fn session_thinking_level_owned(&self) -> Option<String> {
        self.session.thinking_level_owned()
    }

    pub(crate) fn set_session_thinking_level(&mut self, thinking_level: Option<String>) {
        self.session.set_thinking_level(thinking_level);
    }
}

fn changes_are_source_file_only(changes: &[WorkspaceChange]) -> bool {
    changes.iter().all(|change| {
        matches!(
            change,
            WorkspaceChange::FileChanged(_)
                | WorkspaceChange::FileDeleted(_)
                | WorkspaceChange::FileMoved { .. }
        )
    })
}

pub(crate) fn contextual_surface_view(view: ShellView) -> bool {
    matches!(
        view,
        ShellView::Catalog
            | ShellView::CommandPalette
            | ShellView::ConfirmDialog
            | ShellView::QuitConfirm
            | ShellView::ThemePicker
            | ShellView::Keymap
            | ShellView::UpdateAvailable
            | ShellView::Help
            | ShellView::Jobs
            | ShellView::Replay
            | ShellView::Trace
            | ShellView::RunDiff
            | ShellView::Scene
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contextual_utilities_restore_the_exact_workflow_origin() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Prove));
        app.router
            .workbench_mut()
            .set_focus(crate::ui_view_models::PhaseSurfaceId::ProveReceipt);
        app.set_input_mode(InputMode::Prompt);

        app.set_shell_view(ShellView::Help);
        assert_eq!(app.router.overlay_origin(), Some(ShellView::Workbench));
        assert_eq!(app.input_mode(), InputMode::Prompt);

        app.set_shell_view(ShellView::Jobs);
        assert_eq!(app.router.overlay_origin(), Some(ShellView::Workbench));
        assert!(app.restore_contextual_surface_origin());

        assert_eq!(app.shell_view(), ShellView::Workbench);
        assert_eq!(app.input_mode(), InputMode::Prompt);
        assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Prove));
        assert_eq!(
            app.router.workbench().focus_for(WorkbenchPage::Prove),
            crate::ui_view_models::PhaseSurfaceId::ProveReceipt
        );
    }

    #[test]
    fn returning_to_setup_refreshes_stale_map_artifacts() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let task = PlanningTaskId::GatherRepoContext;
        let row = PlanningTaskRow::for_task(task, target.path());
        assert_eq!(row.artifact_state, PlanningArtifactState::Missing);
        app.engagement.planning_picker_mut().open_phase_profiled(
            WorkflowPhase::Map,
            vec![row],
            [task].into_iter().collect(),
            false,
        );
        app.engagement
            .planning_picker_mut()
            .set_return_to_setup(true);
        app.engagement.planning_picker_mut().mark_artifacts_stale();

        let artifact = task.artifact_path(target.path()).unwrap();
        crate::test_support::write_current_context_snapshot(target.path(), serde_json::json!({}));
        assert_eq!(artifact, kuzushi_core::context_snapshot_path(target.path()));
        app.set_shell_view(ShellView::Activity);

        app.set_shell_view(ShellView::Setup);

        let picker = app.engagement.planning_picker();
        let row = picker.tasks().iter().find(|row| row.id == task).unwrap();
        assert_eq!(row.artifact_state, PlanningArtifactState::Cached);
        assert!(!picker.selected().contains(&task));
        assert!(!picker.artifacts_stale());
    }

    #[test]
    fn contextual_surface_replacement_does_not_nest_origins() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Report);
        app.set_input_mode(InputMode::Navigate);

        for view in [ShellView::Scene, ShellView::Trace, ShellView::Replay] {
            app.set_shell_view(view);
            assert_eq!(app.router.overlay_origin(), Some(ShellView::Report));
        }

        assert!(app.restore_contextual_surface_origin());
        assert_eq!(app.shell_view(), ShellView::Report);
        assert_eq!(app.input_mode(), InputMode::Navigate);
    }

    #[test]
    fn contextual_decks_leave_activity_back_history_pointing_at_review() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Review));
        app.set_input_mode(InputMode::Prompt);
        app.sync_view_change();

        app.set_shell_view(ShellView::Activity);
        app.set_input_mode(InputMode::Navigate);
        app.sync_view_change();
        app.set_input_mode(InputMode::Prompt);

        for view in [ShellView::Replay, ShellView::Trace, ShellView::Jobs] {
            app.set_shell_view(view);
            assert!(
                !app.sync_view_change(),
                "{view:?} must be history-transparent"
            );
        }

        assert!(app.restore_contextual_surface_origin());
        assert_eq!(app.shell_view(), ShellView::Activity);
        assert_eq!(app.input_mode(), InputMode::Prompt);
        assert!(!app.sync_view_change());

        app.go_back();
        assert_eq!(app.shell_view(), ShellView::Workbench);
        assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Review));
        assert_eq!(app.input_mode(), InputMode::Prompt);
    }

    #[test]
    fn unknown_command_from_workbench_sets_error_notice_and_keeps_log() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);

        let effects = app
            .reduce_command_effects(&ShellCommand::Unknown("not-a-command".to_string()))
            .expect("unknown command handled synchronously");

        assert!(effects.is_empty());
        let notice = app.advisory().notice.as_ref().expect("visible notice");
        assert_eq!(notice.severity, NoticeSeverity::Error);
        assert!(notice.message.contains("unknown command"));
        assert!(notice.message.contains("Next:"));
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.prefix == "error" && line.body.contains("not-a-command")));
    }

    #[test]
    fn ordinary_view_error_log_remains_transcript_only() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Tools);

        app.log("error", "visible in this view's transcript");

        assert!(app.advisory().notice.is_none());
        assert!(app.log_lines().iter().any(|line| line.prefix == "error"));
    }

    #[test]
    fn run_preparation_error_from_workbench_uses_notice_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_shell_view(ShellView::Workbench);
        let expected_title = app
            .registry()
            .resolve_tool("semgrep:scan")
            .unwrap()
            .description
            .trim()
            .to_string();

        let effects = app.prepare_run_tool_launch(RunToolPreparation {
            tool_name: "semgrep:scan".to_string(),
            input: Some("{".to_string()),
            target: Some(workspace.root().to_path_buf()),
        });

        assert!(effects.is_empty());
        let notice = app.advisory().notice.as_ref().expect("visible notice");
        assert_eq!(notice.severity, NoticeSeverity::Error);
        assert!(notice
            .message
            .contains("legacy structured run input is invalid"));
        assert!(notice
            .message
            .contains("Next: run semgrep:scan with defaults"));
        assert!(notice.message.contains("options semgrep:scan"));
        assert_blocked_preparation_run(temp.path(), &expected_title);
    }

    #[test]
    fn descriptor_rejection_is_persisted_as_a_failed_shell_call() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let expected_title = app
            .registry()
            .resolve_tool("workspace:status")
            .unwrap()
            .description
            .trim()
            .to_string();

        let effects = app.prepare_run_tool_launch(RunToolPreparation {
            tool_name: "workspace:status".to_string(),
            input: Some(r#"{"unknownOption":true}"#.to_string()),
            target: Some(workspace.root().to_path_buf()),
        });

        assert!(effects.is_empty());
        assert_blocked_preparation_run(temp.path(), &expected_title);
    }

    fn assert_blocked_preparation_run(target: &std::path::Path, expected_title: &str) {
        let entry = kuzushi_core::list_recent_run_summary_entries(target, 1)
            .unwrap()
            .pop()
            .unwrap();
        let read = kuzushi_core::run_lifecycle::load_run_projection(target, &entry.run_id).unwrap();
        assert_eq!(
            read.projection.terminal.as_ref().map(|item| item.status),
            Some(kuzushi_core::run_lifecycle::RunItemStatus::Blocked)
        );
        let task = read.projection.tasks.values().next().unwrap();
        assert_eq!(task.title.as_str(), expected_title);
        let call = read.projection.calls.values().next().unwrap();
        assert_eq!(
            call.status,
            kuzushi_core::run_lifecycle::RunItemStatus::Blocked
        );
        assert!(!read.projection.artifacts.is_empty());
        assert!(read
            .projection
            .artifacts
            .values()
            .all(|artifact| artifact.producing_item_id == call.item_id));
        assert_eq!(
            call.result_artifact
                .as_ref()
                .map(|artifact| artifact.path.as_str()),
            Some("result.json")
        );
    }
}
