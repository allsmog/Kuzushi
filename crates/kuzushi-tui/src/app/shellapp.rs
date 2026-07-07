use super::*;

#[derive(Debug)]
pub struct ShellApp {
    pub(crate) editor: EditorState,
    pub(in crate::app) log: LogState,
    pub shell_view: ShellView,
    pub(crate) session: SessionState,
    pub(crate) domain: DomainCache,
    pub(crate) workbench_cache: std::cell::RefCell<WorkbenchCache>,
    pub advisory: AdvisoryState,
    /// Per-task duration history for ETA forecasting in the ambient
    /// progress chip. Loaded from `<target>/.kuzushi/task-durations.json`.
    pub(crate) task_durations: crate::app::TaskDurationStore,
    /// Engagement-scoped planning runtime state: current phase, queued steps,
    /// failures/retries, target classification, planning picker route state,
    /// and per-run option overlays.
    pub engagement: EngagementState,
    /// Route-local scroll/filter state for simple stacked shell surfaces.
    pub router: RouterState,
    pub(crate) ui: UiPrefs,
    pub(crate) jobs: JobHub,
    pub(crate) runtime_state: RuntimeState,
    pub(crate) tool_run: ToolRunState,
    #[cfg(test)]
    pub(crate) option_persistence_enabled_for_test: bool,
}

impl ShellApp {
    pub(crate) fn editor(&self) -> &EditorState {
        &self.editor
    }

    pub(crate) fn editor_mut(&mut self) -> &mut EditorState {
        &mut self.editor
    }

    pub fn log(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        self.log.push(prefix, body);
    }

    pub fn log_lines(&self) -> &[LogLine] {
        self.log.lines()
    }

    pub fn log_len(&self) -> usize {
        self.log.len()
    }

    pub fn clear_log(&mut self) {
        self.log.clear();
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
        self.shell_view = ShellView::Options;
    }

    #[doc(hidden)]
    pub fn open_auth_method_picker_for_test(&mut self, provider: impl Into<String>) {
        self.router.auth_picker_mut().open(provider.into());
        self.shell_view = ShellView::AuthMethodPicker;
    }

    #[doc(hidden)]
    pub fn open_threat_view_for_test(&mut self, view: ThreatView) {
        self.router.threat_mut().open(view);
        self.shell_view = ShellView::Threat;
    }

    #[doc(hidden)]
    pub fn open_patch_for_test(&mut self, alias: impl Into<String>) {
        self.router.patch_mut().open(alias);
        self.shell_view = ShellView::Patch;
    }

    #[doc(hidden)]
    pub fn open_run_diff_for_test(&mut self, left: impl Into<String>, right: impl Into<String>) {
        self.router.run_diff_mut().open(left, right);
        self.shell_view = ShellView::RunDiff;
    }

    #[doc(hidden)]
    pub fn open_replay_for_test(&mut self, run_id: impl Into<String>) {
        self.router.replay_mut().open(run_id);
        self.shell_view = ShellView::Replay;
    }

    #[doc(hidden)]
    pub fn open_trace_for_test(&mut self, run_id: impl Into<String>) {
        self.router.trace_mut().open(run_id);
        self.shell_view = ShellView::Trace;
    }

    #[doc(hidden)]
    pub fn open_interruption_for_test(&mut self, view: InterruptionView) {
        self.router.interruption_mut().open(view);
        self.shell_view = ShellView::Interruption;
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
        self.router.set_focused_module(module);
    }

    pub(crate) fn clear_focused_module(&mut self) {
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
        self.log.replace_for_test(lines);
    }

    #[doc(hidden)]
    pub fn log_lines_mut_for_test(&mut self) -> &mut [LogLine] {
        self.log.lines_mut_for_test()
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
        self.session.set_target(target);
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
        self.domain.set_scan(scan);
    }

    #[cfg(test)]
    pub(crate) fn scan_is_none(&self) -> bool {
        self.domain.scan().is_none()
    }

    pub(crate) fn agent_cancel_token(&self) -> Option<&ScanCancellation> {
        self.runtime_state.agent_cancel()
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

    pub(crate) fn tool_is_running(&self) -> bool {
        self.tool_run.is_running()
    }

    pub(crate) fn running_tool_name_owned(&self) -> Option<String> {
        self.tool_run.active_name_owned()
    }

    pub(crate) fn tool_cancel_token(&self) -> Option<&ScanCancellation> {
        self.tool_run.cancel()
    }

    pub(crate) fn active_tool_run_id(&self) -> Option<&str> {
        self.tool_run.run_id()
    }

    pub(crate) fn take_active_tool_run_id(&mut self) -> Option<String> {
        self.tool_run.take_run_id()
    }

    pub(crate) fn active_model_override(&self) -> Option<&str> {
        self.tool_run.active_model_override()
    }

    pub(crate) fn set_active_model_override(&mut self, model: Option<String>) {
        self.tool_run.set_active_model_override(model);
    }

    pub(crate) fn start_tool_run(
        &mut self,
        tool_name: String,
        cancel: ScanCancellation,
        run_id: String,
        model_override: Option<String>,
    ) {
        self.tool_run
            .start(tool_name, cancel, run_id, model_override);
    }

    pub(crate) fn finish_tool_run(&mut self) {
        self.tool_run.finish();
    }

    pub(crate) fn clear_finished_tool_run_slot(&mut self) {
        self.tool_run.clear_finished_run_slot();
    }

    pub(crate) fn request_tool_abort_flag(&mut self) {
        self.tool_run.request_abort();
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

    pub(crate) fn ctrl_c_armed_at(&self) -> Option<Instant> {
        self.ui.ctrl_c_armed_at()
    }

    pub(crate) fn set_ctrl_c_armed_at(&mut self, armed_at: Option<Instant>) {
        self.ui.set_ctrl_c_armed_at(armed_at);
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

    pub(crate) fn findings(&self) -> &[Finding] {
        self.domain.findings()
    }

    pub(crate) fn findings_total_count(&self) -> usize {
        self.domain.findings_total_count()
    }

    pub(crate) fn findings_are_partial(&self) -> bool {
        self.domain.findings_are_partial()
    }

    pub(crate) fn findings_mut(&mut self) -> &mut Vec<Finding> {
        self.domain.findings_mut()
    }

    pub fn set_findings(&mut self, findings: Vec<Finding>) {
        self.domain.set_findings(findings);
    }

    pub(crate) fn set_findings_total_count(&mut self, total: usize) {
        self.domain.set_findings_total_count(total);
    }

    pub(crate) fn review_decisions(&self) -> &[kuzushi_core::findings::ReviewDecisionRecord] {
        self.domain.review_decisions()
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
        self.domain.set_activity(activity);
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

    pub(crate) fn agent_chat_mut(&mut self) -> Option<&mut AgentChatView> {
        self.domain.agent_chat_mut()
    }

    pub(crate) fn set_agent_chat(&mut self, agent: Option<AgentChatView>) {
        self.domain.set_agent_chat(agent);
    }

    pub(crate) fn clear_agent_chat(&mut self) {
        self.domain.clear_agent_chat();
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

    pub(crate) fn session(&self) -> &SessionState {
        &self.session
    }

    pub(crate) fn session_mut(&mut self) -> &mut SessionState {
        &mut self.session
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
