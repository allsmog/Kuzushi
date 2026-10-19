mod answers;
#[path = "options_browser.rs"]
mod options_browser;
mod pickers;
mod report;
mod run_artifact;
pub use run_artifact::RunArtifactRouteState;
#[cfg(test)]
mod run_artifact_tests;
pub(crate) use answers::{AnswerFocus, AnswersRouteState};
pub(crate) use options_browser::{OptionsBrowserState, ToolOptionEdit};
pub(crate) use report::ReportOrigin;
pub(crate) use report::ReportStudyRef;
pub use report::{ReportReceipt, ReportRouteState};

use super::ActivityRouteState;
pub(crate) use pickers::ConfigModelPickerOrigin;
pub(crate) use pickers::PendingTargetIntent;
pub use pickers::{
    AuthPickerRouteState, MapRunConfigRouteState, MapRunConfigRowId, ModelPickerRouteState,
    PlanningPickerRouteState, SetupEditor, SetupRouteState, SetupRowId, TargetPickerRouteState,
};
use std::{path::PathBuf, time::Instant};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RouterState {
    pub(crate) strategy_inspection: Option<(PathBuf, String)>,
    pub(crate) lessons: crate::app::lessons::LessonsRouteState,
    pub(crate) relationships: crate::app::RelationshipsRouteState,
    answers: AnswersRouteState,
    current: crate::app::ShellView,
    overlay_origin: Option<crate::app::ShellView>,
    overlay_input_mode: Option<crate::app::InputMode>,
    focused_module: Option<String>,
    auth_screen_snapshot: Option<crate::app::AuthScreenSnapshot>,
    boot_splash_snapshot: Option<crate::app::BootSplashSnapshot>,
    command_palette_snapshot: Option<crate::app::CommandPaletteSnapshot>,
    config_screen_snapshot: Option<crate::app::ConfigScreenSnapshot>,
    context_screen_snapshot: Option<crate::app::ContextScreenSnapshot>,
    cost_screen_snapshot: Option<crate::app::CostScreenSnapshot>,
    confirm_dialog_snapshot: Option<crate::app::ConfirmDialogSnapshot>,
    health_snapshot: Option<crate::app::HealthSnapshot>,
    help_screen_snapshot: Option<crate::app::HelpScreenSnapshot>,
    interruption_snapshot: Option<crate::app::InterruptionSnapshot>,
    keymap_snapshot: Option<crate::app::KeymapSnapshot>,
    options_screen_snapshot: Option<crate::app::OptionsScreenSnapshot>,
    options: crate::app::OptionsView,
    options_browser: OptionsBrowserState,
    interruption: InterruptionRouteState,
    quit_confirm_snapshot: Option<crate::app::QuitConfirmSnapshot>,
    quit_confirm_scroll: usize,
    sast_tasks_snapshot: Option<crate::app::SastTasksSnapshot>,
    theme_picker_snapshot: Option<crate::app::ThemePickerSnapshot>,
    update_available_snapshot: Option<crate::app::UpdateAvailableSnapshot>,
    navigation: NavigationRouteState,
    auth: AuthRouteState,
    command_palette: CommandPaletteRouteState,
    model_picker: ModelPickerRouteState,
    auth_picker: AuthPickerRouteState,
    target_picker: TargetPickerRouteState,
    setup: SetupRouteState,
    report: ReportRouteState,
    file_picker: FilePickerRouteState,
    activity: ActivityRouteState,
    workbench: WorkbenchRouteState,
    campaign: super::CampaignRouteState,
    scope_review: Option<crate::app::ScopeReviewState>,
    coverage: super::CoverageRouteState,
    catalog: CatalogRouteState,
    findings: FindingsRouteState,
    help: HelpRouteState,
    tools: ToolsRouteState,
    default_scroll: DefaultScrollRouteState,
    history: ScrollRouteState,
    kb: ScrollRouteState,
    modules: ScrollRouteState,
    logs: LogsRouteState,
    scene: SceneRouteState,
    threat: ThreatRouteState,
    tune: TuneRouteState,
    prompts: PromptsRouteState,
    actor_detail: ActorDetailRouteState,
    run_diff: RunDiffRouteState,
    replay: RunArtifactRouteState,
    trace: RunArtifactRouteState,
    patch: PatchRouteState,
}

impl RouterState {
    pub(crate) fn answers(&self) -> &AnswersRouteState {
        &self.answers
    }

    pub(crate) fn answers_mut(&mut self) -> &mut AnswersRouteState {
        &mut self.answers
    }

    pub(crate) fn current(&self) -> crate::app::ShellView {
        self.current
    }

    pub(crate) fn set_current(&mut self, view: crate::app::ShellView) {
        self.reset_changed_run_scroll(view);
        self.current = view;
    }

    fn reset_changed_run_scroll(&mut self, view: crate::app::ShellView) {
        let route = match view {
            crate::app::ShellView::Replay => &mut self.replay,
            crate::app::ShellView::Trace => &mut self.trace,
            _ => return,
        };
        if std::mem::take(&mut route.scroll_reset_pending) {
            self.default_scroll.reset();
        }
    }

    pub(crate) fn overlay_origin(&self) -> Option<crate::app::ShellView> {
        self.overlay_origin
    }

    pub(crate) fn set_overlay_origin(&mut self, origin: Option<crate::app::ShellView>) {
        self.overlay_origin = origin;
    }

    pub(crate) fn overlay_input_mode(&self) -> Option<crate::app::InputMode> {
        self.overlay_input_mode
    }

    pub(crate) fn set_overlay_input_mode(&mut self, mode: Option<crate::app::InputMode>) {
        self.overlay_input_mode = mode;
    }

    pub(crate) fn focused_module(&self) -> Option<&str> {
        self.focused_module.as_deref()
    }

    pub(crate) fn focused_module_owned(&self) -> Option<String> {
        self.focused_module.clone()
    }

    pub(crate) fn set_focused_module(&mut self, module: Option<String>) {
        self.focused_module = module;
    }

    pub(crate) fn clear_focused_module(&mut self) {
        self.focused_module = None;
    }

    pub(crate) fn auth_screen_snapshot(&self) -> Option<&crate::app::AuthScreenSnapshot> {
        self.auth_screen_snapshot.as_ref()
    }

    pub(crate) fn set_auth_screen_snapshot(
        &mut self,
        snapshot: Option<crate::app::AuthScreenSnapshot>,
    ) {
        self.auth_screen_snapshot = snapshot;
    }

    pub(crate) fn boot_splash_snapshot(&self) -> Option<&crate::app::BootSplashSnapshot> {
        self.boot_splash_snapshot.as_ref()
    }

    pub(crate) fn set_boot_splash_snapshot(
        &mut self,
        snapshot: Option<crate::app::BootSplashSnapshot>,
    ) {
        self.boot_splash_snapshot = snapshot;
    }

    pub(crate) fn command_palette_snapshot(&self) -> Option<&crate::app::CommandPaletteSnapshot> {
        self.command_palette_snapshot.as_ref()
    }

    pub(crate) fn set_command_palette_snapshot(
        &mut self,
        snapshot: Option<crate::app::CommandPaletteSnapshot>,
    ) {
        self.command_palette_snapshot = snapshot;
    }

    pub(crate) fn config_screen_snapshot(&self) -> Option<&crate::app::ConfigScreenSnapshot> {
        self.config_screen_snapshot.as_ref()
    }

    pub(crate) fn set_config_screen_snapshot(
        &mut self,
        snapshot: Option<crate::app::ConfigScreenSnapshot>,
    ) {
        self.config_screen_snapshot = snapshot;
    }

    pub(crate) fn context_screen_snapshot(&self) -> Option<&crate::app::ContextScreenSnapshot> {
        self.context_screen_snapshot.as_ref()
    }

    pub(crate) fn set_context_screen_snapshot(
        &mut self,
        snapshot: Option<crate::app::ContextScreenSnapshot>,
    ) {
        self.context_screen_snapshot = snapshot;
    }

    pub(crate) fn cost_screen_snapshot(&self) -> Option<&crate::app::CostScreenSnapshot> {
        self.cost_screen_snapshot.as_ref()
    }

    pub(crate) fn set_cost_screen_snapshot(
        &mut self,
        snapshot: Option<crate::app::CostScreenSnapshot>,
    ) {
        self.cost_screen_snapshot = snapshot;
    }

    pub(crate) fn confirm_dialog_snapshot(&self) -> Option<&crate::app::ConfirmDialogSnapshot> {
        self.confirm_dialog_snapshot.as_ref()
    }

    pub(crate) fn set_confirm_dialog_snapshot(
        &mut self,
        snapshot: Option<crate::app::ConfirmDialogSnapshot>,
    ) {
        self.confirm_dialog_snapshot = snapshot;
    }

    pub(crate) fn health_snapshot(&self) -> Option<&crate::app::HealthSnapshot> {
        self.health_snapshot.as_ref()
    }

    pub(crate) fn set_health_snapshot(&mut self, snapshot: Option<crate::app::HealthSnapshot>) {
        self.health_snapshot = snapshot;
    }

    pub(crate) fn help_screen_snapshot(&self) -> Option<&crate::app::HelpScreenSnapshot> {
        self.help_screen_snapshot.as_ref()
    }

    pub(crate) fn set_help_screen_snapshot(
        &mut self,
        snapshot: Option<crate::app::HelpScreenSnapshot>,
    ) {
        self.help_screen_snapshot = snapshot;
    }

    pub(crate) fn interruption_snapshot(&self) -> Option<&crate::app::InterruptionSnapshot> {
        self.interruption_snapshot.as_ref()
    }

    pub(crate) fn set_interruption_snapshot(
        &mut self,
        snapshot: Option<crate::app::InterruptionSnapshot>,
    ) {
        self.interruption_snapshot = snapshot;
    }

    pub(crate) fn keymap_snapshot(&self) -> Option<&crate::app::KeymapSnapshot> {
        self.keymap_snapshot.as_ref()
    }

    pub(crate) fn set_keymap_snapshot(&mut self, snapshot: Option<crate::app::KeymapSnapshot>) {
        self.keymap_snapshot = snapshot;
    }

    pub(crate) fn options_screen_snapshot(&self) -> Option<&crate::app::OptionsScreenSnapshot> {
        self.options_screen_snapshot.as_ref()
    }

    pub(crate) fn set_options_screen_snapshot(
        &mut self,
        snapshot: Option<crate::app::OptionsScreenSnapshot>,
    ) {
        self.options_screen_snapshot = snapshot;
    }

    pub(crate) fn options(&self) -> &crate::app::OptionsView {
        &self.options
    }

    pub(crate) fn set_options(&mut self, options: crate::app::OptionsView) {
        if self.options.tool_name != options.tool_name {
            if let Some(edit) = self.options_browser.edit.take() {
                self.options_browser
                    .drafts
                    .insert((edit.tool, edit.option), edit.field);
            }
            self.options_browser.selected = None;
            self.options_browser.detail_scroll = 0;
            self.options_browser.notice = None;
        }
        if self.options.filter != options.filter {
            self.options_browser.detail_scroll = 0;
        }
        self.options = options;
    }

    pub(crate) fn options_browser(&self) -> &OptionsBrowserState {
        &self.options_browser
    }

    pub(crate) fn options_browser_mut(&mut self) -> &mut OptionsBrowserState {
        &mut self.options_browser
    }

    pub(crate) fn quit_confirm_scroll(&self) -> usize {
        self.quit_confirm_scroll
    }
    pub(crate) fn set_quit_confirm_scroll(&mut self, offset: usize) {
        self.quit_confirm_scroll = offset.min(u16::MAX as usize);
    }

    pub(crate) fn quit_confirm_snapshot(&self) -> Option<&crate::app::QuitConfirmSnapshot> {
        self.quit_confirm_snapshot.as_ref()
    }

    pub(crate) fn set_quit_confirm_snapshot(
        &mut self,
        snapshot: Option<crate::app::QuitConfirmSnapshot>,
    ) {
        self.quit_confirm_snapshot = snapshot;
        self.quit_confirm_scroll = 0;
    }

    pub(crate) fn sast_tasks_snapshot(&self) -> Option<&crate::app::SastTasksSnapshot> {
        self.sast_tasks_snapshot.as_ref()
    }

    pub(crate) fn set_sast_tasks_snapshot(
        &mut self,
        snapshot: Option<crate::app::SastTasksSnapshot>,
    ) {
        self.sast_tasks_snapshot = snapshot;
    }

    pub(crate) fn theme_picker_snapshot(&self) -> Option<&crate::app::ThemePickerSnapshot> {
        self.theme_picker_snapshot.as_ref()
    }

    pub(crate) fn set_theme_picker_snapshot(
        &mut self,
        snapshot: Option<crate::app::ThemePickerSnapshot>,
    ) {
        self.theme_picker_snapshot = snapshot;
    }

    pub(crate) fn update_available_snapshot(&self) -> Option<&crate::app::UpdateAvailableSnapshot> {
        self.update_available_snapshot.as_ref()
    }

    pub(crate) fn set_update_available_snapshot(
        &mut self,
        snapshot: Option<crate::app::UpdateAvailableSnapshot>,
    ) {
        self.update_available_snapshot = snapshot;
    }

    pub(crate) fn navigation(&self) -> &NavigationRouteState {
        &self.navigation
    }

    pub(crate) fn navigation_mut(&mut self) -> &mut NavigationRouteState {
        &mut self.navigation
    }

    pub(crate) fn auth(&self) -> &AuthRouteState {
        &self.auth
    }

    pub(crate) fn auth_mut(&mut self) -> &mut AuthRouteState {
        &mut self.auth
    }

    pub(crate) fn command_palette(&self) -> &CommandPaletteRouteState {
        &self.command_palette
    }

    pub(crate) fn command_palette_mut(&mut self) -> &mut CommandPaletteRouteState {
        &mut self.command_palette
    }

    pub(crate) fn model_picker(&self) -> &ModelPickerRouteState {
        &self.model_picker
    }

    pub(crate) fn model_picker_mut(&mut self) -> &mut ModelPickerRouteState {
        &mut self.model_picker
    }

    pub(crate) fn auth_picker(&self) -> &AuthPickerRouteState {
        &self.auth_picker
    }

    pub(crate) fn auth_picker_mut(&mut self) -> &mut AuthPickerRouteState {
        &mut self.auth_picker
    }

    pub(crate) fn target_picker(&self) -> &TargetPickerRouteState {
        &self.target_picker
    }

    pub(crate) fn target_picker_mut(&mut self) -> &mut TargetPickerRouteState {
        &mut self.target_picker
    }

    pub(crate) fn setup(&self) -> &SetupRouteState {
        &self.setup
    }

    pub(crate) fn setup_mut(&mut self) -> &mut SetupRouteState {
        &mut self.setup
    }

    pub(crate) fn report(&self) -> &ReportRouteState {
        &self.report
    }

    pub(crate) fn report_mut(&mut self) -> &mut ReportRouteState {
        &mut self.report
    }

    pub(crate) fn file_picker(&self) -> &FilePickerRouteState {
        &self.file_picker
    }

    pub(crate) fn file_picker_mut(&mut self) -> &mut FilePickerRouteState {
        &mut self.file_picker
    }

    pub(crate) fn activity(&self) -> &ActivityRouteState {
        &self.activity
    }

    pub(crate) fn activity_mut(&mut self) -> &mut ActivityRouteState {
        &mut self.activity
    }

    pub(crate) fn workbench(&self) -> &WorkbenchRouteState {
        &self.workbench
    }

    pub(crate) fn workbench_mut(&mut self) -> &mut WorkbenchRouteState {
        &mut self.workbench
    }

    pub(crate) fn scope_review(&self) -> &Option<crate::app::ScopeReviewState> {
        &self.scope_review
    }

    pub(crate) fn scope_review_mut(&mut self) -> &mut Option<crate::app::ScopeReviewState> {
        &mut self.scope_review
    }

    pub(crate) fn campaign(&self) -> &super::CampaignRouteState {
        &self.campaign
    }

    pub(crate) fn campaign_mut(&mut self) -> &mut super::CampaignRouteState {
        &mut self.campaign
    }

    pub(crate) fn coverage(&self) -> &super::CoverageRouteState {
        &self.coverage
    }

    pub(crate) fn coverage_mut(&mut self) -> &mut super::CoverageRouteState {
        &mut self.coverage
    }

    pub(crate) fn catalog(&self) -> &CatalogRouteState {
        &self.catalog
    }

    pub(crate) fn catalog_mut(&mut self) -> &mut CatalogRouteState {
        &mut self.catalog
    }

    pub(crate) fn findings(&self) -> &FindingsRouteState {
        &self.findings
    }

    pub(crate) fn findings_mut(&mut self) -> &mut FindingsRouteState {
        &mut self.findings
    }

    pub(crate) fn help(&self) -> &HelpRouteState {
        &self.help
    }

    pub(crate) fn help_mut(&mut self) -> &mut HelpRouteState {
        &mut self.help
    }

    pub(crate) fn tools(&self) -> &ToolsRouteState {
        &self.tools
    }

    pub(crate) fn tools_mut(&mut self) -> &mut ToolsRouteState {
        &mut self.tools
    }

    pub(crate) fn default_scroll(&self) -> &DefaultScrollRouteState {
        &self.default_scroll
    }

    pub(crate) fn default_scroll_mut(&mut self) -> &mut DefaultScrollRouteState {
        &mut self.default_scroll
    }

    pub(crate) fn history(&self) -> &ScrollRouteState {
        &self.history
    }

    pub(crate) fn history_mut(&mut self) -> &mut ScrollRouteState {
        &mut self.history
    }

    pub(crate) fn kb(&self) -> &ScrollRouteState {
        &self.kb
    }

    pub(crate) fn kb_mut(&mut self) -> &mut ScrollRouteState {
        &mut self.kb
    }

    pub(crate) fn modules(&self) -> &ScrollRouteState {
        &self.modules
    }

    pub(crate) fn modules_mut(&mut self) -> &mut ScrollRouteState {
        &mut self.modules
    }

    pub(crate) fn logs(&self) -> &LogsRouteState {
        &self.logs
    }

    pub(crate) fn logs_mut(&mut self) -> &mut LogsRouteState {
        &mut self.logs
    }

    pub(crate) fn scene(&self) -> &SceneRouteState {
        &self.scene
    }

    pub(crate) fn scene_mut(&mut self) -> &mut SceneRouteState {
        &mut self.scene
    }

    pub(crate) fn threat(&self) -> &ThreatRouteState {
        &self.threat
    }

    pub(crate) fn threat_mut(&mut self) -> &mut ThreatRouteState {
        &mut self.threat
    }

    pub(crate) fn tune(&self) -> &TuneRouteState {
        &self.tune
    }

    pub(crate) fn tune_mut(&mut self) -> &mut TuneRouteState {
        &mut self.tune
    }

    pub(crate) fn prompts(&self) -> &PromptsRouteState {
        &self.prompts
    }

    pub(crate) fn prompts_mut(&mut self) -> &mut PromptsRouteState {
        &mut self.prompts
    }

    pub(crate) fn actor_detail(&self) -> &ActorDetailRouteState {
        &self.actor_detail
    }

    pub(crate) fn actor_detail_mut(&mut self) -> &mut ActorDetailRouteState {
        &mut self.actor_detail
    }

    pub(crate) fn run_diff(&self) -> &RunDiffRouteState {
        &self.run_diff
    }

    pub(crate) fn run_diff_mut(&mut self) -> &mut RunDiffRouteState {
        &mut self.run_diff
    }

    pub(crate) fn interruption(&self) -> &InterruptionRouteState {
        &self.interruption
    }

    pub(crate) fn interruption_mut(&mut self) -> &mut InterruptionRouteState {
        &mut self.interruption
    }

    pub(crate) fn replay(&self) -> &RunArtifactRouteState {
        &self.replay
    }

    pub(crate) fn replay_mut(&mut self) -> &mut RunArtifactRouteState {
        &mut self.replay
    }

    pub(crate) fn trace(&self) -> &RunArtifactRouteState {
        &self.trace
    }

    pub(crate) fn trace_mut(&mut self) -> &mut RunArtifactRouteState {
        &mut self.trace
    }

    pub(crate) fn patch(&self) -> &PatchRouteState {
        &self.patch
    }

    pub(crate) fn patch_mut(&mut self) -> &mut PatchRouteState {
        &mut self.patch
    }
}

/// The safety boundary an investigation plan runs under. Both variants map
/// onto the real `verify:finding` `mode` option — this is a routing choice
/// the operator makes on the plan card, not decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InvestigationBoundary {
    /// `mode=model`: static adversarial analysis, no code is executed.
    #[default]
    StaticOnly,
    /// `mode=empirical`: proof-of-concept construction with sandboxed
    /// execution against the local checkout.
    LocalReproduction,
}

impl InvestigationBoundary {
    pub(crate) fn mode_value(self) -> &'static str {
        match self {
            Self::StaticOnly => "model",
            Self::LocalReproduction => "empirical",
        }
    }

    pub(crate) fn toggled(self) -> Self {
        match self {
            Self::StaticOnly => Self::LocalReproduction,
            Self::LocalReproduction => Self::StaticOnly,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkbenchRouteState {
    focus: Option<crate::ui_view_models::PhaseSurfaceId>,
    zoom: crate::app::WorkbenchZoom,
    page: Option<crate::app::WorkbenchPage>,
    scroll: crate::app::WorkbenchSurfaceScroll,
    review: crate::app::WorkbenchReviewState,
    investigation: Option<(
        InvestigationBoundary,
        kuzushi_core::verification::application::LocalVerificationReadiness,
    )>,
    chains_open: bool,
    trace_open: bool,
    trace_origin_focus: Option<crate::ui_view_models::PhaseSurfaceId>,
}

impl Default for WorkbenchRouteState {
    fn default() -> Self {
        Self {
            focus: None,
            zoom: crate::app::WorkbenchZoom::default(),
            page: None,
            scroll: crate::app::WorkbenchSurfaceScroll::default(),
            review: crate::app::WorkbenchReviewState::default(),
            investigation: None,
            chains_open: false,
            trace_open: false,
            trace_origin_focus: None,
        }
    }
}

impl WorkbenchRouteState {
    pub(crate) fn reset_for_target(&mut self) {
        *self = Self::default();
    }

    /// The focused surface for `page`. A focus stored while another page was
    /// active falls back to this page's finding-list-role surface, so phase
    /// changes never alias focus onto an unrelated surface.
    pub(crate) fn focus_for(
        &self,
        page: crate::app::WorkbenchPage,
    ) -> crate::ui_view_models::PhaseSurfaceId {
        self.focus
            .filter(|surface| surface.page() == page)
            .unwrap_or_else(|| page.findings_surface())
    }

    pub(crate) fn set_focus(&mut self, focus: crate::ui_view_models::PhaseSurfaceId) {
        self.focus = Some(focus);
        self.zoom.follow_focus(focus);
    }

    pub(crate) fn investigation_draft(&self) -> Option<InvestigationBoundary> {
        self.investigation.map(|(boundary, _)| boundary)
    }

    pub(crate) fn investigation_readiness(
        &self,
    ) -> Option<kuzushi_core::verification::application::LocalVerificationReadiness> {
        self.investigation.map(|(_, readiness)| readiness)
    }

    pub(crate) fn open_investigation_draft(
        &mut self,
        readiness: kuzushi_core::verification::application::LocalVerificationReadiness,
    ) {
        self.trace_open = false;
        self.scroll
            .set(crate::ui_view_models::PhaseSurfaceId::ProveInvestigation, 0);
        self.investigation = Some((InvestigationBoundary::default(), readiness));
    }

    pub(crate) fn close_investigation_draft(&mut self) {
        self.investigation = None;
    }

    pub(crate) fn toggle_investigation_boundary(&mut self) -> Option<InvestigationBoundary> {
        self.scroll
            .set(crate::ui_view_models::PhaseSurfaceId::ProveInvestigation, 0);
        self.investigation = self
            .investigation
            .map(|(boundary, readiness)| (boundary.toggled(), readiness));
        self.investigation_draft()
    }

    pub(crate) fn chains_view_open(&self) -> bool {
        self.chains_open
    }

    pub(crate) fn toggle_chains_view(&mut self) -> bool {
        self.chains_open = !self.chains_open;
        self.chains_open
    }

    pub(crate) fn trace_view_open(&self) -> bool {
        self.trace_open
    }

    pub(crate) fn prove_detail_is_open(&self) -> bool {
        self.investigation.is_some() || self.trace_open
    }

    pub(crate) fn close_prove_detail(&mut self) {
        self.investigation = None;
        if self.trace_open {
            self.focus = self.trace_origin_focus.take();
        }
        self.trace_open = false;
    }

    pub(crate) fn toggle_trace_view(&mut self) -> bool {
        self.investigation = None;
        if self.trace_open {
            self.focus = self.trace_origin_focus.take();
        } else {
            self.trace_origin_focus = self.focus;
        }
        self.trace_open = !self.trace_open;
        self.trace_open
    }

    pub(crate) fn zoom(&self) -> crate::app::WorkbenchZoom {
        self.zoom
    }

    pub(crate) fn toggle_zoom(&mut self, focus: crate::ui_view_models::PhaseSurfaceId) {
        self.focus = Some(focus);
        self.zoom.toggle(focus);
    }

    pub(crate) fn show_zoomed_focus(&mut self, focus: crate::ui_view_models::PhaseSurfaceId) {
        self.focus = Some(focus);
        self.zoom.show(focus);
    }

    pub(crate) fn clear_zoom(&mut self) {
        self.zoom.clear();
    }

    pub(crate) fn page(&self) -> Option<crate::app::WorkbenchPage> {
        self.page
    }

    pub(crate) fn set_page(&mut self, page: Option<crate::app::WorkbenchPage>) {
        self.page = page;
    }

    pub(crate) fn scroll(&self) -> &crate::app::WorkbenchSurfaceScroll {
        &self.scroll
    }

    pub(crate) fn scroll_mut(&mut self) -> &mut crate::app::WorkbenchSurfaceScroll {
        &mut self.scroll
    }

    pub(crate) fn review(&self) -> &crate::app::WorkbenchReviewState {
        &self.review
    }

    pub(crate) fn review_mut(&mut self) -> &mut crate::app::WorkbenchReviewState {
        &mut self.review
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRouteState {
    login: Option<crate::app::AuthLoginView>,
}

impl AuthRouteState {
    pub(crate) fn login(&self) -> Option<&crate::app::AuthLoginView> {
        self.login.as_ref()
    }

    pub(crate) fn login_mut(&mut self) -> Option<&mut crate::app::AuthLoginView> {
        self.login.as_mut()
    }

    pub(crate) fn set_login(&mut self, login: crate::app::AuthLoginView) {
        self.login = Some(login);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandPaletteRouteState {
    query: String,
    cursor: usize,
    /// Entry snapshot taken at open — commands, visible tools, and modules
    /// don't change while the palette is up, so matching never rebuilds them.
    entries: Vec<crate::app::PaletteEntry>,
}

impl CommandPaletteRouteState {
    pub(crate) fn reset(&mut self) {
        self.query.clear();
        self.cursor = 0;
    }

    pub(crate) fn entries(&self) -> &[crate::app::PaletteEntry] {
        &self.entries
    }

    pub(crate) fn set_entries(&mut self, entries: Vec<crate::app::PaletteEntry>) {
        self.entries = entries;
    }

    pub(crate) fn query(&self) -> &str {
        &self.query
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn push_query(&mut self, ch: char) {
        self.query.push(ch);
        self.cursor = 0;
    }

    pub(crate) fn pop_query(&mut self) {
        self.query.pop();
        self.cursor = 0;
    }

    pub(crate) fn move_cursor(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.cursor = 0;
            return;
        }
        let current = self.cursor.min(len - 1) as isize;
        self.cursor = (current + delta).rem_euclid(len as isize) as usize;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NavigationRouteState {
    synced_view: Option<crate::app::ShellView>,
    history: Vec<crate::app::ShellView>,
}

impl NavigationRouteState {
    pub(crate) fn sync_view_change(&mut self, view: crate::app::ShellView) -> bool {
        if crate::app::contextual_surface_view(view) {
            return false;
        }
        let current = Some(view);
        if self.synced_view == current {
            return false;
        }
        if let Some(prev) = self.synced_view.take() {
            self.push_history(prev);
        }
        self.synced_view = current;
        true
    }

    pub(crate) fn push_history(&mut self, view: crate::app::ShellView) {
        if is_transient_view(&view) || self.history.last() == Some(&view) {
            return;
        }
        self.push_history_entry(view);
    }

    pub(crate) fn push_overlay_origin(&mut self, view: crate::app::ShellView) {
        if is_overlay_view(&view) || self.history.last() == Some(&view) {
            return;
        }
        self.push_history_entry(view);
    }

    fn push_history_entry(&mut self, view: crate::app::ShellView) {
        const NAV_HISTORY_DEPTH: usize = 16;
        self.history.push(view);
        if self.history.len() > NAV_HISTORY_DEPTH {
            let excess = self.history.len() - NAV_HISTORY_DEPTH;
            self.history.drain(..excess);
        }
    }

    pub(crate) fn pop_history(&mut self) -> Option<crate::app::ShellView> {
        self.history.pop()
    }

    /// Accept a user-requested back destination without recording the view
    /// they just left as a new forward step on the next redraw.
    pub(crate) fn accept_back_transition(&mut self, view: crate::app::ShellView) {
        self.synced_view = Some(view);
    }

    #[cfg(test)]
    pub(crate) fn contains_history(&self, view: &crate::app::ShellView) -> bool {
        self.history.contains(view)
    }
}

fn is_transient_view(view: &crate::app::ShellView) -> bool {
    matches!(
        view,
        crate::app::ShellView::Story
            | crate::app::ShellView::FilePicker
            | crate::app::ShellView::CommandPalette
            | crate::app::ShellView::PlanningPicker
            | crate::app::ShellView::TargetPicker
    )
}

fn is_overlay_view(view: &crate::app::ShellView) -> bool {
    matches!(
        view,
        crate::app::ShellView::Story | crate::app::ShellView::FilePicker
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct SceneRouteState {
    dfd_review_origin: Option<crate::app::state_transitions::DfdReviewOrigin>,
    page: crate::scene3d::VizPage,
    /// A Map-origin zoom stays inside the four Map projections. Explicit
    /// `scene` access restores the complete security-visualization gallery.
    map_only: bool,
    yaw: f32,
    pitch: f32,
    paused: bool,
    last_advance: Option<Instant>,
    /// DFD cursor over flattened nodes, flows, and boundaries.
    dfd_selection: usize,
    /// Requested first row in the wrapped DFD detail panel.
    dfd_detail_scroll: usize,
    /// Focused local security-context graph replaces the topology area.
    dfd_focused: bool,
    /// Cursor over annotations attached to the selected DFD element.
    dfd_context_selection: usize,
    /// Cursor over architectural components in the system-summary tree.
    summary_component_selection: usize,
    /// Signed row offset from the selected component's centered viewport.
    summary_scroll: i32,
    /// Cursor over the trust-zone-grouped entry-point list.
    entry_point_selection: usize,
    /// Requested first row in the selected entry-point detail pane.
    entry_point_detail_scroll: usize,
}

impl Default for SceneRouteState {
    fn default() -> Self {
        Self {
            dfd_review_origin: None,
            page: crate::scene3d::VizPage::default(),
            map_only: false,
            yaw: 0.6,
            pitch: 0.45,
            paused: false,
            last_advance: None,
            dfd_selection: 0,
            dfd_detail_scroll: 0,
            dfd_focused: false,
            dfd_context_selection: 0,
            summary_component_selection: 0,
            summary_scroll: 0,
            entry_point_selection: 0,
            entry_point_detail_scroll: 0,
        }
    }
}

impl SceneRouteState {
    pub(crate) fn dfd_review_origin(
        &self,
    ) -> Option<&crate::app::state_transitions::DfdReviewOrigin> {
        self.dfd_review_origin.as_ref()
    }

    pub(crate) fn set_dfd_review_origin(
        &mut self,
        origin: crate::app::state_transitions::DfdReviewOrigin,
    ) {
        self.dfd_review_origin = Some(origin);
    }

    pub(crate) fn take_dfd_review_origin(
        &mut self,
    ) -> Option<crate::app::state_transitions::DfdReviewOrigin> {
        self.dfd_review_origin.take()
    }
}

impl SceneRouteState {
    pub(crate) fn page(&self) -> crate::scene3d::VizPage {
        self.page
    }

    pub(crate) fn set_page(&mut self, page: crate::scene3d::VizPage) {
        self.page = page;
    }

    pub(crate) fn map_only(&self) -> bool {
        self.map_only
    }

    pub(crate) fn set_map_only(&mut self, map_only: bool) {
        self.map_only = map_only;
    }

    pub(crate) fn yaw(&self) -> f32 {
        self.yaw
    }

    pub(crate) fn pitch(&self) -> f32 {
        self.pitch
    }

    pub(crate) fn paused(&self) -> bool {
        self.paused
    }

    pub(crate) fn toggle_paused(&mut self) {
        self.paused = !self.paused;
    }

    pub(crate) fn reset_orientation(&mut self) {
        self.yaw = 0.6;
        self.pitch = 0.45;
        self.paused = false;
    }

    pub(crate) fn nudge_yaw(&mut self, amount: f32) {
        self.paused = true;
        self.yaw = wrap_scene_angle(self.yaw + amount);
    }

    pub(crate) fn nudge_pitch(&mut self, amount: f32) {
        self.paused = true;
        self.pitch = (self.pitch + amount).clamp(-1.4, 1.4);
    }

    pub(crate) fn dfd_selection(&self) -> usize {
        self.dfd_selection
    }

    pub(crate) fn dfd_detail_scroll(&self) -> usize {
        self.dfd_detail_scroll
    }

    pub(crate) fn dfd_focused(&self) -> bool {
        self.dfd_focused
    }

    pub(crate) fn dfd_context_selection(&self) -> usize {
        self.dfd_context_selection
    }

    pub(crate) fn summary_component_selection(&self) -> usize {
        self.summary_component_selection
    }

    pub(crate) fn summary_scroll(&self) -> i32 {
        self.summary_scroll
    }

    pub(crate) fn entry_point_selection(&self) -> usize {
        self.entry_point_selection
    }

    pub(crate) fn entry_point_detail_scroll(&self) -> usize {
        self.entry_point_detail_scroll
    }

    pub(crate) fn toggle_dfd_focus(&mut self) {
        self.dfd_focused = !self.dfd_focused;
        self.dfd_context_selection = 0;
        self.dfd_detail_scroll = 0;
    }

    pub(crate) fn collapse_dfd_focus(&mut self) -> bool {
        if !self.dfd_focused {
            return false;
        }
        self.dfd_focused = false;
        self.dfd_context_selection = 0;
        true
    }

    /// Cycle the DFD selection with wrap over nodes, flows, then boundaries.
    /// A shrunken model clamps the cursor instead of pointing past the end.
    pub(crate) fn cycle_dfd_selection(&mut self, direction: i32, len: usize) {
        if len == 0 {
            self.dfd_selection = 0;
            return;
        }
        let current = self.dfd_selection.min(len - 1) as i32;
        self.dfd_selection = (current + direction).rem_euclid(len as i32) as usize;
        self.dfd_context_selection = 0;
        self.dfd_detail_scroll = 0;
    }

    pub(crate) fn set_dfd_selection(&mut self, selection: usize, len: usize) {
        self.dfd_selection = selection.min(len.saturating_sub(1));
        self.dfd_focused = false;
        self.dfd_context_selection = 0;
        self.dfd_detail_scroll = 0;
    }

    pub(crate) fn cycle_dfd_context_selection(&mut self, direction: i32, len: usize) {
        if len == 0 {
            self.dfd_context_selection = 0;
            return;
        }
        let current = self.dfd_context_selection.min(len - 1) as i32;
        self.dfd_context_selection = (current + direction).rem_euclid(len as i32) as usize;
        self.dfd_detail_scroll = 0;
    }

    pub(crate) fn scroll_dfd_detail(&mut self, direction: i32, amount: usize) {
        if direction >= 0 {
            self.dfd_detail_scroll = self.dfd_detail_scroll.saturating_add(amount);
        } else {
            self.dfd_detail_scroll = self.dfd_detail_scroll.saturating_sub(amount);
        }
    }

    pub(crate) fn scroll_summary(&mut self, direction: i32, amount: usize) {
        let amount = i32::try_from(amount).unwrap_or(i32::MAX);
        self.summary_scroll = self
            .summary_scroll
            .saturating_add(direction.signum().saturating_mul(amount));
        if self.summary_component_selection == 0 {
            self.summary_scroll = self.summary_scroll.max(0);
        }
    }

    pub(crate) fn cycle_summary_component_selection(&mut self, direction: i32, len: usize) {
        if len == 0 {
            self.reset_summary_navigation();
            return;
        }
        let current = self.summary_component_selection.min(len - 1) as i32;
        self.set_summary_component_selection(
            (current + direction).rem_euclid(len as i32) as usize,
            len,
        );
    }

    pub(crate) fn set_summary_component_selection(&mut self, selection: usize, len: usize) {
        self.summary_component_selection = selection.min(len.saturating_sub(1));
        self.summary_scroll = 0;
    }

    pub(crate) fn reset_summary_navigation(&mut self) {
        self.summary_component_selection = 0;
        self.summary_scroll = 0;
    }

    pub(crate) fn cycle_entry_point_selection(&mut self, direction: i32, len: usize) {
        if len == 0 {
            self.entry_point_selection = 0;
            return;
        }
        let current = self.entry_point_selection.min(len - 1) as i32;
        self.entry_point_selection = (current + direction).rem_euclid(len as i32) as usize;
        self.entry_point_detail_scroll = 0;
    }

    pub(crate) fn set_entry_point_selection(&mut self, selection: usize, len: usize) {
        self.entry_point_selection = selection.min(len.saturating_sub(1));
        self.entry_point_detail_scroll = 0;
    }

    pub(crate) fn set_entry_point_detail_scroll(&mut self, offset: usize) {
        self.entry_point_detail_scroll = offset;
    }

    pub(crate) fn clear_advance_baseline(&mut self) {
        self.last_advance = None;
    }

    pub(crate) fn last_advance(&self) -> Option<Instant> {
        self.last_advance
    }

    pub(crate) fn set_advance_baseline(&mut self, at: Instant) {
        self.last_advance = Some(at);
    }

    pub(crate) fn advance_yaw(&mut self, amount: f32, at: Instant) {
        self.yaw = wrap_scene_angle(self.yaw + amount);
        self.last_advance = Some(at);
    }
}

fn wrap_scene_angle(angle: f32) -> f32 {
    let tau = std::f32::consts::TAU;
    let mut wrapped = angle % tau;
    if wrapped < 0.0 {
        wrapped += tau;
    }
    wrapped
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatRouteState {
    view: crate::app::ThreatView,
    versions: Vec<kuzushi_core::findings::ThreatModelVersionRecord>,
    live_sha256: Option<String>,
    history: Option<crate::app::ContextHistoryState>,
}

impl Default for ThreatRouteState {
    fn default() -> Self {
        Self {
            view: crate::app::ThreatView::Summary,
            versions: Vec::new(),
            live_sha256: None,
            history: None,
        }
    }
}

impl ThreatRouteState {
    pub(crate) fn history(&self) -> Option<&crate::app::ContextHistoryState> {
        self.history.as_ref()
    }

    pub(crate) fn history_mut(&mut self) -> Option<&mut crate::app::ContextHistoryState> {
        self.history.as_mut()
    }

    pub(crate) fn set_history(&mut self, history: crate::app::ContextHistoryState) {
        self.history = Some(history);
    }

    pub(crate) fn view(&self) -> crate::app::ThreatView {
        self.view
    }

    pub(crate) fn open(&mut self, view: crate::app::ThreatView) {
        self.view = view;
    }

    pub(crate) fn versions(&self) -> &[kuzushi_core::findings::ThreatModelVersionRecord] {
        &self.versions
    }

    pub(crate) fn live_sha256(&self) -> Option<&str> {
        self.live_sha256.as_deref()
    }

    pub(crate) fn set_versions(
        &mut self,
        versions: Vec<kuzushi_core::findings::ThreatModelVersionRecord>,
        live_sha256: Option<String>,
    ) {
        self.versions = versions;
        self.live_sha256 = live_sha256;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatalogRouteState {
    expanded: bool,
    cursor: usize,
    recommend_cursor: usize,
}

impl CatalogRouteState {
    pub(crate) fn collapse(&mut self) {
        self.expanded = false;
    }

    #[cfg(test)]
    pub(crate) fn expand(&mut self) {
        self.expanded = true;
    }

    pub(crate) fn toggle_expanded(&mut self) {
        self.expanded = !self.expanded;
        self.cursor = 0;
    }

    pub(crate) fn is_expanded(&self) -> bool {
        self.expanded
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn move_cursor(&mut self, delta: i32, len: usize) {
        if len == 0 {
            self.cursor = 0;
            return;
        }
        let len = len as i32;
        let mut next = self.cursor as i32 + delta;
        while next < 0 {
            next += len;
        }
        self.cursor = (next % len) as usize;
    }

    pub(crate) fn jump_start(&mut self) {
        self.cursor = 0;
    }

    pub(crate) fn jump_end(&mut self, len: usize) {
        self.cursor = len.saturating_sub(1);
    }

    pub(crate) fn page_cursor(&mut self, delta: i32, len: usize) {
        self.cursor = self
            .cursor
            .saturating_add_signed(delta as isize)
            .min(len.saturating_sub(1));
    }

    pub(crate) fn recommend_cursor(&self) -> usize {
        self.recommend_cursor
    }

    pub(crate) fn reset_recommend_cursor(&mut self) {
        self.recommend_cursor = 0;
    }

    pub(crate) fn move_recommend_cursor(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.recommend_cursor = 0;
            return;
        }
        if delta >= 0 {
            self.recommend_cursor = (self.recommend_cursor + 1).min(len.saturating_sub(1));
        } else {
            self.recommend_cursor = self.recommend_cursor.saturating_sub(1);
        }
    }

    pub(crate) fn selected_recommend_cursor(&mut self, len: usize) -> usize {
        let max = len.saturating_sub(1);
        self.recommend_cursor = self.recommend_cursor.min(max);
        self.recommend_cursor
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum FilePickerPurpose {
    #[default]
    KnowledgeBase,
    MapDocument,
    ReviewEvidence,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilePickerRouteState {
    files: Vec<String>,
    query: crate::app::FieldEditor,
    cursor: usize,
    truncated: bool,
    purpose: FilePickerPurpose,
    review_selection: crate::app::file_picker::ReviewFileSelection,
}

impl FilePickerRouteState {
    pub(crate) fn open(&mut self, files: Vec<String>, truncated: bool) {
        self.files = files;
        self.query = crate::app::FieldEditor::default();
        self.cursor = 0;
        self.truncated = truncated;
        self.purpose = FilePickerPurpose::KnowledgeBase;
        self.review_selection = Default::default();
    }

    pub(crate) fn purpose(&self) -> FilePickerPurpose {
        self.purpose
    }

    pub(crate) fn set_purpose(&mut self, purpose: FilePickerPurpose) {
        self.purpose = purpose;
    }

    pub(crate) fn review_selection(&self) -> &crate::app::file_picker::ReviewFileSelection {
        &self.review_selection
    }

    pub(crate) fn review_selection_mut(
        &mut self,
    ) -> &mut crate::app::file_picker::ReviewFileSelection {
        &mut self.review_selection
    }

    pub(crate) fn toggle_review_basket(&mut self) {
        self.review_selection
            .switch_view(&mut self.query, &mut self.cursor);
        self.clamp_cursor();
    }

    pub(crate) fn replace_files(&mut self, files: Vec<String>, truncated: bool) {
        let selected = self.selected_path();
        self.files = files;
        self.truncated = truncated;
        let filtered = self.filtered_paths();
        self.cursor = selected
            .and_then(|selected| filtered.iter().position(|path| path == &selected))
            .unwrap_or_else(|| self.cursor.min(filtered.len().saturating_sub(1)));
    }

    pub(crate) fn files(&self) -> &[String] {
        &self.files
    }

    pub(crate) fn query(&self) -> &str {
        self.query.text()
    }

    pub(crate) fn query_field(&self) -> &crate::app::FieldEditor {
        &self.query
    }

    pub(crate) fn edit_query(&mut self, key: crossterm::event::KeyEvent) {
        self.query.handle_key(key);
        self.clamp_cursor();
    }

    pub(crate) fn paste_query(&mut self, text: &str) {
        self.query.insert(text);
        self.clamp_cursor();
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn filtered_paths(&self) -> Vec<String> {
        let files = if self.purpose == FilePickerPurpose::ReviewEvidence {
            self.review_selection.candidates(&self.files)
        } else {
            self.files.clone()
        };
        crate::app::line_editor::rank_fuzzy(
            crate::app::line_editor::dedupe_sorted(files),
            self.query(),
        )
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        let len = self.filtered_paths().len();
        if len == 0 {
            self.cursor = 0;
            return;
        }
        let current = (self.cursor.min(len - 1)) as isize;
        self.cursor = (current + delta).rem_euclid(len as isize) as usize;
    }

    pub(crate) fn selected_path(&self) -> Option<String> {
        self.filtered_paths().get(self.cursor).cloned()
    }

    fn clamp_cursor(&mut self) {
        let len = self.filtered_paths().len();
        self.cursor = self.cursor.min(len.saturating_sub(1));
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FindingsRouteState {
    cursor: usize,
    active_filter: Option<String>,
    selected_finding: Option<kuzushi_core::Finding>,
    selected_reference: Option<SelectedFindingReference>,
}

#[derive(Debug, Clone, PartialEq)]
struct SelectedFindingReference {
    anchor: String,
    reference: String,
    watermark: Option<u64>,
    policy: kuzushi_core::findings::IdentityFoldPolicy,
}

impl FindingsRouteState {
    pub(crate) fn reset(&mut self) {
        self.cursor = 0;
    }

    pub(crate) fn reset_for_target(&mut self) {
        self.cursor = 0;
        self.active_filter = None;
        self.selected_finding = None;
        self.selected_reference = None;
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn active_filter(&self) -> &Option<String> {
        &self.active_filter
    }

    pub(crate) fn set_active_filter(&mut self, filter: Option<String>) {
        self.active_filter = filter;
    }

    pub(crate) fn selected_finding(&self) -> &Option<kuzushi_core::Finding> {
        &self.selected_finding
    }

    pub(crate) fn selected_finding_mut(&mut self) -> &mut Option<kuzushi_core::Finding> {
        self.selected_reference = None;
        &mut self.selected_finding
    }

    pub(crate) fn set_selected_finding(&mut self, finding: Option<kuzushi_core::Finding>) {
        let anchor = finding
            .as_ref()
            .map(kuzushi_core::findings::finding_page_anchor);
        if self
            .selected_reference
            .as_ref()
            .is_some_and(|reference| Some(&reference.anchor) != anchor.as_ref())
        {
            self.selected_reference = None;
        }
        self.selected_finding = finding;
    }

    pub(crate) fn bind_selected_reference(
        &mut self,
        reference: String,
        watermark: Option<u64>,
        policy: kuzushi_core::findings::IdentityFoldPolicy,
    ) {
        self.selected_reference =
            self.selected_finding
                .as_ref()
                .map(|finding| SelectedFindingReference {
                    anchor: kuzushi_core::findings::finding_page_anchor(finding),
                    reference,
                    watermark,
                    policy,
                });
    }

    pub(crate) fn selected_reference(
        &self,
        finding: &kuzushi_core::Finding,
        watermark: Option<u64>,
        policy: kuzushi_core::findings::IdentityFoldPolicy,
    ) -> Option<String> {
        let reference = self.selected_reference.as_ref()?;
        let current = reference.watermark == watermark && reference.policy == policy;
        (current && reference.anchor == kuzushi_core::findings::finding_page_anchor(finding))
            .then(|| reference.reference.clone())
    }

    pub(crate) fn selection_is_explicit(&self) -> bool {
        self.selected_reference.is_some()
    }

    pub(crate) fn selected_read_watermark(&self, finding: &kuzushi_core::Finding) -> Option<u64> {
        let reference = self.selected_reference.as_ref()?;
        (reference.anchor == kuzushi_core::findings::finding_page_anchor(finding))
            .then_some(reference.watermark)
            .flatten()
    }

    pub(crate) fn acknowledge_selected_decision(
        &mut self,
        finding: &kuzushi_core::Finding,
        read_watermark: Option<u64>,
        committed_seq: Option<u64>,
    ) {
        let Some(seq) = committed_seq.filter(|seq| read_watermark.is_some_and(|read| read <= *seq))
        else {
            return;
        };
        let anchor = kuzushi_core::findings::finding_page_anchor(finding);
        let Some(reference) = self
            .selected_reference
            .as_mut()
            .filter(|reference| reference.anchor == anchor)
            .filter(|reference| reference.watermark == read_watermark)
        else {
            return;
        };
        reference.watermark = Some(seq);
    }

    pub(crate) fn clear_selection(&mut self) {
        self.selected_finding = None;
        self.selected_reference = None;
    }

    pub(crate) fn refresh_selected_finding(&mut self, corpus: &[kuzushi_core::Finding]) {
        let Some(selected) = &self.selected_finding else {
            return;
        };
        let anchor = kuzushi_core::findings::finding_page_anchor(selected);
        if let Some(current) = corpus
            .iter()
            .find(|finding| kuzushi_core::findings::finding_page_anchor(finding) == anchor)
        {
            self.selected_finding = Some(current.clone());
        }
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
    }

    pub(crate) fn clamp(&mut self, len: usize) {
        self.cursor = if len == 0 {
            0
        } else {
            self.cursor.min(len - 1)
        };
    }

    pub(crate) fn step_direction(&mut self, direction: isize, len: usize) {
        self.clear_selection();
        if direction < 0 {
            self.cursor = self.cursor.saturating_sub(1);
        } else {
            self.cursor = (self.cursor + 1).min(len.saturating_sub(1));
        }
    }

    pub(crate) fn page_down(&mut self, rows: usize, len: usize) {
        self.clear_selection();
        self.cursor = (self.cursor + rows).min(len.saturating_sub(1));
    }

    pub(crate) fn page_up(&mut self, rows: usize) {
        self.clear_selection();
        self.cursor = self.cursor.saturating_sub(rows);
    }

    pub(crate) fn jump(&mut self, to_start: bool, len: usize) {
        self.clear_selection();
        self.cursor = if to_start { 0 } else { len.saturating_sub(1) };
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScrollRouteState {
    scroll: usize,
}

impl ScrollRouteState {
    pub(crate) fn open(&mut self) {
        self.scroll = 0;
    }

    pub(crate) fn scroll(&self) -> usize {
        self.scroll
    }

    pub(crate) fn scroll_mut(&mut self) -> &mut usize {
        &mut self.scroll
    }

    pub(crate) fn set_scroll(&mut self, scroll: usize) {
        self.scroll = scroll;
    }

    pub(crate) fn scroll_up(&mut self, amount: usize) {
        self.scroll = self.scroll.saturating_sub(amount);
    }

    pub(crate) fn scroll_down(&mut self, amount: usize) {
        self.scroll = self.scroll.saturating_add(amount);
    }
}

/// Logs route state. Scroll behaves like every other scrollable document; the
/// route additionally owns the durable history it pages into, whether it is
/// following new output, and the operator's active filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogsRouteState {
    scroll: ScrollRouteState,
    history: crate::app::log::session_history::SessionHistory,
    query: String,
    filter_capture: bool,
    following: bool,
    reader_origin: Option<(usize, bool)>,
    command_text: bool,
    command_scroll: (usize, bool),
}

impl LogsRouteState {
    pub(crate) fn reader_open(&self) -> bool {
        self.reader_origin.is_some()
    }

    pub(crate) fn expand_reader(&mut self) {
        self.reader_origin
            .get_or_insert((self.scroll(), self.following));
    }

    pub(crate) fn close_reader(&mut self) {
        if self.command_text {
            self.toggle_command_text();
        }
        if let Some((scroll, following)) = self.reader_origin.take() {
            self.scroll.set_scroll(scroll);
            self.following = following;
        }
    }

    pub(crate) fn command_text_expanded(&self) -> bool {
        self.command_text
    }

    pub(crate) fn toggle_command_text(&mut self) {
        if !self.reader_open() {
            return;
        }
        std::mem::swap(self.scroll.scroll_mut(), &mut self.command_scroll.0);
        std::mem::swap(&mut self.following, &mut self.command_scroll.1);
        self.command_text = !self.command_text;
    }

    pub(crate) fn open(&mut self) {
        self.scroll.open();
    }

    pub(crate) fn scroll(&self) -> usize {
        self.scroll.scroll()
    }

    pub(crate) fn scroll_mut(&mut self) -> &mut usize {
        self.scroll.scroll_mut()
    }

    pub(crate) fn set_scroll(&mut self, scroll: usize) {
        self.scroll.set_scroll(scroll);
    }

    /// Scrolling back releases the tail so arriving output stops yanking the
    /// viewport away from what the operator is reading.
    pub(crate) fn scroll_up(&mut self, amount: usize) {
        self.following = false;
        self.scroll.scroll_up(amount);
    }

    pub(crate) fn scroll_down(&mut self, amount: usize) {
        self.scroll.scroll_down(amount);
    }

    /// Jump to the oldest row, which also releases the tail.
    pub(crate) fn jump_to_start(&mut self) {
        self.following = false;
        self.scroll.open();
    }

    /// Re-attach to the tail so new output follows again.
    pub(crate) fn follow_tail(&mut self) {
        self.following = true;
        self.scroll.set_scroll(usize::MAX);
    }

    pub(crate) fn is_following(&self) -> bool {
        self.following
    }

    pub(crate) fn history(&self) -> &crate::app::log::session_history::SessionHistory {
        &self.history
    }

    pub(crate) fn set_history(
        &mut self,
        history: crate::app::log::session_history::SessionHistory,
    ) {
        self.history = history;
    }

    pub(crate) fn query(&self) -> Option<&str> {
        let query = self.query.trim();
        (!query.is_empty()).then_some(query)
    }

    /// True while `/` capture owns typing, so filter keys never leak into the
    /// composer.
    pub(crate) fn filter_capture(&self) -> bool {
        self.filter_capture
    }

    pub(crate) fn open_filter_capture(&mut self) {
        self.filter_capture = true;
    }

    pub(crate) fn close_filter_capture(&mut self, keep_query: bool) {
        self.filter_capture = false;
        if !keep_query {
            self.query.clear();
            self.reanchor();
        }
    }

    pub(crate) fn push_filter_char(&mut self, character: char) {
        self.query.push(character);
        self.reanchor();
    }

    pub(crate) fn pop_filter_char(&mut self) {
        self.query.pop();
        self.reanchor();
    }

    /// Changing the filter re-anchors to the top: the first match is the one
    /// the operator is looking for, and following a filtered tail is noise.
    fn reanchor(&mut self) {
        self.following = false;
        self.scroll.set_scroll(0);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefaultScrollRouteState {
    offset: u16,
}

impl DefaultScrollRouteState {
    pub(crate) fn offset(&self) -> u16 {
        self.offset
    }

    pub(crate) fn set(&mut self, offset: u16) {
        self.offset = offset;
    }

    pub(crate) fn reset(&mut self) {
        self.offset = 0;
    }

    pub(crate) fn tail(&mut self) {
        self.offset = u16::MAX;
    }

    pub(crate) fn scroll_down(&mut self, amount: u16) {
        self.offset = self.offset.saturating_add(amount);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HelpRouteState {
    scroll: usize,
    filter: Option<String>,
}

impl HelpRouteState {
    pub(crate) fn open(&mut self, filter: Option<String>) {
        self.scroll = 0;
        self.filter = filter;
    }

    pub(crate) fn scroll(&self) -> usize {
        self.scroll
    }

    pub(crate) fn scroll_mut(&mut self) -> &mut usize {
        &mut self.scroll
    }

    pub(crate) fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolsRouteState {
    scroll: usize,
    filter: Option<String>,
    selected_support: Option<String>,
    support_focused: bool,
}

impl ToolsRouteState {
    pub(crate) fn open(&mut self, filter: Option<String>) {
        self.support_focused = true;
        if self.filter != filter {
            self.selected_support = None;
        }
        self.scroll = 0;
        self.filter = filter;
    }

    pub(crate) fn scroll(&self) -> usize {
        self.scroll
    }

    pub(crate) fn scroll_mut(&mut self) -> &mut usize {
        &mut self.scroll
    }

    pub(crate) fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    pub(crate) fn selected_support(&self) -> Option<&str> {
        self.selected_support.as_deref()
    }

    pub(crate) fn select_support(&mut self, tool: String) {
        self.selected_support = Some(tool);
    }

    pub(crate) fn support_focused(&self) -> bool {
        self.support_focused
    }

    pub(crate) fn release_support_focus(&mut self) {
        self.support_focused = false;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuneRouteState {
    cursor: usize,
    house_rules: crate::app::HouseRulesRead,
}

impl Default for TuneRouteState {
    fn default() -> Self {
        Self {
            cursor: 0,
            house_rules: crate::app::HouseRulesRead::Missing,
        }
    }
}

impl TuneRouteState {
    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    #[cfg(test)]
    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
    }

    pub(crate) fn move_cursor(&mut self, delta: i32, len: usize) {
        self.cursor = shifted_cursor(self.cursor, delta, len);
    }

    pub(crate) fn house_rules(&self) -> &crate::app::HouseRulesRead {
        &self.house_rules
    }

    pub(crate) fn set_house_rules(&mut self, house_rules: crate::app::HouseRulesRead) {
        self.house_rules = house_rules;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptsRouteState {
    cursor: usize,
    document: Option<PromptDocumentState>,
}

impl PromptsRouteState {
    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    #[cfg(test)]
    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
    }

    pub(crate) fn move_cursor(&mut self, delta: i32, len: usize) {
        self.cursor = shifted_cursor(self.cursor, delta, len);
    }

    pub(crate) fn document(&self) -> Option<&PromptDocumentState> {
        self.document.as_ref()
    }

    pub(crate) fn document_mut(&mut self) -> Option<&mut PromptDocumentState> {
        self.document.as_mut()
    }

    pub(crate) fn open_document(&mut self, document: PromptDocumentState) {
        self.document = Some(document);
    }

    pub(crate) fn close_document(&mut self) -> Option<PromptDocumentState> {
        self.document.take()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PromptDocumentMode {
    #[default]
    Normal,
    Insert,
    Command,
    ConfirmDiscard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptDocumentState {
    pub prompt_specs: Vec<kuzushi_core::modules::PromptSpec>,
    pub prompt_index: usize,
    pub role: String,
    pub path: PathBuf,
    pub source: String,
    pub hash: String,
    pub context_note: String,
    pub lines: Vec<String>,
    pub trailing_newline: bool,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub top_row: usize,
    pub mode: PromptDocumentMode,
    pub command: String,
    pub dirty: bool,
    pub exit_after_save: bool,
    pub pending_g: bool,
    pub origin: crate::app::ShellView,
}

impl PromptDocumentState {
    pub fn text(&self) -> String {
        let mut text = self.lines.join("\n");
        if self.trailing_newline {
            text.push('\n');
        }
        text
    }

    pub fn current_line_len(&self) -> usize {
        self.lines
            .get(self.cursor_row)
            .map(|line| line.chars().count())
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActorDetailRouteState {
    index: usize,
    filter: crate::app::ActorDetailFilter,
}

impl ActorDetailRouteState {
    pub(crate) fn open(&mut self, index: usize) {
        self.index = index;
    }

    pub(crate) fn index(&self) -> usize {
        self.index
    }

    pub(crate) fn filter(&self) -> crate::app::ActorDetailFilter {
        self.filter
    }

    #[cfg(test)]
    pub(crate) fn set_filter(&mut self, filter: crate::app::ActorDetailFilter) {
        self.filter = filter;
    }

    pub(crate) fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
    }

    pub(crate) fn reset_filter(&mut self) {
        self.filter = crate::app::ActorDetailFilter::All;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchRouteState {
    alias: String,
}

impl PatchRouteState {
    pub(crate) fn open(&mut self, alias: impl Into<String>) {
        self.alias = alias.into();
    }

    pub(crate) fn alias(&self) -> &str {
        &self.alias
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunDiffRouteState {
    left: String,
    right: String,
    sources_open: bool,
    other_scroll: u16,
}

impl RunDiffRouteState {
    pub(crate) fn open(&mut self, left: impl Into<String>, right: impl Into<String>) {
        self.left = left.into();
        self.right = right.into();
        self.sources_open = false;
        self.other_scroll = 0;
    }

    pub(crate) fn sources_open(&self) -> bool {
        self.sources_open
    }

    pub(crate) fn toggle_sources(&mut self, current_scroll: u16) -> u16 {
        self.sources_open = !self.sources_open;
        std::mem::replace(&mut self.other_scroll, current_scroll)
    }

    pub(crate) fn left(&self) -> &str {
        &self.left
    }

    pub(crate) fn right(&self) -> &str {
        &self.right
    }

    pub(crate) fn label(&self) -> String {
        format!("{} -> {}", self.left, self.right)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptionRouteState {
    view: crate::app::InterruptionView,
}

impl Default for InterruptionRouteState {
    fn default() -> Self {
        Self {
            view: crate::app::InterruptionView::NoModel,
        }
    }
}

impl InterruptionRouteState {
    pub(crate) fn open(&mut self, view: crate::app::InterruptionView) {
        self.view = view;
    }

    pub(crate) fn view(&self) -> crate::app::InterruptionView {
        self.view
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PwnRouteState {
    selected_panel: usize,
    selected_row: usize,
}

#[cfg(test)]
impl PwnRouteState {
    pub(crate) fn selected_panel(&self) -> usize {
        self.selected_panel
    }

    pub(crate) fn selected_row(&self) -> usize {
        self.selected_row
    }

    pub(crate) fn set_selection(&mut self, panel: usize, row: usize) {
        self.selected_panel = panel;
        self.selected_row = row;
    }

    pub(crate) fn reset_selection(&mut self) {
        self.selected_panel = 0;
        self.selected_row = 0;
    }
}

fn shifted_cursor(current: usize, delta: i32, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let current = current.min(len - 1) as i32;
    (current + delta).clamp(0, len as i32 - 1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_owns_overlay_snapshots() {
        let mut router = RouterState::default();
        let boot = boot_snapshot();
        let health = health_snapshot();
        let interruption = interruption_snapshot();
        let keymap = keymap_snapshot();
        let quit = quit_snapshot();
        let theme = theme_snapshot();
        let update = update_snapshot();

        router.set_boot_splash_snapshot(Some(boot.clone()));
        router.set_health_snapshot(Some(health.clone()));
        router.set_interruption_snapshot(Some(interruption.clone()));
        router.set_keymap_snapshot(Some(keymap.clone()));
        router.set_quit_confirm_snapshot(Some(quit.clone()));
        router.set_theme_picker_snapshot(Some(theme.clone()));
        router.set_update_available_snapshot(Some(update.clone()));

        assert_eq!(router.boot_splash_snapshot(), Some(&boot));
        assert_eq!(router.health_snapshot(), Some(&health));
        assert_eq!(router.interruption_snapshot(), Some(&interruption));
        assert_eq!(router.keymap_snapshot(), Some(&keymap));
        assert_eq!(router.quit_confirm_snapshot(), Some(&quit));
        assert_eq!(router.theme_picker_snapshot(), Some(&theme));
        assert_eq!(router.update_available_snapshot(), Some(&update));
    }

    #[test]
    fn findings_route_owns_active_filter() {
        let mut route = FindingsRouteState::default();

        route.set_active_filter(Some("decision:needs_review".to_string()));

        assert_eq!(
            route.active_filter().as_deref(),
            Some("decision:needs_review")
        );
    }

    #[test]
    fn findings_route_owns_selected_finding() {
        let mut route = FindingsRouteState::default();
        let finding = kuzushi_core::Finding::new_tool(
            "fixture",
            "route/selected",
            "src/lib.rs",
            7,
            None,
            kuzushi_core::Severity::High,
            "selected",
        );

        route.set_selected_finding(Some(finding.clone()));

        assert_eq!(route.selected_finding(), &Some(finding));
    }

    #[test]
    fn decision_acknowledgement_keeps_other_selections_and_unknown_receipts_unchanged() {
        let finding = kuzushi_core::Finding::new_tool(
            "fixture",
            "owned",
            "lib.rs",
            1,
            None,
            kuzushi_core::Severity::Info,
            "Owned note",
        );
        let mut other = finding.clone();
        other.id = Some(99);
        let mut route = FindingsRouteState::default();
        route.set_selected_finding(Some(finding.clone()));
        route.bind_selected_reference("owned".into(), Some(10), Default::default());
        for (selected, expected, receipt) in [
            (&other, Some(10), Some(12)),
            (&finding, Some(9), Some(12)),
            (&finding, Some(10), None),
            (&finding, Some(10), Some(9)),
        ] {
            route.acknowledge_selected_decision(selected, expected, receipt);
            assert_eq!(route.selected_read_watermark(&finding), Some(10));
        }
        route.acknowledge_selected_decision(&finding, Some(10), Some(12));
        assert_eq!(route.selected_read_watermark(&finding), Some(12));
    }

    #[test]
    fn pwn_route_owns_dashboard_selection() {
        let mut route = PwnRouteState::default();

        route.set_selection(2, 7);

        assert_eq!(route.selected_panel(), 2);
        assert_eq!(route.selected_row(), 7);

        route.reset_selection();

        assert_eq!(route.selected_panel(), 0);
        assert_eq!(route.selected_row(), 0);
    }

    #[test]
    fn summary_component_cursor_wraps_and_recenters_its_scroll() {
        let mut route = SceneRouteState::default();

        route.scroll_summary(1, 12);
        route.cycle_summary_component_selection(-1, 3);

        assert_eq!(route.summary_component_selection(), 2);
        assert_eq!(route.summary_scroll(), 0);

        route.scroll_summary(-1, 7);
        route.set_summary_component_selection(9, 3);

        assert_eq!(route.summary_component_selection(), 2);
        assert_eq!(route.summary_scroll(), 0);

        route.reset_summary_navigation();
        assert_eq!(route.summary_component_selection(), 0);
    }

    #[test]
    fn summary_pages_clamp_at_the_document_start_but_can_precede_a_selected_component() {
        let mut route = SceneRouteState::default();
        route.scroll_summary(-1, 2);
        assert_eq!(route.summary_scroll(), 0);

        route.set_summary_component_selection(1, 3);
        route.scroll_summary(-1, 2);
        assert_eq!(route.summary_scroll(), -2);
    }

    fn boot_snapshot() -> crate::app::BootSplashSnapshot {
        crate::app::BootSplashSnapshot {
            version_line: "v-test".to_string(),
            checks: vec![crate::app::BootSplashCheck::new(
                crate::app::BootSplashCheckState::Ok,
                "config",
                "loaded",
            )],
            primary_hint: "primary".to_string(),
            secondary_hint: "secondary".to_string(),
        }
    }

    fn keymap_snapshot() -> crate::app::KeymapSnapshot {
        crate::app::KeymapSnapshot {
            status: keymap_status(),
            event_time: "12:00:00".to_string(),
            sections: vec![crate::app::KeymapSection::new(
                "GLOBAL",
                "work everywhere",
                vec![crate::app::KeymapBindingRow::new("?", "help")],
            )],
            note: "note".to_string(),
            footer: crate::app::KeymapFooter {
                stage: "keys".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: "help".to_string(),
            },
        }
    }

    fn health_snapshot() -> crate::app::HealthSnapshot {
        crate::app::HealthSnapshot {
            status: crate::app::HealthStatus {
                target: "target".to_string(),
                ctx: "ctx".to_string(),
                model: "model".to_string(),
                module: "doctor".to_string(),
                cost: "$0.00".to_string(),
            },
            body_rows: vec!["body".to_string()],
            footer: crate::app::HealthFooter {
                stage: "doctor".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: None,
            },
        }
    }

    fn interruption_snapshot() -> crate::app::InterruptionSnapshot {
        crate::app::InterruptionSnapshot {
            view: crate::app::InterruptionView::NoBinary,
            status: crate::app::InterruptionStatus {
                target: "target".to_string(),
                ctx: "ctx".to_string(),
                model: "model".to_string(),
                module: "codeql".to_string(),
                cost: "$0.00".to_string(),
            },
            body_rows: vec!["body".to_string()],
            footer: crate::app::InterruptionFooter {
                stage: "refused".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: Some("codeql".to_string()),
            },
        }
    }

    fn keymap_status() -> crate::app::KeymapStatus {
        crate::app::KeymapStatus {
            target: "target".to_string(),
            ctx: "ctx".to_string(),
            model: "model".to_string(),
            module: "keys".to_string(),
            cost: "$0.00".to_string(),
        }
    }

    fn quit_snapshot() -> crate::app::QuitConfirmSnapshot {
        crate::app::QuitConfirmSnapshot {
            status: quit_status(),
            timestamp: "12:00:00".to_string(),
            warning_title: "CONFIRM".to_string(),
            warning_body: "body".to_string(),
            sections: Vec::new(),
            default_line: "default".to_string(),
            footer: crate::app::QuitConfirmFooter {
                stage: "quit".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: "quit".to_string(),
            },
        }
    }

    fn quit_status() -> crate::app::QuitConfirmStatus {
        crate::app::QuitConfirmStatus {
            target: "target".to_string(),
            ctx: "ctx".to_string(),
            model: "model".to_string(),
            module: "quit".to_string(),
            cost: "$0.00".to_string(),
        }
    }

    fn theme_snapshot() -> crate::app::ThemePickerSnapshot {
        crate::app::ThemePickerSnapshot {
            status: theme_status(),
            event_time: "12:00:00".to_string(),
            current_theme: "default".to_string(),
            source_hint: "source".to_string(),
            tty_override_hint: "tty".to_string(),
            palettes: vec![crate::app::ThemePaletteRow::new(
                "default", "bg", "fg", "accent", "sev", "blurb",
            )],
            selected_palette: 0,
            preview_title: "preview".to_string(),
            preview_rows: Vec::new(),
            accessibility_rows: Vec::new(),
            custom_rows: Vec::new(),
            flow_time: "12:00:00".to_string(),
            flow_hint: "hint".to_string(),
            footer: crate::app::ThemePickerFooter {
                stage: "theme".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: "theme".to_string(),
            },
        }
    }

    fn theme_status() -> crate::app::ThemePickerStatus {
        crate::app::ThemePickerStatus {
            target: "target".to_string(),
            ctx: "ctx".to_string(),
            model: "model".to_string(),
            module: "theme".to_string(),
            cost: "$0.00".to_string(),
        }
    }

    fn update_snapshot() -> crate::app::UpdateAvailableSnapshot {
        crate::app::UpdateAvailableSnapshot {
            status: update_status(),
            body_rows: vec!["UPDATE".to_string()],
            footer: crate::app::UpdateAvailableFooter {
                stage: "update".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: None,
            },
        }
    }

    fn update_status() -> crate::app::UpdateAvailableStatus {
        crate::app::UpdateAvailableStatus {
            target: "target".to_string(),
            ctx: "ctx".to_string(),
            model: "model".to_string(),
            module: "update".to_string(),
            cost: "$0.00".to_string(),
        }
    }
}
