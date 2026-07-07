mod pickers;

use super::ActivityRouteState;
pub use pickers::{
    AuthPickerRouteState, ModelPickerRouteState, PlanningPickerRouteState, TargetPickerRouteState,
};
use std::time::Instant;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RouterState {
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
    interruption: InterruptionRouteState,
    quit_confirm_snapshot: Option<crate::app::QuitConfirmSnapshot>,
    sast_tasks_snapshot: Option<crate::app::SastTasksSnapshot>,
    theme_picker_snapshot: Option<crate::app::ThemePickerSnapshot>,
    update_available_snapshot: Option<crate::app::UpdateAvailableSnapshot>,
    navigation: NavigationRouteState,
    auth: AuthRouteState,
    command_palette: CommandPaletteRouteState,
    model_catalog: ModelCatalogRouteState,
    model_picker: ModelPickerRouteState,
    auth_picker: AuthPickerRouteState,
    target_picker: TargetPickerRouteState,
    file_picker: FilePickerRouteState,
    activity: ActivityRouteState,
    workbench: WorkbenchRouteState,
    catalog: CatalogRouteState,
    findings: FindingsRouteState,
    help: HelpRouteState,
    tools: ToolsRouteState,
    default_scroll: DefaultScrollRouteState,
    history: ScrollRouteState,
    kb: ScrollRouteState,
    modules: ScrollRouteState,
    logs: ScrollRouteState,
    scene: SceneRouteState,
    threat: ThreatRouteState,
    tune: TuneRouteState,
    prompts: PromptsRouteState,
    actor_detail: ActorDetailRouteState,
    run_diff: RunDiffRouteState,
    replay: RunArtifactRouteState,
    trace: RunArtifactRouteState,
    patch: PatchRouteState,
    pwn: PwnRouteState,
}

impl RouterState {
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
        self.options = options;
    }

    pub(crate) fn quit_confirm_snapshot(&self) -> Option<&crate::app::QuitConfirmSnapshot> {
        self.quit_confirm_snapshot.as_ref()
    }

    pub(crate) fn set_quit_confirm_snapshot(
        &mut self,
        snapshot: Option<crate::app::QuitConfirmSnapshot>,
    ) {
        self.quit_confirm_snapshot = snapshot;
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

    pub(crate) fn model_catalog(&self) -> &ModelCatalogRouteState {
        &self.model_catalog
    }

    pub(crate) fn model_catalog_mut(&mut self) -> &mut ModelCatalogRouteState {
        &mut self.model_catalog
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

    pub(crate) fn logs(&self) -> &ScrollRouteState {
        &self.logs
    }

    pub(crate) fn logs_mut(&mut self) -> &mut ScrollRouteState {
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

    pub(crate) fn pwn(&self) -> &PwnRouteState {
        &self.pwn
    }

    pub(crate) fn pwn_mut(&mut self) -> &mut PwnRouteState {
        &mut self.pwn
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkbenchRouteState {
    focus: crate::app::WorkbenchPane,
    page: Option<crate::app::WorkbenchPage>,
    center_mode: crate::app::WorkbenchCenterMode,
    scroll: crate::app::WorkbenchPaneScroll,
    review: crate::app::WorkbenchReviewState,
    nav: crate::app::WorkbenchNav,
    depth_stack: bool,
}

impl Default for WorkbenchRouteState {
    fn default() -> Self {
        Self {
            focus: crate::app::WorkbenchPane::Findings,
            page: None,
            center_mode: crate::app::WorkbenchCenterMode::default(),
            scroll: crate::app::WorkbenchPaneScroll::default(),
            review: crate::app::WorkbenchReviewState::default(),
            nav: crate::app::WorkbenchNav::default(),
            depth_stack: false,
        }
    }
}

impl WorkbenchRouteState {
    pub(crate) fn focus(&self) -> crate::app::WorkbenchPane {
        self.focus
    }

    pub(crate) fn set_focus(&mut self, focus: crate::app::WorkbenchPane) {
        self.focus = focus;
    }

    pub(crate) fn page(&self) -> Option<crate::app::WorkbenchPage> {
        self.page
    }

    pub(crate) fn set_page(&mut self, page: Option<crate::app::WorkbenchPage>) {
        self.page = page;
    }

    pub(crate) fn center_mode(&self) -> crate::app::WorkbenchCenterMode {
        self.center_mode
    }

    pub(crate) fn set_center_mode(&mut self, mode: crate::app::WorkbenchCenterMode) {
        self.center_mode = mode;
    }

    pub(crate) fn toggle_center_mode(&mut self) {
        self.center_mode = self.center_mode.toggled();
        self.scroll.set(crate::app::WorkbenchPane::Center, 0);
    }

    pub(crate) fn cycle_center_mode(&mut self, direction: i32) {
        self.center_mode = if direction >= 0 {
            self.center_mode.next()
        } else {
            self.center_mode.prev()
        };
        self.focus = crate::app::WorkbenchPane::Center;
        self.scroll.set(crate::app::WorkbenchPane::Center, 0);
    }

    pub(crate) fn scroll(&self) -> crate::app::WorkbenchPaneScroll {
        self.scroll
    }

    pub(crate) fn scroll_mut(&mut self) -> &mut crate::app::WorkbenchPaneScroll {
        &mut self.scroll
    }

    pub(crate) fn review(&self) -> &crate::app::WorkbenchReviewState {
        &self.review
    }

    pub(crate) fn review_mut(&mut self) -> &mut crate::app::WorkbenchReviewState {
        &mut self.review
    }

    pub(crate) fn nav(&self) -> &crate::app::WorkbenchNav {
        &self.nav
    }

    pub(crate) fn nav_mut(&mut self) -> &mut crate::app::WorkbenchNav {
        &mut self.nav
    }

    pub(crate) fn depth_stack(&self) -> bool {
        self.depth_stack
    }

    pub(crate) fn set_depth_stack(&mut self, enabled: bool) {
        self.depth_stack = enabled;
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
}

impl CommandPaletteRouteState {
    pub(crate) fn reset(&mut self) {
        self.query.clear();
        self.cursor = 0;
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
pub struct ModelCatalogRouteState {
    selected_index: usize,
}

impl ModelCatalogRouteState {
    pub(crate) fn selected_index(&self) -> usize {
        self.selected_index
    }

    pub(crate) fn set_selected_index(&mut self, selected_index: usize) {
        self.selected_index = selected_index;
    }

    pub(crate) fn move_selection(&mut self, visible_indexes: &[usize], delta: isize) {
        if visible_indexes.is_empty() {
            self.selected_index = 0;
            return;
        }
        let current_pos = visible_indexes
            .iter()
            .position(|&index| index == self.selected_index)
            .unwrap_or(0);
        let next_pos =
            (current_pos as isize + delta).rem_euclid(visible_indexes.len() as isize) as usize;
        self.selected_index = visible_indexes[next_pos];
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NavigationRouteState {
    synced_view: Option<crate::app::ShellView>,
    history: Vec<crate::app::ShellView>,
}

impl NavigationRouteState {
    pub(crate) fn sync_view_change(&mut self, view: crate::app::ShellView) -> bool {
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
            | crate::app::ShellView::ModelPicker
            | crate::app::ShellView::AuthMethodPicker
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
    page: crate::scene3d::VizPage,
    yaw: f32,
    pitch: f32,
    paused: bool,
    last_advance: Option<Instant>,
}

impl Default for SceneRouteState {
    fn default() -> Self {
        Self {
            page: crate::scene3d::VizPage::default(),
            yaw: 0.6,
            pitch: 0.45,
            paused: false,
            last_advance: None,
        }
    }
}

impl SceneRouteState {
    pub(crate) fn page(&self) -> crate::scene3d::VizPage {
        self.page
    }

    pub(crate) fn set_page(&mut self, page: crate::scene3d::VizPage) {
        self.page = page;
    }

    pub(crate) fn next_page(&mut self, direction: i32) -> crate::scene3d::VizPage {
        self.page = if direction >= 0 {
            self.page.next()
        } else {
            self.page.prev()
        };
        self.page
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatRouteState {
    view: crate::app::ThreatView,
}

impl Default for ThreatRouteState {
    fn default() -> Self {
        Self {
            view: crate::app::ThreatView::Summary,
        }
    }
}

impl ThreatRouteState {
    pub(crate) fn view(&self) -> crate::app::ThreatView {
        self.view
    }

    pub(crate) fn open(&mut self, view: crate::app::ThreatView) {
        self.view = view;
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

    pub(crate) fn expand(&mut self) {
        self.expanded = true;
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilePickerRouteState {
    files: Vec<String>,
    query: String,
    cursor: usize,
    truncated: bool,
}

impl FilePickerRouteState {
    pub(crate) fn open(&mut self, files: Vec<String>, truncated: bool) {
        self.files = files;
        self.query.clear();
        self.cursor = 0;
        self.truncated = truncated;
    }

    pub(crate) fn files(&self) -> &[String] {
        &self.files
    }

    pub(crate) fn query(&self) -> &str {
        &self.query
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn filtered_paths(&self) -> Vec<String> {
        crate::app::line_editor::rank_fuzzy(
            crate::app::line_editor::dedupe_sorted(self.files.clone()),
            &self.query,
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

    pub(crate) fn push_query(&mut self, ch: char) {
        self.query.push(ch);
        self.clamp_cursor();
    }

    pub(crate) fn pop_query(&mut self) {
        self.query.pop();
        self.clamp_cursor();
    }

    pub(crate) fn clear_query(&mut self) {
        self.query.clear();
        self.cursor = 0;
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
}

impl FindingsRouteState {
    pub(crate) fn reset(&mut self) {
        self.cursor = 0;
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
        &mut self.selected_finding
    }

    pub(crate) fn set_selected_finding(&mut self, finding: Option<kuzushi_core::Finding>) {
        self.selected_finding = finding;
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
        if direction < 0 {
            self.cursor = self.cursor.saturating_sub(1);
        } else {
            self.cursor = (self.cursor + 1).min(len.saturating_sub(1));
        }
    }

    pub(crate) fn page_down(&mut self, rows: usize, len: usize) {
        self.cursor = (self.cursor + rows).min(len.saturating_sub(1));
    }

    pub(crate) fn page_up(&mut self, rows: usize) {
        self.cursor = self.cursor.saturating_sub(rows);
    }

    pub(crate) fn jump(&mut self, to_start: bool, len: usize) {
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

    pub(crate) fn scroll_up(&mut self, amount: u16) {
        self.offset = self.offset.saturating_sub(amount);
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
}

impl ToolsRouteState {
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

    pub(crate) fn filter_clone(&self) -> Option<String> {
        self.filter.clone()
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
}

impl PromptsRouteState {
    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
    }

    pub(crate) fn move_cursor(&mut self, delta: i32, len: usize) {
        self.cursor = shifted_cursor(self.cursor, delta, len);
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
}

impl RunDiffRouteState {
    pub(crate) fn open(&mut self, left: impl Into<String>, right: impl Into<String>) {
        self.left = left.into();
        self.right = right.into();
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunArtifactRouteState {
    run_id: String,
}

impl RunArtifactRouteState {
    pub(crate) fn open(&mut self, run_id: impl Into<String>) {
        self.run_id = run_id.into();
    }

    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    pub(crate) fn run_id_owned(&self) -> String {
        self.run_id.clone()
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PwnRouteState {
    selected_panel: usize,
    selected_row: usize,
}

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
    fn pwn_route_owns_dashboard_selection() {
        let mut route = PwnRouteState::default();

        route.set_selection(2, 7);

        assert_eq!(route.selected_panel(), 2);
        assert_eq!(route.selected_row(), 7);

        route.reset_selection();

        assert_eq!(route.selected_panel(), 0);
        assert_eq!(route.selected_row(), 0);
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
