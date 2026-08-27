use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GalleryKeyTarget {
    EmbeddedMap,
    FullScene,
}

impl ShellApp {
    pub(super) fn handle_cursor_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        let scene_update = self.handle_scene_view_key(key, modifiers);
        if scene_update.handled {
            return scene_update;
        }
        let Some(handler) = cursor_key_handler(key.code, modifiers) else {
            return InputUpdate::ignored();
        };
        handler(self);
        InputUpdate::handled()
    }

    pub(super) fn handle_empty_input_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if !self.view_key_navigation_is_active() {
            return InputUpdate::ignored();
        }
        if let Some(update) = self.handle_specialized_view_key(key, modifiers) {
            return update;
        }
        self.handle_view_hotkey_fallback(key, modifiers)
    }

    fn view_key_navigation_is_active(&self) -> bool {
        self.input_mode() == InputMode::Navigate && self.input().is_empty()
    }

    fn handle_specialized_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> Option<InputUpdate> {
        // First view-specific handler that claims the key wins; the hotkey
        // fallback is last so per-view keys take precedence.
        let report_update = self.handle_report_view_key(key, modifiers);
        if report_update.handled {
            return Some(report_update);
        }
        let config_update = self.handle_config_view_key(key, modifiers);
        if config_update.handled {
            return Some(config_update);
        }
        let scene_update = self.handle_scene_view_key(key, modifiers);
        if scene_update.handled {
            return Some(scene_update);
        }
        None
    }

    fn handle_report_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if !modifiers.plain || !matches!(self.shell_view(), ShellView::Report) {
            return InputUpdate::ignored();
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.router.report_mut().move_format(-1),
            KeyCode::Down | KeyCode::Char('j') => self.router.report_mut().move_format(1),
            KeyCode::Char('c') => self.router.report_mut().cycle_completeness(),
            KeyCode::Char('e') => self.router.report_mut().set_editing_path(true),
            KeyCode::Char('q') => self.close_report_to_origin(),
            KeyCode::Enter => {
                let route = self.router.report();
                let output = route.path_draft().trim();
                if output.is_empty() {
                    self.log("report", "destination must not be empty");
                    return InputUpdate::handled();
                }
                return InputUpdate::handled_with_effects(vec![ShellEffect::ExportReport(
                    ReportExport {
                        format: route.format(),
                        completeness: route.completeness(),
                        output: PathBuf::from(output),
                        target: self.target_owned(),
                    },
                )]);
            }
            KeyCode::Char('o') => {
                return InputUpdate::handled_with_effects(vec![
                    ShellEffect::RevealReportDestination,
                ]);
            }
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    /// Arrow-key / single-key view hotkeys, tried after the per-view handlers.
    fn handle_view_hotkey_fallback(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if matches!(key.code, KeyCode::Up | KeyCode::Down) && modifiers.plain {
            let update = self.handle_view_hotkey(key);
            if update.handled {
                return update;
            }
        }
        if modifiers.no_modifiers {
            return self.handle_view_hotkey(key);
        }
        InputUpdate::ignored()
    }

    pub(super) fn handle_config_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if !modifiers.plain || !matches!(self.shell_view(), ShellView::Config) {
            return InputUpdate::ignored();
        }
        match key.code {
            KeyCode::Up => {
                self.move_model_selection(-1);
                InputUpdate::handled()
            }
            KeyCode::Down => {
                self.move_model_selection(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => InputUpdate::handled_with_effects(self.select_current_model_choice()),
            _ => InputUpdate::ignored(),
        }
    }

    /// 3D playground controls (active only while `ShellView::Scene` is open and
    /// the prompt is empty): cycle scenes, pause, reset, and orbit by keyboard.
    pub(super) fn handle_scene_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        let Some(target) = self.gallery_key_target(modifiers) else {
            return InputUpdate::ignored();
        };
        // Gallery hotkeys yield to the prompt the moment the operator starts
        // typing — otherwise `back`/`home` are untypeable on the 3D page
        // (h/j/k/l would orbit the camera instead of reaching the prompt).
        if !self.input().is_empty() {
            return InputUpdate::ignored();
        }
        match target {
            GalleryKeyTarget::EmbeddedMap => self.handle_embedded_map_gallery_key(key),
            GalleryKeyTarget::FullScene => self.handle_full_scene_view_key(key),
        }
    }

    fn gallery_key_target(&self, modifiers: KeyModifierState) -> Option<GalleryKeyTarget> {
        if self.embedded_map_gallery_owns_keys(modifiers) {
            return Some(GalleryKeyTarget::EmbeddedMap);
        }
        self.scene_view_owns_keys(modifiers)
            .then_some(GalleryKeyTarget::FullScene)
    }

    fn handle_full_scene_view_key(&mut self, key: KeyEvent) -> InputUpdate {
        // 3D controls only apply on the attack-surface page; on the DFD page
        // selection keys drive the node/flow inspector cursor instead. Other
        // 2D pages use the shared document-scroll handler. Tab/Shift+Tab/Esc/q
        // work on every page.
        if self.handle_line_scene_scroll_key(key) {
            return InputUpdate::handled();
        }
        let is_3d = self.router.scene().page().is_3d();
        let is_summary = matches!(self.router.scene().page(), crate::scene3d::VizPage::Summary);
        let is_dfd = matches!(self.router.scene().page(), crate::scene3d::VizPage::Dfd);
        let is_entry_points = matches!(
            self.router.scene().page(),
            crate::scene3d::VizPage::EntryPoints
        );
        if is_summary {
            return self.handle_summary_key(key);
        }
        self.handle_frame_scene_key(key, is_3d, is_dfd, is_entry_points)
    }

    fn handle_frame_scene_key(
        &mut self,
        key: KeyEvent,
        is_3d: bool,
        is_dfd: bool,
        is_entry_points: bool,
    ) -> InputUpdate {
        if is_entry_points {
            return self.handle_entry_point_frame_key(key);
        }
        match key.code {
            KeyCode::Tab => self.cycle_scene(1),
            KeyCode::BackTab => self.cycle_scene(-1),
            KeyCode::Char(' ') | KeyCode::Char('p') if is_3d => {
                self.router.scene_mut().toggle_paused()
            }
            KeyCode::Char('r') if is_3d => self.reset_scene_orientation(),
            // Explicit exits: the gallery is a leaf view, never a trap.
            KeyCode::Esc if is_dfd && self.router.scene_mut().collapse_dfd_focus() => {}
            KeyCode::Esc | KeyCode::Char('q') => self.go_back(),
            KeyCode::Char('h') if is_3d => self.nudge_scene_yaw(-1.0),
            KeyCode::Char('l') if is_3d => self.nudge_scene_yaw(1.0),
            KeyCode::Char('k') if is_3d => self.nudge_scene_pitch(1.0),
            KeyCode::Char('j') if is_3d => self.nudge_scene_pitch(-1.0),
            KeyCode::Char('j') | KeyCode::Down if is_dfd => self.cycle_active_dfd_selection(1),
            KeyCode::Char('k') | KeyCode::Up if is_dfd => self.cycle_active_dfd_selection(-1),
            KeyCode::PageDown if is_dfd => self.scroll_dfd_detail(1),
            KeyCode::PageUp if is_dfd => self.scroll_dfd_detail(-1),
            KeyCode::Enter if is_dfd => return self.activate_dfd_selection(),
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    fn handle_entry_point_frame_key(&mut self, key: KeyEvent) -> InputUpdate {
        match key.code {
            KeyCode::Tab => self.cycle_scene(1),
            KeyCode::BackTab => self.cycle_scene(-1),
            KeyCode::Esc | KeyCode::Char('q') if self.input_mode() == InputMode::Navigate => {
                self.go_back()
            }
            _ => return self.handle_entry_point_navigation_key(key),
        }
        InputUpdate::handled()
    }

    fn handle_entry_point_navigation_key(&mut self, key: KeyEvent) -> InputUpdate {
        match key.code {
            KeyCode::Down => self.cycle_entry_point_selection(1),
            KeyCode::Up => self.cycle_entry_point_selection(-1),
            KeyCode::PageDown => self.scroll_entry_point_detail(1),
            KeyCode::PageUp => self.scroll_entry_point_detail(-1),
            _ if self.input_mode() != InputMode::Navigate => return InputUpdate::ignored(),
            KeyCode::Char('j') => self.cycle_entry_point_selection(1),
            KeyCode::Char('k') => self.cycle_entry_point_selection(-1),
            KeyCode::Char('g') => self.jump_entry_point_selection(false),
            KeyCode::Char('G') => self.jump_entry_point_selection(true),
            KeyCode::Enter => return self.activate_entry_point_selection(),
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    fn scene_view_owns_keys(&self, modifiers: KeyModifierState) -> bool {
        modifiers.plain && matches!(self.shell_view(), ShellView::Scene)
    }

    fn embedded_map_gallery_owns_keys(&self, modifiers: KeyModifierState) -> bool {
        if !modifiers.plain
            || self.shell_view() != ShellView::Workbench
            || crate::ui_view_models::active_workbench_page(self) != crate::app::WorkbenchPage::Map
        {
            return false;
        }
        crate::ui_view_models::map_gallery_is_primary(self)
    }

    fn handle_embedded_map_gallery_key(&mut self, key: KeyEvent) -> InputUpdate {
        if key.code == KeyCode::Tab {
            self.cycle_map_viz_page(1);
            return InputUpdate::handled();
        }
        match self.current_map_viz_page() {
            crate::scene3d::VizPage::Summary => self.handle_summary_key(key),
            crate::scene3d::VizPage::Dfd => self.handle_embedded_dfd_key(key),
            crate::scene3d::VizPage::EntryPoints => self.handle_embedded_entry_key(key),
            crate::scene3d::VizPage::Components => self.handle_embedded_component_key(key),
            _ => InputUpdate::ignored(),
        }
    }

    fn handle_summary_key(&mut self, key: KeyEvent) -> InputUpdate {
        if let Some(update) = self.handle_summary_scene_navigation_key(key) {
            return update;
        }
        if self.handle_summary_arrow_or_scroll_key(key) {
            return InputUpdate::handled();
        }
        if self.input_mode() != InputMode::Navigate {
            return InputUpdate::ignored();
        }
        self.handle_summary_navigation_key(key)
    }

    fn handle_summary_scene_navigation_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.shell_view() != ShellView::Scene {
            return None;
        }
        match key.code {
            KeyCode::Tab => self.cycle_scene(1),
            KeyCode::BackTab => self.cycle_scene(-1),
            KeyCode::Esc | KeyCode::Char('q') => self.go_back(),
            _ => return None,
        }
        Some(InputUpdate::handled())
    }

    fn handle_summary_arrow_or_scroll_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Down => self.cycle_summary_component_selection(1),
            KeyCode::Up => self.cycle_summary_component_selection(-1),
            KeyCode::PageDown => self.scroll_summary(1),
            KeyCode::PageUp => self.scroll_summary(-1),
            _ => return false,
        }
        true
    }

    fn handle_summary_navigation_key(&mut self, key: KeyEvent) -> InputUpdate {
        match key.code {
            KeyCode::Char('j') => self.cycle_summary_component_selection(1),
            KeyCode::Char('k') => self.cycle_summary_component_selection(-1),
            KeyCode::Char('g') => self.jump_summary_component_selection(false),
            KeyCode::Char('G') => self.jump_summary_component_selection(true),
            KeyCode::Enter => return self.activate_summary_component_selection(),
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    fn handle_embedded_dfd_key(&mut self, key: KeyEvent) -> InputUpdate {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.cycle_active_dfd_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.cycle_active_dfd_selection(-1),
            KeyCode::PageDown => self.scroll_dfd_detail(1),
            KeyCode::PageUp => self.scroll_dfd_detail(-1),
            KeyCode::Enter => return self.activate_dfd_selection(),
            KeyCode::Esc if self.router.scene_mut().collapse_dfd_focus() => {}
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    fn handle_embedded_entry_key(&mut self, key: KeyEvent) -> InputUpdate {
        self.handle_entry_point_navigation_key(key)
    }

    fn handle_embedded_component_key(&mut self, key: KeyEvent) -> InputUpdate {
        let scroll = self.router.workbench_mut().scroll_mut();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                scroll.shift(crate::ui_view_models::PhaseSurfaceId::MapDfd, 1)
            }
            KeyCode::Char('k') | KeyCode::Up => {
                scroll.shift(crate::ui_view_models::PhaseSurfaceId::MapDfd, -1)
            }
            KeyCode::Char('g') => scroll.set(crate::ui_view_models::PhaseSurfaceId::MapDfd, 0),
            KeyCode::Char('G') => {
                scroll.set(crate::ui_view_models::PhaseSurfaceId::MapDfd, u16::MAX)
            }
            KeyCode::PageDown => scroll.shift(
                crate::ui_view_models::PhaseSurfaceId::MapDfd,
                VIEWPORT_PAGE_LINES as i32,
            ),
            KeyCode::PageUp => scroll.shift(
                crate::ui_view_models::PhaseSurfaceId::MapDfd,
                -(VIEWPORT_PAGE_LINES as i32),
            ),
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    fn handle_line_scene_scroll_key(&mut self, key: KeyEvent) -> bool {
        if self.router.scene().page().is_frame_rendered() {
            return false;
        }
        self.handle_generic_scroll_hotkey(key)
    }

    fn cycle_active_dfd_selection(&mut self, direction: i32) {
        let model = crate::ui_view_models::dfd_model(self);
        if self.router.scene().dfd_focused() {
            let len = crate::ui_view_models::dfd_security_items_for_selection(
                &model,
                self.router.scene().dfd_selection(),
            )
            .len();
            self.router
                .scene_mut()
                .cycle_dfd_context_selection(direction, len);
            return;
        }
        let len = crate::ui_view_models::dfd_selectable_count(&model);
        self.router.scene_mut().cycle_dfd_selection(direction, len);
    }

    fn activate_dfd_selection(&mut self) -> InputUpdate {
        let model = crate::ui_view_models::dfd_model(self);
        if model.empty_hint.is_some()
            || model.link_state == crate::ui_view_models::DfdLinkState::LegacyNeedsRebuild
        {
            return self.request_threat_model_build();
        }
        self.router.scene_mut().toggle_dfd_focus();
        InputUpdate::handled()
    }

    /// The generate affordance shared by every threat-model-backed viz page.
    /// No inline input: descriptor defaults and runtime gates own the build.
    fn request_threat_model_build(&mut self) -> InputUpdate {
        self.reduce_hotkey_command(ShellCommand::RunTool {
            tool: Some("threat-model:build".to_string()),
            input: None,
        })
    }

    fn cycle_summary_component_selection(&mut self, direction: i32) {
        let overview = crate::ui_view_models::dfd_overview(&crate::ui_view_models::dfd_model(self));
        let len = crate::ui_view_models::dfd_overview_component_count(&overview);
        self.router
            .scene_mut()
            .cycle_summary_component_selection(direction, len);
    }

    fn jump_summary_component_selection(&mut self, last: bool) {
        let overview = crate::ui_view_models::dfd_overview(&crate::ui_view_models::dfd_model(self));
        let len = crate::ui_view_models::dfd_overview_component_count(&overview);
        let selection = if last { len.saturating_sub(1) } else { 0 };
        self.router
            .scene_mut()
            .set_summary_component_selection(selection, len);
    }

    fn activate_summary_component_selection(&mut self) -> InputUpdate {
        let dfd = crate::ui_view_models::dfd_model(self);
        // No threat model at all is a different state from a model whose
        // component has no resolved node: offer the build the empty DFD offers
        // rather than telling the operator to rebuild something that is absent.
        if dfd.empty_hint.is_some() {
            return self.request_threat_model_build();
        }
        let overview = crate::ui_view_models::dfd_overview(&dfd);
        let selected = self.router.scene().summary_component_selection();
        let target = crate::ui_view_models::dfd_overview_component_at(&overview, selected)
            .map(|(_, component)| component.key.clone());
        let Some(selection) = target
            .as_deref()
            .and_then(|key| crate::ui_view_models::dfd_selection_for_key(&dfd, key))
        else {
            return self.summary_component_target_missing();
        };
        let len = crate::ui_view_models::dfd_selectable_count(&dfd);
        self.router.scene_mut().set_dfd_selection(selection, len);
        self.router
            .scene_mut()
            .set_page(crate::scene3d::VizPage::Dfd);
        InputUpdate::handled()
    }

    fn summary_component_target_missing(&mut self) -> InputUpdate {
        self.set_warn_notice(
            "component tree",
            "selected component has no resolved DFD node · rebuild with `threat-model:build`",
        );
        InputUpdate::handled()
    }

    fn cycle_entry_point_selection(&mut self, direction: i32) {
        let len = crate::ui_view_models::entry_point_breakdown(self)
            .entries
            .len();
        self.router
            .scene_mut()
            .cycle_entry_point_selection(direction, len);
    }

    fn jump_entry_point_selection(&mut self, last: bool) {
        let len = crate::ui_view_models::entry_point_breakdown(self)
            .entries
            .len();
        let selection = if last { len.saturating_sub(1) } else { 0 };
        self.router
            .scene_mut()
            .set_entry_point_selection(selection, len);
    }

    fn scroll_entry_point_detail(&mut self, direction: i32) {
        self.router
            .scene_mut()
            .scroll_entry_point_detail(direction, VIEWPORT_PAGE_LINES);
    }

    fn activate_entry_point_selection(&mut self) -> InputUpdate {
        let breakdown = crate::ui_view_models::entry_point_breakdown(self);
        let entries = &breakdown.entries;
        let selection = self
            .router
            .scene()
            .entry_point_selection()
            .min(entries.len().saturating_sub(1));
        let selected = entries.get(selection);
        let disposition = selected.map(|entry| entry.disposition);
        let target = selected
            .and_then(|entry| entry.targets.first())
            .map(|target| target.id.clone());
        let Some(target) = target else {
            return self.entry_point_target_missing(disposition);
        };
        let dfd = crate::ui_view_models::dfd_model(self);
        let Some(selection) = crate::ui_view_models::dfd_selection_for_key(&dfd, &target) else {
            return self.entry_point_target_missing(disposition);
        };
        let len = crate::ui_view_models::dfd_selectable_count(&dfd);
        self.router.scene_mut().set_dfd_selection(selection, len);
        self.router
            .scene_mut()
            .set_page(crate::scene3d::VizPage::Dfd);
        InputUpdate::handled()
    }

    fn entry_point_target_missing(
        &mut self,
        disposition: Option<crate::ui_view_models::EntryPointDisposition>,
    ) -> InputUpdate {
        use crate::ui_view_models::EntryPointDisposition;
        let detail = match disposition {
            Some(EntryPointDisposition::ExtractedOnly) => {
                "extractor evidence is not represented in the threat model · run `threat-model:build`"
            }
            Some(EntryPointDisposition::Deprioritized) => {
                "entry point was explicitly deprioritized and has no DFD target"
            }
            Some(EntryPointDisposition::ModelOnly) => {
                "model-only entry has no resolved DFD target · run `threat-model:build`"
            }
            Some(EntryPointDisposition::Modeled) | None => {
                "modeled entry has no resolved DFD target · run `threat-model:build`"
            }
        };
        self.set_warn_notice("entry points", detail);
        InputUpdate::handled()
    }

    fn scroll_dfd_detail(&mut self, direction: i32) {
        self.router
            .scene_mut()
            .scroll_dfd_detail(direction, VIEWPORT_PAGE_LINES);
    }

    fn scroll_summary(&mut self, direction: i32) {
        self.router
            .scene_mut()
            .scroll_summary(direction, VIEWPORT_PAGE_LINES);
    }

    fn cycle_scene(&mut self, direction: i32) {
        self.cycle_scene_page(direction);
    }

    /// Manual orbit implies the operator wants to inspect a frame, so it pauses
    /// the idle spin; `space` resumes it.
    fn nudge_scene_yaw(&mut self, sign: f32) {
        self.router.scene_mut().nudge_yaw(sign * SCENE_NUDGE);
    }

    fn nudge_scene_pitch(&mut self, sign: f32) {
        self.router.scene_mut().nudge_pitch(sign * SCENE_NUDGE);
    }

    fn reset_scene_orientation(&mut self) {
        self.router.scene_mut().reset_orientation();
    }

    pub(super) fn handle_history_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> bool {
        if !modifiers.plain {
            return false;
        }
        match key.code {
            KeyCode::Up => self.history_prev(),
            KeyCode::Down => self.history_next(),
            _ => return false,
        }
        true
    }
}

fn cursor_key_handler(code: KeyCode, modifiers: KeyModifierState) -> Option<fn(&mut ShellApp)> {
    if modifiers.ctrl_or_alt() {
        return cursor_table_handler(code, CTRL_CURSOR_KEY_ACTIONS);
    }
    if modifiers.plain {
        return cursor_table_handler(code, PLAIN_CURSOR_KEY_ACTIONS);
    }
    cursor_table_handler(code, UNMODIFIED_CURSOR_KEY_ACTIONS)
}

fn cursor_table_handler(
    code: KeyCode,
    actions: &[(KeyCode, fn(&mut ShellApp))],
) -> Option<fn(&mut ShellApp)> {
    actions
        .iter()
        .find_map(|(candidate, handler)| (*candidate == code).then_some(*handler))
}

const CTRL_CURSOR_KEY_ACTIONS: &[(KeyCode, fn(&mut ShellApp))] = &[
    (KeyCode::Left, ShellApp::move_cursor_word_left),
    (KeyCode::Right, ShellApp::move_cursor_word_right),
    (KeyCode::Backspace, ShellApp::delete_word_left),
];

const PLAIN_CURSOR_KEY_ACTIONS: &[(KeyCode, fn(&mut ShellApp))] = &[
    (KeyCode::Left, ShellApp::move_cursor_left),
    (KeyCode::Right, ShellApp::move_cursor_right),
    (KeyCode::Home, ShellApp::move_cursor_home),
    (KeyCode::End, ShellApp::move_cursor_end),
    (KeyCode::Delete, ShellApp::delete_forward),
];

const UNMODIFIED_CURSOR_KEY_ACTIONS: &[(KeyCode, fn(&mut ShellApp))] = &[
    (KeyCode::Home, ShellApp::move_cursor_home),
    (KeyCode::End, ShellApp::move_cursor_end),
    (KeyCode::Delete, ShellApp::delete_forward),
];
