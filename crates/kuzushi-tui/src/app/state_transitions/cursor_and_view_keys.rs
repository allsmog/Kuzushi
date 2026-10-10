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
        if self.run_diff_owns_tab(key, modifiers) {
            return self.handle_view_hotkey(key);
        }
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

    fn run_diff_owns_tab(&self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        self.shell_view() == ShellView::RunDiff
            && self.input().is_empty()
            && modifiers.plain
            && matches!(key.code, KeyCode::Tab | KeyCode::BackTab)
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
        // Navigate owns view controls even when the shared composer keeps a
        // preserved draft. Prompt mode is the only mode in which printable
        // keys may extend that draft; a stale/nonempty buffer must not turn an
        // advertised Navigate key such as `1..5` back into prompt text.
        self.input_mode() == InputMode::Navigate
    }

    fn handle_specialized_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> Option<InputUpdate> {
        // First view-specific handler that claims the key wins; the hotkey
        // fallback is last so per-view keys take precedence.
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
        if key.code != KeyCode::Enter {
            return InputUpdate::ignored();
        }
        self.open_model_picker();
        InputUpdate::handled()
    }

    /// 3D playground controls (active only while `ShellView::Scene` is open and
    /// Prompt mode is not mid-draft): cycle scenes, pause, reset, and orbit by
    /// keyboard.
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
        // Only Prompt mode extends that draft, so the yield is Prompt's alone:
        // a draft preserved into Navigate used to disarm the whole gallery,
        // which turned `q` — the advertised way out of a leaf view — into one
        // more character of the draft and left the operator inside the view
        // they asked to leave.
        if self.composer_is_mid_draft() {
            return InputUpdate::ignored();
        }
        match target {
            GalleryKeyTarget::EmbeddedMap => self.handle_embedded_map_gallery_key(key),
            GalleryKeyTarget::FullScene => self.handle_full_scene_view_key(key),
        }
    }

    /// `true` while the composer is mid-draft in the one mode that extends a
    /// draft. This is `view_key_navigation_is_active`'s rule from the other
    /// side: Navigate owns view controls whatever the composer still holds.
    fn composer_is_mid_draft(&self) -> bool {
        self.input_mode() == InputMode::Prompt && !self.input().is_empty()
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
            KeyCode::Char('g') if is_dfd => return self.regenerate_selected_dfd_scope(),
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
        // The Navigate gate below exists for `j/k/g/G`, which are printable and
        // must reach the prompt. Enter on an empty Summary is not ambiguous —
        // there is no cursor to move and the footer advertises it as the
        // generate affordance — so it stays modeless like the empty DFD's
        // Enter. `handle_scene_view_key` has already proved the composer empty.
        if key.code == KeyCode::Enter && crate::ui_view_models::dfd_model_is_empty(self) {
            return self.activate_summary_component_selection();
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
            KeyCode::Char('g') => return self.regenerate_selected_dfd_scope(),
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

    fn regenerate_selected_dfd_scope(&mut self) -> InputUpdate {
        let (target, scope) = match self.selected_scope_regeneration_context() {
            Ok(context) => context,
            Err(error) => return self.refuse_scoped_regeneration(&error),
        };
        self.dispatch_scoped_regeneration(&target, &scope)
    }

    fn selected_scope_regeneration_context(
        &self,
    ) -> Result<(PathBuf, kuzushi_core::NestedProjectScope), String> {
        let evidence = self.selected_dfd_evidence();
        if evidence.is_empty() {
            return Err("selected component has no repository evidence path".to_string());
        }
        let target = self
            .target_owned()
            .ok_or_else(|| "scoped regeneration requires a target".to_string())?;
        let tree = kuzushi_core::load_nested_project_scopes(&target)
            .map_err(|error| format!("could not read the scope tree: {error:#}"))?
            .ok_or_else(|| "run Map decomposition first".to_string())?;
        let scope = crate::app::owning_leaf_scope(&tree, &evidence)
            .cloned()
            .ok_or_else(|| "no eligible leaf scope owns the selected evidence".to_string())?;
        Ok((target, scope))
    }

    fn selected_dfd_evidence(&self) -> Vec<String> {
        let model = crate::ui_view_models::dfd_model(self);
        let rows = crate::ui_view_models::dfd_security_items_for_selection(
            &model,
            self.router.scene().dfd_selection(),
        );
        if self.router.scene().dfd_focused() {
            return rows
                .get(self.router.scene().dfd_context_selection())
                .map(|row| row.evidence_paths.clone())
                .unwrap_or_default();
        }
        rows.into_iter()
            .flat_map(|row| row.evidence_paths.clone())
            .collect()
    }

    fn dispatch_scoped_regeneration(
        &mut self,
        target: &std::path::Path,
        scope: &kuzushi_core::NestedProjectScope,
    ) -> InputUpdate {
        let methodology = self.configured_map_methodology();
        let input = match crate::app::scoped_regeneration_input(target, scope, &methodology) {
            Ok(input) => input,
            Err(error) => {
                return self.refuse_scoped_regeneration(&format!(
                    "could not bind scoped regeneration: {error:#}"
                ));
            }
        };
        self.reduce_hotkey_command(ShellCommand::RunTool {
            tool: Some("threat-model:build".to_string()),
            input: Some(input.to_string()),
        })
    }

    fn refuse_scoped_regeneration(&mut self, detail: &str) -> InputUpdate {
        self.set_warn_notice("Map regeneration", detail);
        InputUpdate::handled()
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
        if let Some(scroll) = crate::renderer::entry_point_page_scroll(self, direction) {
            self.router
                .scene_mut()
                .set_entry_point_detail_scroll(scroll);
        }
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
        let rows = crate::renderer::summary_page_rows(self)
            .unwrap_or(VIEWPORT_PAGE_LINES)
            .min(VIEWPORT_PAGE_LINES);
        self.router.scene_mut().scroll_summary(direction, rows);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn navigate_mode_keeps_phase_keys_active_with_a_preserved_draft() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Prove));
        app.set_input("preserved draft");
        app.set_input_mode(InputMode::Navigate);

        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));

        assert!(update.handled);
        assert_eq!(
            crate::ui_view_models::active_workbench_page(&app),
            crate::app::WorkbenchPage::Review
        );
        assert_eq!(app.input(), "preserved draft");
        assert_eq!(app.input_mode(), InputMode::Navigate);
    }

    #[test]
    fn prompt_mode_still_appends_phase_digits_to_the_draft() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Prove));
        app.set_input("draft");
        app.set_input_mode(InputMode::Prompt);

        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE));

        assert!(update.handled);
        assert_eq!(
            crate::ui_view_models::active_workbench_page(&app),
            crate::app::WorkbenchPage::Prove
        );
        assert_eq!(app.input(), "draft5");
        assert_eq!(app.input_mode(), InputMode::Prompt);
    }

    /// The `/scene` gallery is a leaf view whose own keys are the only way to
    /// cycle or leave it. A draft preserved into Navigate mode used to disarm
    /// every one of them: `Tab` did nothing at all and `q` was typed into the
    /// draft, leaving the operator inside the view they asked to leave.
    #[test]
    fn navigate_mode_keeps_gallery_keys_active_with_a_preserved_draft() {
        let (_target, mut app) = scene_gallery_app(InputMode::Navigate, "preserved draft");
        let before = app.router.scene().page();

        let update = app.reduce_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));

        assert!(update.handled);
        assert_ne!(app.router.scene().page(), before);
        assert_eq!(app.input(), "preserved draft");
        assert_eq!(app.input_mode(), InputMode::Navigate);
    }

    #[test]
    fn navigate_mode_gallery_exit_leaves_the_scene_instead_of_typing() {
        let (_target, mut app) = scene_gallery_app(InputMode::Navigate, "preserved draft");

        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));

        assert!(update.handled);
        assert_ne!(app.shell_view(), ShellView::Scene);
        // The view it lands on owns its own composer mode; what matters here
        // is that the draft survived instead of absorbing the exit key.
        assert_eq!(app.input(), "preserved draft");
    }

    /// Prompt mode still owns a draft in progress, so the gallery keeps
    /// yielding the printable keys `back`/`home` are spelled with.
    #[test]
    fn prompt_mode_gallery_keys_still_extend_the_draft() {
        let (_target, mut app) = scene_gallery_app(InputMode::Prompt, "draft");

        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));

        assert!(update.handled);
        assert_eq!(app.shell_view(), ShellView::Scene);
        assert_eq!(app.input(), "draftq");
        assert_eq!(app.input_mode(), InputMode::Prompt);
    }

    fn scene_gallery_app(mode: InputMode, draft: &str) -> (tempfile::TempDir, ShellApp) {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_shell_view(ShellView::Scene);
        app.set_input(draft);
        app.set_input_mode(mode);
        (target, app)
    }

    #[test]
    fn dfd_g_prepares_regeneration_for_the_leaf_that_owns_structured_evidence() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("services/api/src")).unwrap();
        let tree = scope_tree();
        kuzushi_core::save_nested_project_scopes(target.path(), &tree).unwrap();
        let scope =
            kuzushi_core::capabilities::current_scope_ref_for_path(target.path(), "services/api")
                .unwrap()
                .unwrap();
        let committed = commit_scope_model(target.path(), scope);
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();
        let model = crate::ui_view_models::dfd_model(&app);
        assert_eq!(model.security_context.len(), 1, "{model:#?}");
        assert_eq!(
            model.security_context[0].evidence_paths,
            ["services/api/src/routes.rs"]
        );

        let key = KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty());
        let update = app.handle_frame_scene_key(key, false, true, false);
        let [ShellEffect::PrepareRunTool(preparation)] = update.effects.as_slice() else {
            panic!("DFD g must prepare one scoped build");
        };
        let input: serde_json::Value =
            serde_json::from_str(preparation.input.as_deref().unwrap()).unwrap();

        assert!(update.handled);
        assert_eq!(preparation.tool_name, "threat-model:build");
        assert_eq!(input["scope"], json!("id:api"));
        assert_eq!(input["modelId"], json!(committed.model_id.as_str()));
        assert_eq!(input["mode"], json!("refine"));
    }

    fn scope_tree() -> kuzushi_core::NestedProjectScopeTree {
        kuzushi_core::NestedProjectScopeTree {
            schema_version: 2,
            root: kuzushi_core::workspace::ROOT_SCOPE_ID.to_string(),
            scopes: vec![
                kuzushi_core::NestedProjectScope {
                    id: kuzushi_core::workspace::ROOT_SCOPE_ID.to_string(),
                    parent: None,
                    kind: kuzushi_core::NestedProjectKind::Root,
                    rel_path: ".".to_string(),
                    inherited_sections: Vec::new(),
                },
                kuzushi_core::NestedProjectScope {
                    id: "api".to_string(),
                    parent: Some(kuzushi_core::workspace::ROOT_SCOPE_ID.to_string()),
                    kind: kuzushi_core::NestedProjectKind::PackageRoot,
                    rel_path: "services/api".to_string(),
                    inherited_sections: Vec::new(),
                },
            ],
        }
    }

    fn commit_scope_model(
        root: &std::path::Path,
        scope: kuzushi_core::ScopeRef,
    ) -> kuzushi_core::ThreatModelRef {
        let document = json!({
            "version": "2.0",
            "methodology": "stride",
            "dfd": {
                "nodes": [
                    {"id": "api", "name": "API", "trustZone": "service"},
                    {"id": "db", "name": "Database", "trustZone": "data"}
                ],
                "flows": [{
                    "id": "api-to-db",
                    "sourceId": "api",
                    "targetId": "db",
                    "description": "query"
                }],
                "trustBoundaries": []
            },
            "attackSurface": {"entryPoints": [{
                "id": "EP-api",
                "name": "API route",
                "path": "services/api/src/routes.rs",
                "targetElementIds": ["api"]
            }]},
            "threats": [],
            "summary": {"text": "API scope"}
        });
        kuzushi_core::capabilities::commit_threat_model_revision(
            root,
            &document,
            kuzushi_core::ThreatModelCommit {
                model_id: None,
                new_model: false,
                label: "API STRIDE".to_string(),
                scope,
                methodology: "stride".to_string(),
                source: kuzushi_core::ThreatModelRevisionSource::Build,
                source_revision_id: None,
                run_id: None,
                activate: Some(true),
                actor: "test".to_string(),
            },
        )
        .unwrap()
        .model_ref
    }
}
