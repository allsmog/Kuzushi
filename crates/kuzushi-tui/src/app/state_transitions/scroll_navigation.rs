use super::page_scroll::{page_scroll_kind, PageScrollKind};
use super::*;

impl ShellApp {
    pub(super) fn handle_generic_scroll_hotkey(&mut self, key: KeyEvent) -> bool {
        if self.handle_catalog_row_hotkey(key) {
            return true;
        }
        if !self.is_scrollable_view() {
            return false;
        }
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => self.scroll_current_view_down(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_current_view_up(1),
            KeyCode::Char('g') => self.scroll_current_view_to_top(),
            KeyCode::Char('G') => self.scroll_current_view_to_bottom(),
            _ => return false,
        }
        true
    }

    pub(super) fn scroll_current_view_down(&mut self, amount: usize) {
        if let Some(kind) = self.current_page_scroll_kind() {
            self.add_page_scroll(kind, amount);
        } else {
            self.scroll_down(amount.min(u16::MAX as usize) as u16);
        }
    }

    pub(super) fn scroll_current_view_up(&mut self, amount: usize) {
        if let Some(kind) = self.current_page_scroll_kind() {
            self.subtract_page_scroll(kind, amount);
        } else {
            self.scroll_up(amount.min(u16::MAX as usize) as u16);
        }
    }

    pub(super) fn scroll_current_view_to_top(&mut self) {
        if matches!(self.shell_view(), ShellView::Logs) {
            // Jumping to the start of the transcript is leaving the tail; the
            // footer must not keep claiming the view is following new output.
            self.router.logs_mut().jump_to_start();
            return;
        }
        if let Some(kind) = self.current_page_scroll_kind() {
            *self.page_scroll_mut(kind) = 0;
        } else {
            self.scroll_to_top();
        }
    }

    pub(super) fn scroll_current_view_to_bottom(&mut self) {
        if matches!(self.shell_view(), ShellView::Logs) {
            // Jumping to the end of the transcript is also how the operator
            // asks to follow new output again.
            self.router.logs_mut().follow_tail();
            return;
        }
        if let Some(kind) = self.current_page_scroll_kind() {
            *self.page_scroll_mut(kind) = usize::MAX;
        } else {
            self.scroll_to_bottom();
        }
    }

    fn current_page_scroll_kind(&self) -> Option<PageScrollKind> {
        page_scroll_kind(&self.shell_view(), self.router.catalog().is_expanded())
    }

    fn handle_catalog_row_hotkey(&mut self, key: KeyEvent) -> bool {
        if !matches!(self.shell_view(), ShellView::Catalog) {
            return false;
        }
        match key.code {
            KeyCode::Char('j') => self.move_catalog_cursor(1),
            KeyCode::Char('k') => self.move_catalog_cursor(-1),
            KeyCode::Char('g') => self.router.catalog_mut().jump_start(),
            KeyCode::Char('G') => {
                let total = self.catalog_module_count();
                self.router.catalog_mut().jump_end(total);
            }
            _ => return false,
        }
        true
    }

    pub(super) fn page_down_current_view(&mut self) {
        let step = self.current_page_step();
        if self.page_findings_down() {
            return;
        }
        if let Some(kind) =
            page_scroll_kind(&self.shell_view(), self.router.catalog().is_expanded())
        {
            self.add_page_scroll(kind, step);
            return;
        }
        if self.is_scrollable_view() {
            self.scroll_down(step as u16);
        }
    }

    pub(super) fn page_up_current_view(&mut self) {
        let step = self.current_page_step();
        if self.page_findings_up() {
            return;
        }
        if let Some(kind) =
            page_scroll_kind(&self.shell_view(), self.router.catalog().is_expanded())
        {
            self.subtract_page_scroll(kind, step);
            return;
        }
        if self.is_scrollable_view() {
            self.scroll_up(step as u16);
        }
    }

    fn current_page_step(&self) -> usize {
        crate::renderer::workbench_scroll_page_rows(self)
            .or_else(|| crate::renderer::finding_group_page_rows(self))
            .or_else(|| {
                crate::renderer::activity_output_scroll(self).map(|scroll| scroll.page_rows)
            })
            .or_else(|| crate::renderer::run_artifact_page_rows(self))
            .or_else(|| crate::renderer::recommendation_page_rows(self))
            .or_else(|| crate::renderer::strategy_queue_page_rows(self))
            .or_else(|| crate::renderer::logs_reader_scroll(self).map(|reader| reader.page_rows))
            .or_else(|| crate::renderer::keymap_reader_scroll(self).map(|reader| reader.page_rows))
            .or_else(|| {
                crate::renderer::campaign_reader_scroll(self).map(|reader| reader.page_rows)
            })
            .or_else(|| crate::renderer::coverage_page_rows(self))
            .or_else(|| crate::renderer::context_page_rows(self))
            .or_else(|| crate::renderer::scene_page_rows(self))
            .unwrap_or(VIEWPORT_PAGE_LINES)
    }

    fn page_findings_down(&mut self) -> bool {
        if !self.workbench_findings_paging() {
            return false;
        }
        let len = crate::ui_view_models::visible_findings_len(self);
        if len > 0 {
            self.router
                .findings_mut()
                .page_down(FINDINGS_PAGE_ROWS, len);
        }
        true
    }

    fn page_findings_up(&mut self) -> bool {
        if !self.workbench_findings_paging() {
            return false;
        }
        self.router.findings_mut().page_up(FINDINGS_PAGE_ROWS);
        true
    }

    /// PgUp/PgDn page the FINDINGS list only while the Workbench has that pane
    /// focused; otherwise paging falls through to line/section scrolling.
    fn workbench_findings_paging(&self) -> bool {
        if !matches!(self.shell_view(), ShellView::Workbench) {
            return false;
        }
        let viewport = self.viewport();
        let Some(plan) = crate::renderer::workbench_phase_plan_for_app(
            self,
            ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
        ) else {
            return false;
        };
        plan.surface(plan.effective_focus).is_some_and(|surface| {
            surface.interaction == crate::ui_view_models::SurfaceInteraction::Selectable
        })
    }

    fn add_page_scroll(&mut self, kind: PageScrollKind, step: usize) {
        if matches!(kind, PageScrollKind::Campaign) {
            self.shift_campaign_scroll(step.min(isize::MAX as usize) as isize);
            return;
        }
        if matches!(kind, PageScrollKind::Logs) {
            self.scroll_down(step.min(u16::MAX as usize) as u16);
            return;
        }
        let scroll = self.page_scroll_mut(kind);
        *scroll = scroll.saturating_add(step);
    }

    fn subtract_page_scroll(&mut self, kind: PageScrollKind, step: usize) {
        if matches!(kind, PageScrollKind::Campaign) {
            self.shift_campaign_scroll(-(step.min(isize::MAX as usize) as isize));
            return;
        }
        if matches!(kind, PageScrollKind::Logs) {
            self.scroll_up(step.min(u16::MAX as usize) as u16);
            return;
        }
        let scroll = self.page_scroll_mut(kind);
        *scroll = scroll.saturating_sub(step);
    }

    fn shift_campaign_scroll(&mut self, amount: isize) {
        let max =
            crate::renderer::campaign_reader_scroll(self).map_or(0, |reader| reader.max_offset);
        let scroll = &mut self.router.campaign_mut().read_scroll;
        *scroll = (*scroll).min(max).saturating_add_signed(amount).min(max);
    }

    fn page_scroll_mut(&mut self, kind: PageScrollKind) -> &mut usize {
        match kind {
            PageScrollKind::Help => self.router.help_mut().scroll_mut(),
            PageScrollKind::Tools => self.router.tools_mut().scroll_mut(),
            PageScrollKind::History => self.router.history_mut().scroll_mut(),
            PageScrollKind::KnowledgeBase => self.router.kb_mut().scroll_mut(),
            PageScrollKind::Modules => self.router.modules_mut().scroll_mut(),
            PageScrollKind::Logs => self.router.logs_mut().scroll_mut(),
            PageScrollKind::Campaign => &mut self.router.campaign_mut().read_scroll,
        }
    }

    pub(super) fn is_scrollable_view(&self) -> bool {
        self.is_view_scrollable(self.shell_view())
    }

    pub(super) fn is_view_scrollable(&self, view: ShellView) -> bool {
        if view == ShellView::Scene {
            return !self.router.scene().page().is_frame_rendered();
        }
        SCROLLABLE_SHELL_VIEWS.contains(&view)
    }
}

const SCROLLABLE_SHELL_VIEWS: &[ShellView] = &[
    ShellView::Recommend,
    ShellView::Relationships,
    ShellView::Lessons,
    ShellView::Catalog,
    ShellView::Help,
    ShellView::Module,
    ShellView::Quickstart,
    ShellView::Logs,
    ShellView::Config,
    ShellView::Permissions,
    ShellView::Health,
    ShellView::Keymap,
    ShellView::Tools,
    ShellView::Options,
    ShellView::Runs,
    ShellView::RunDiff,
    ShellView::Replay,
    ShellView::Trace,
    ShellView::Activity,
    ShellView::SastTasks,
    ShellView::Context,
    ShellView::FailureHandoff,
    ShellView::ProjectModel,
    ShellView::StrategyQueue,
    ShellView::Workspace,
    ShellView::KnowledgeBase,
    ShellView::History,
    ShellView::Story,
    ShellView::Threat,
    ShellView::ThreatEditor,
    ShellView::PromptsEditor,
    ShellView::Pwn,
    ShellView::Tune,
    ShellView::ActorDetail,
    ShellView::Campaign,
    ShellView::Coverage,
    ShellView::ModuleRun,
    ShellView::Report,
    ShellView::Workbench,
];

#[cfg(test)]
mod coverage_scroll_tests {
    use super::*;

    #[test]
    fn component_gallery_paging_keeps_the_draft_and_covers_each_visible_row() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::Scene);
        app.router
            .scene_mut()
            .set_page(crate::scene3d::VizPage::Components);
        app.set_viewport(crate::TerminalViewport::new(40, 12));
        app.set_input_mode(InputMode::Navigate);
        app.set_input("saved component draft");
        let rows = crate::renderer::scene_page_rows(&app).unwrap();
        assert!(rows < VIEWPORT_PAGE_LINES);
        app.page_down_current_view();
        assert_eq!(usize::from(app.router.default_scroll().offset()), rows);
        app.page_up_current_view();
        assert_eq!(app.router.default_scroll().offset(), 0);
        assert_eq!(app.input(), "saved component draft");
    }

    #[test]
    fn context_paging_does_not_skip_body_rows_or_change_a_preserved_draft() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::Context);
        app.set_viewport(crate::TerminalViewport::new(40, 12));
        app.set_input_mode(InputMode::Navigate);
        app.set_input("saved context draft");
        let visible = crate::renderer::context_page_rows(&app).unwrap();
        assert!(visible < VIEWPORT_PAGE_LINES);
        app.page_down_current_view();
        assert_eq!(usize::from(app.router.default_scroll().offset()), visible);
        app.page_up_current_view();
        assert_eq!(app.router.default_scroll().offset(), 0);
        assert_eq!(app.input(), "saved context draft");
        assert_eq!(app.shell_view(), ShellView::Context);
    }

    #[test]
    fn coverage_reader_owns_page_and_line_navigation_without_changing_the_draft() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::Coverage);
        app.set_input_mode(InputMode::Navigate);
        app.set_input("saved draft");
        assert!(app.is_scrollable_view());
        app.page_down_current_view();
        assert!(app.router.default_scroll().offset() > 0);
        app.page_up_current_view();
        assert_eq!(app.router.default_scroll().offset(), 0);
        app.handle_generic_scroll_hotkey(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.router.default_scroll().offset(), 1);
        assert_eq!(app.input(), "saved draft");
        assert_eq!(app.shell_view(), ShellView::Coverage);
    }
}
