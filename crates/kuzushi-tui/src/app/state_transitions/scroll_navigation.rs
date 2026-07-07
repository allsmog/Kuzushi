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
            KeyCode::Char('j') => self.scroll_down(1),
            KeyCode::Char('k') => self.scroll_up(1),
            KeyCode::Char('g') => self.scroll_to_top(),
            KeyCode::Char('G') => self.scroll_to_bottom(),
            _ => return false,
        }
        true
    }

    fn handle_catalog_row_hotkey(&mut self, key: KeyEvent) -> bool {
        if !matches!(self.shell_view, ShellView::Catalog) || !self.catalog_route.is_expanded() {
            return false;
        }
        match key.code {
            KeyCode::Char('j') => self.move_catalog_cursor(1),
            KeyCode::Char('k') => self.move_catalog_cursor(-1),
            KeyCode::Char('g') => self.catalog_route.jump_start(),
            KeyCode::Char('G') => {
                let total = self.catalog_module_count();
                self.catalog_route.jump_end(total);
            }
            _ => return false,
        }
        true
    }

    pub(super) fn page_down_current_view(&mut self) {
        let step = VIEWPORT_PAGE_LINES;
        if self.page_findings_down() {
            return;
        }
        if let Some(kind) = page_scroll_kind(&self.shell_view, self.catalog_route.is_expanded()) {
            self.add_page_scroll(kind, step);
            return;
        }
        if self.is_scrollable_view() {
            self.scroll_down(step as u16);
        }
    }

    pub(super) fn page_up_current_view(&mut self) {
        let step = VIEWPORT_PAGE_LINES;
        if self.page_findings_up() {
            return;
        }
        if let Some(kind) = page_scroll_kind(&self.shell_view, self.catalog_route.is_expanded()) {
            self.subtract_page_scroll(kind, step);
            return;
        }
        if self.is_scrollable_view() {
            self.scroll_up(step as u16);
        }
    }

    fn page_findings_down(&mut self) -> bool {
        if !self.workbench_findings_paging() {
            return false;
        }
        let len = crate::ui_view_models::visible_findings_len(self);
        if len > 0 {
            self.findings_route.page_down(FINDINGS_PAGE_ROWS, len);
        }
        true
    }

    fn page_findings_up(&mut self) -> bool {
        if !self.workbench_findings_paging() {
            return false;
        }
        self.findings_route.page_up(FINDINGS_PAGE_ROWS);
        true
    }

    /// PgUp/PgDn page the FINDINGS list only while the Workbench has that pane
    /// focused; otherwise paging falls through to line/section scrolling.
    fn workbench_findings_paging(&self) -> bool {
        matches!(self.shell_view, ShellView::Workbench)
            && self.workbench_focus == crate::app::WorkbenchPane::Findings
    }

    fn add_page_scroll(&mut self, kind: PageScrollKind, step: usize) {
        let scroll = self.page_scroll_mut(kind);
        *scroll = scroll.saturating_add(step);
    }

    fn subtract_page_scroll(&mut self, kind: PageScrollKind, step: usize) {
        let scroll = self.page_scroll_mut(kind);
        *scroll = scroll.saturating_sub(step);
    }

    fn page_scroll_mut(&mut self, kind: PageScrollKind) -> &mut usize {
        match kind {
            PageScrollKind::Help => self.help_route.scroll_mut(),
            PageScrollKind::Tools => self.tools_route.scroll_mut(),
            PageScrollKind::History => self.history_route.scroll_mut(),
            PageScrollKind::KnowledgeBase => self.kb_route.scroll_mut(),
            PageScrollKind::Modules => self.modules_route.scroll_mut(),
            PageScrollKind::Logs => self.logs_route.scroll_mut(),
        }
    }

    pub(super) fn is_scrollable_view(&self) -> bool {
        match &self.shell_view {
            ShellView::Catalog => self.catalog_route.is_expanded(),
            ShellView::Help
            | ShellView::Quickstart
            | ShellView::Logs
            | ShellView::Health
            | ShellView::Tools
            | ShellView::Options(_)
            | ShellView::Runs
            | ShellView::RunDiff { .. }
            | ShellView::Replay(_)
            | ShellView::Trace(_)
            | ShellView::Activity
            | ShellView::SastTasks
            | ShellView::Context
            | ShellView::ProjectModel
            | ShellView::StrategyQueue
            | ShellView::Workspace
            | ShellView::KnowledgeBase
            | ShellView::AgentChat
            | ShellView::History
            | ShellView::Story
            | ShellView::Threat(_)
            | ShellView::ThreatEditor
            | ShellView::PromptsEditor
            | ShellView::Pwn
            | ShellView::Tune
            | ShellView::ActorDetail(_)
            | ShellView::ModuleRun
            | ShellView::Workbench => true,
            ShellView::Scene(page) => !page.is_3d(),
            _ => false,
        }
    }
}
