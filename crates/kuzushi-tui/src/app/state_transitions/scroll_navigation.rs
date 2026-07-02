use super::page_scroll::{page_scroll_kind, PageScrollKind};
use super::*;

impl ShellApp {
    pub(super) fn handle_generic_scroll_hotkey(&mut self, key: KeyEvent) -> bool {
        // Catalog j/k drives the row cursor (`design/mockups/catalog.jsx`
        // advertises `j/k row`), not the module-scroll.  Catalog scrolling
        // already lives on PgUp/PgDn for very tall workspaces.
        if matches!(self.shell_view, ShellView::Catalog) && self.catalog_expanded {
            match key.code {
                KeyCode::Char('j') => {
                    self.move_catalog_cursor(1);
                    return true;
                }
                KeyCode::Char('k') => {
                    self.move_catalog_cursor(-1);
                    return true;
                }
                KeyCode::Char('g') => {
                    self.catalog_cursor = 0;
                    return true;
                }
                KeyCode::Char('G') => {
                    let total = self.catalog_module_count();
                    self.catalog_cursor = total.saturating_sub(1);
                    return true;
                }
                _ => {}
            }
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

    pub(super) fn page_down_current_view(&mut self) {
        let step = VIEWPORT_PAGE_LINES;
        if self.page_findings_down() {
            return;
        }
        if let Some(kind) = page_scroll_kind(&self.shell_view, self.catalog_expanded) {
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
        if let Some(kind) = page_scroll_kind(&self.shell_view, self.catalog_expanded) {
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
            self.findings_cursor =
                (self.findings_cursor + FINDINGS_PAGE_ROWS).min(len.saturating_sub(1));
        }
        true
    }

    fn page_findings_up(&mut self) -> bool {
        if !self.workbench_findings_paging() {
            return false;
        }
        self.findings_cursor = self.findings_cursor.saturating_sub(FINDINGS_PAGE_ROWS);
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
            PageScrollKind::Help => &mut self.help_scroll,
            PageScrollKind::Tools => &mut self.tools_scroll,
            PageScrollKind::History => &mut self.history_scroll,
            PageScrollKind::KnowledgeBase => &mut self.kb_scroll,
            PageScrollKind::Modules => &mut self.modules_scroll,
            PageScrollKind::Logs => &mut self.logs_scroll,
        }
    }

    pub(super) fn is_scrollable_view(&self) -> bool {
        match &self.shell_view {
            ShellView::Catalog => self.catalog_expanded,
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
