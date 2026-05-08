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
        match self.shell_view {
            ShellView::Findings => {
                if !self.findings.is_empty() {
                    self.findings_cursor = (self.findings_cursor + FINDINGS_PAGE_ROWS)
                        .min(self.findings.len().saturating_sub(1));
                }
            }
            ShellView::Help | ShellView::Quickstart => {
                self.help_scroll = self.help_scroll.saturating_add(step);
            }
            ShellView::Tools => self.tools_scroll = self.tools_scroll.saturating_add(step),
            ShellView::History => self.history_scroll = self.history_scroll.saturating_add(step),
            ShellView::KnowledgeBase => self.kb_scroll = self.kb_scroll.saturating_add(step),
            ShellView::Catalog if self.catalog_expanded => {
                self.modules_scroll = self.modules_scroll.saturating_add(step);
            }
            _ if self.is_scrollable_view() => self.scroll_down(step as u16),
            _ => {}
        }
    }

    pub(super) fn page_up_current_view(&mut self) {
        let step = VIEWPORT_PAGE_LINES;
        match self.shell_view {
            ShellView::Findings => {
                self.findings_cursor = self.findings_cursor.saturating_sub(FINDINGS_PAGE_ROWS);
            }
            ShellView::Help | ShellView::Quickstart => {
                self.help_scroll = self.help_scroll.saturating_sub(step);
            }
            ShellView::Tools => self.tools_scroll = self.tools_scroll.saturating_sub(step),
            ShellView::History => self.history_scroll = self.history_scroll.saturating_sub(step),
            ShellView::KnowledgeBase => self.kb_scroll = self.kb_scroll.saturating_sub(step),
            ShellView::Catalog if self.catalog_expanded => {
                self.modules_scroll = self.modules_scroll.saturating_sub(step);
            }
            _ if self.is_scrollable_view() => self.scroll_up(step as u16),
            _ => {}
        }
    }

    pub(super) fn is_scrollable_view(&self) -> bool {
        match &self.shell_view {
            ShellView::Catalog => self.catalog_expanded,
            ShellView::Help
            | ShellView::Quickstart
            | ShellView::Tools
            | ShellView::Options(_)
            | ShellView::Runs
            | ShellView::Replay(_)
            | ShellView::Trace(_)
            | ShellView::SastTasks
            | ShellView::Context
            | ShellView::Workspace
            | ShellView::KnowledgeBase
            | ShellView::AgentChat
            | ShellView::History
            | ShellView::Story
            | ShellView::Threat(_)
            | ShellView::ThreatEditor
            | ShellView::PromptsEditor
            | ShellView::Tune
            | ShellView::ActorDetail(_)
            | ShellView::ModuleRun
            | ShellView::Finding => true,
            _ => false,
        }
    }
}
