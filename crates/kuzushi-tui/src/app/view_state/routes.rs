mod pickers;

pub use pickers::{
    AuthPickerRouteState, ModelPickerRouteState, PlanningPickerRouteState, TargetPickerRouteState,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouterState {
    help: HelpRouteState,
    tools: ToolsRouteState,
    history: ScrollRouteState,
    kb: ScrollRouteState,
    modules: ScrollRouteState,
    logs: ScrollRouteState,
}

impl RouterState {
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
    return_view: Option<crate::app::ShellView>,
}

impl FilePickerRouteState {
    pub(crate) fn open(
        &mut self,
        files: Vec<String>,
        truncated: bool,
        current_view: &crate::app::ShellView,
    ) {
        self.files = files;
        self.query.clear();
        self.cursor = 0;
        self.truncated = truncated;
        if !matches!(current_view, crate::app::ShellView::FilePicker) {
            self.return_view = Some(current_view.clone());
        }
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

    pub(crate) fn close_return_view(&mut self) -> crate::app::ShellView {
        self.return_view
            .take()
            .unwrap_or(crate::app::ShellView::KnowledgeBase)
    }

    pub(crate) fn clear_return_view(&mut self) {
        self.return_view = None;
    }

    fn clamp_cursor(&mut self) {
        let len = self.filtered_paths().len();
        self.cursor = self.cursor.min(len.saturating_sub(1));
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingsRouteState {
    cursor: usize,
}

impl FindingsRouteState {
    pub(crate) fn reset(&mut self) {
        self.cursor = 0;
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
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
