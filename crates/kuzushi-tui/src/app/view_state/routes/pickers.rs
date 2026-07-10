use crate::app::{
    auth_method_row_kinds, AuthMethodRowKind, PickerFocus, PlanningOptionEdit, PlanningTaskId,
    PlanningTaskRow,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModelPickerRouteState {
    cursor: usize,
    focus: PickerFocus,
}

impl ModelPickerRouteState {
    pub(crate) fn open(&mut self, cursor: usize, len: usize) {
        self.cursor = cursor.min(len.saturating_sub(1));
        self.focus = PickerFocus::List;
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn move_cursor(&mut self, delta: isize, len: usize) {
        self.cursor = wrapped_cursor(self.cursor, delta, len);
    }

    pub(crate) fn focus(&self) -> PickerFocus {
        self.focus
    }

    pub(crate) fn set_focus(&mut self, focus: PickerFocus) {
        self.focus = focus;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthPickerRouteState {
    cursor: usize,
    focus: PickerFocus,
    provider: String,
    key_draft: String,
    rows: Vec<AuthMethodRowKind>,
}

impl AuthPickerRouteState {
    pub(crate) fn open(&mut self, provider: String) {
        self.cursor = 0;
        self.focus = PickerFocus::List;
        self.rows = auth_method_row_kinds(&provider);
        self.provider = provider;
        self.key_draft.clear();
    }

    pub(crate) fn provider(&self) -> &str {
        &self.provider
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    #[cfg(test)]
    pub(crate) fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Identity of the row under the cursor. Selection is decided by this,
    /// never by a hardcoded index, so promoting the demo row in the layout
    /// cannot desync which action a cursor position triggers.
    pub(crate) fn selected_kind(&self) -> Option<AuthMethodRowKind> {
        self.rows.get(self.cursor).copied()
    }

    #[cfg(test)]
    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor.min(self.rows.len().saturating_sub(1));
    }

    pub(crate) fn is_api_key_row(&self) -> bool {
        self.selected_kind() == Some(AuthMethodRowKind::ApiKey)
    }

    #[cfg(test)]
    pub(crate) fn is_offline_demo_row(&self) -> bool {
        self.selected_kind() == Some(AuthMethodRowKind::OfflineDemo)
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        self.cursor = wrapped_cursor(self.cursor, delta, self.rows.len());
    }

    pub(crate) fn focus(&self) -> PickerFocus {
        self.focus
    }

    pub(crate) fn set_focus(&mut self, focus: PickerFocus) {
        self.focus = focus;
    }

    pub(crate) fn key_draft(&self) -> &str {
        &self.key_draft
    }

    pub(crate) fn key_draft_trimmed(&self) -> &str {
        self.key_draft.trim()
    }

    pub(crate) fn push_key_char(&mut self, ch: char) {
        self.key_draft.push(ch);
    }

    pub(crate) fn push_key_str(&mut self, value: &str) {
        self.key_draft.push_str(value);
    }

    pub(crate) fn pop_key_char(&mut self) {
        self.key_draft.pop();
    }

    pub(crate) fn clear_key_draft(&mut self) {
        self.key_draft.clear();
    }

    pub(crate) fn take_key_draft_trimmed(&mut self) -> String {
        let key = self.key_draft.trim().to_string();
        self.key_draft.clear();
        key
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetPickerRouteState {
    cursor: usize,
    focus: PickerFocus,
    candidates: Vec<crate::app::TargetCandidate>,
}

impl TargetPickerRouteState {
    pub(crate) fn open(&mut self, candidates: Vec<crate::app::TargetCandidate>) {
        self.candidates = candidates;
        self.cursor = 0;
        self.focus = PickerFocus::List;
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn candidates(&self) -> &[crate::app::TargetCandidate] {
        &self.candidates
    }

    #[cfg(test)]
    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor.min(self.candidates.len().saturating_sub(1));
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        self.cursor = wrapped_cursor(self.cursor, delta, self.candidates.len());
    }

    pub(crate) fn focus(&self) -> PickerFocus {
        self.focus
    }

    pub(crate) fn set_focus(&mut self, focus: PickerFocus) {
        self.focus = focus;
    }

    pub(crate) fn selected(&self) -> Option<&crate::app::TargetCandidate> {
        self.candidates.get(self.cursor)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanningPickerRouteState {
    cursor: usize,
    selected: BTreeSet<PlanningTaskId>,
    tasks: Vec<PlanningTaskRow>,
    rebuild: BTreeSet<PlanningTaskId>,
    focus: PickerFocus,
    option_cursor: usize,
    option_edit: Option<PlanningOptionEdit>,
    option_error: Option<String>,
}

impl PlanningPickerRouteState {
    pub(crate) fn open(&mut self, tasks: Vec<PlanningTaskRow>, selected: BTreeSet<PlanningTaskId>) {
        self.tasks = tasks;
        self.selected = selected;
        self.rebuild.clear();
        self.cursor = 0;
        self.focus = PickerFocus::List;
        self.option_cursor = 0;
        self.option_edit = None;
        self.option_error = None;
    }

    pub(crate) fn tasks(&self) -> &[PlanningTaskRow] {
        &self.tasks
    }

    pub(crate) fn selected(&self) -> &BTreeSet<PlanningTaskId> {
        &self.selected
    }

    pub(crate) fn selected_mut(&mut self) -> &mut BTreeSet<PlanningTaskId> {
        &mut self.selected
    }

    pub(crate) fn rebuild(&self) -> &BTreeSet<PlanningTaskId> {
        &self.rebuild
    }

    pub(crate) fn toggle_rebuild(&mut self, task: PlanningTaskId) -> bool {
        if self.rebuild.remove(&task) {
            self.selected.remove(&task);
            false
        } else {
            self.rebuild.insert(task);
            self.selected.insert(task);
            true
        }
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    #[cfg(test)]
    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
        self.clamp_cursor();
    }

    pub(crate) fn current_row(&self) -> Option<&PlanningTaskRow> {
        self.tasks.get(self.cursor)
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        self.cursor = wrapped_cursor(self.cursor, delta, self.tasks.len());
        self.option_cursor = 0;
        self.option_error = None;
    }

    pub(crate) fn focus(&self) -> PickerFocus {
        self.focus
    }

    pub(crate) fn set_focus(&mut self, focus: PickerFocus) {
        self.focus = focus;
    }

    pub(crate) fn option_cursor(&self) -> usize {
        self.option_cursor
    }

    pub(crate) fn clamp_option_cursor(&mut self, count: usize) {
        self.option_cursor = if count == 0 {
            0
        } else {
            self.option_cursor.min(count - 1)
        };
    }

    pub(crate) fn move_option_cursor(&mut self, delta: isize, count: usize) {
        self.option_cursor = wrapped_cursor(self.option_cursor, delta, count);
        self.option_error = None;
    }

    pub(crate) fn option_edit(&self) -> Option<&PlanningOptionEdit> {
        self.option_edit.as_ref()
    }

    pub(crate) fn option_edit_mut(&mut self) -> Option<&mut PlanningOptionEdit> {
        self.option_edit.as_mut()
    }

    pub(crate) fn set_option_edit(&mut self, edit: Option<PlanningOptionEdit>) {
        self.option_edit = edit;
    }

    pub(crate) fn option_error(&self) -> Option<&str> {
        self.option_error.as_deref()
    }

    pub(crate) fn set_option_error(&mut self, error: impl Into<String>) {
        self.option_error = Some(error.into());
    }

    pub(crate) fn clear_option_error(&mut self) {
        self.option_error = None;
    }

    #[cfg(test)]
    fn clamp_cursor(&mut self) {
        self.cursor = self.cursor.min(self.tasks.len().saturating_sub(1));
    }
}

fn wrapped_cursor(cursor: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let current = cursor.min(len - 1) as isize;
    (current + delta).rem_euclid(len as isize) as usize
}
