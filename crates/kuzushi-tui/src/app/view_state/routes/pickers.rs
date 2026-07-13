use crate::app::{
    auth_method_row_kinds, AuthMethodRowKind, PickerFocus, PlanningArtifactState,
    PlanningOptionEdit, PlanningTaskId, PlanningTaskRow, WorkflowPhase,
};
use std::collections::{BTreeMap, BTreeSet};

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

    pub(crate) fn replace_candidates(&mut self, candidates: Vec<crate::app::TargetCandidate>) {
        let selected = self.selected().map(|candidate| candidate.path.clone());
        self.candidates = candidates;
        self.cursor = selected
            .and_then(|path| {
                self.candidates
                    .iter()
                    .position(|candidate| candidate.path == path)
            })
            .unwrap_or(0);
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
    phase: Option<WorkflowPhase>,
    cursor: usize,
    selected: BTreeSet<PlanningTaskId>,
    default_selected: BTreeSet<PlanningTaskId>,
    draft_selected: BTreeMap<WorkflowPhase, BTreeSet<PlanningTaskId>>,
    draft_rebuild: BTreeMap<WorkflowPhase, BTreeSet<PlanningTaskId>>,
    tasks: Vec<PlanningTaskRow>,
    rebuild: BTreeSet<PlanningTaskId>,
    profile_pending: bool,
    focus: PickerFocus,
    option_cursor: usize,
    option_edit: Option<PlanningOptionEdit>,
    option_error: Option<String>,
}

impl PlanningPickerRouteState {
    #[cfg(test)]
    pub(crate) fn open(&mut self, tasks: Vec<PlanningTaskRow>, selected: BTreeSet<PlanningTaskId>) {
        self.open_profiled(tasks, selected, false);
    }

    #[cfg(test)]
    pub(crate) fn open_profiled(
        &mut self,
        tasks: Vec<PlanningTaskRow>,
        selected: BTreeSet<PlanningTaskId>,
        profile_pending: bool,
    ) {
        self.phase = None;
        self.tasks = tasks;
        self.default_selected = selected.clone();
        self.selected = selected;
        self.rebuild.clear();
        self.profile_pending = profile_pending;
        self.cursor = first_selected_planning_row(&self.tasks, &self.selected);
        self.focus = PickerFocus::List;
        self.option_cursor = 0;
        self.option_edit = None;
        self.option_error = None;
    }

    pub(crate) fn open_phase_profiled(
        &mut self,
        phase: WorkflowPhase,
        tasks: Vec<PlanningTaskRow>,
        defaults: BTreeSet<PlanningTaskId>,
        profile_pending: bool,
    ) {
        self.save_phase_draft();
        let selected = self
            .draft_selected
            .get(&phase)
            .map(|draft| available_tasks(draft, &tasks))
            .unwrap_or_else(|| defaults.clone());
        let rebuild = self
            .draft_rebuild
            .get(&phase)
            .map(|draft| available_tasks(draft, &tasks))
            .unwrap_or_default();
        self.phase = Some(phase);
        self.tasks = tasks;
        self.default_selected = defaults;
        self.selected = selected;
        self.rebuild = rebuild;
        self.profile_pending = profile_pending;
        self.reset_open_state();
    }

    fn save_phase_draft(&mut self) {
        let Some(phase) = self.phase else {
            return;
        };
        self.draft_selected.insert(phase, self.selected.clone());
        self.draft_rebuild.insert(phase, self.rebuild.clone());
    }

    fn reset_open_state(&mut self) {
        self.cursor = first_selected_planning_row(&self.tasks, &self.selected);
        self.focus = PickerFocus::List;
        self.option_cursor = 0;
        self.option_edit = None;
        self.option_error = None;
    }

    pub(crate) fn refresh_profiled(
        &mut self,
        tasks: Vec<PlanningTaskRow>,
        defaults: BTreeSet<PlanningTaskId>,
    ) {
        let focused = self.current_row().map(|row| row.id);
        self.selected =
            refreshed_profile_selection(&self.selected, &self.default_selected, &defaults, &tasks);
        self.default_selected = defaults;
        self.rebuild
            .retain(|task| tasks.iter().any(|row| row.id == *task));
        self.tasks = tasks;
        self.cursor = refreshed_profile_cursor(focused, &self.tasks, &self.selected);
        self.profile_pending = false;
        self.option_cursor = 0;
        self.option_edit = None;
        self.option_error = None;
    }

    pub(crate) fn profile_pending(&self) -> bool {
        self.profile_pending
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

fn first_selected_planning_row(
    tasks: &[PlanningTaskRow],
    selected: &BTreeSet<PlanningTaskId>,
) -> usize {
    tasks
        .iter()
        .position(|row| selected_runnable_row(row, selected))
        .or_else(|| tasks.iter().position(|row| selected.contains(&row.id)))
        .unwrap_or(0)
}

fn available_tasks(
    selected: &BTreeSet<PlanningTaskId>,
    tasks: &[PlanningTaskRow],
) -> BTreeSet<PlanningTaskId> {
    let available = tasks.iter().map(|row| row.id).collect::<BTreeSet<_>>();
    selected.intersection(&available).copied().collect()
}

fn refreshed_profile_selection(
    selected: &BTreeSet<PlanningTaskId>,
    previous_defaults: &BTreeSet<PlanningTaskId>,
    defaults: &BTreeSet<PlanningTaskId>,
    tasks: &[PlanningTaskRow],
) -> BTreeSet<PlanningTaskId> {
    let available = tasks.iter().map(|row| row.id).collect::<BTreeSet<_>>();
    let added = selected.difference(previous_defaults);
    let removed = previous_defaults.difference(selected);
    let mut refreshed: BTreeSet<PlanningTaskId> =
        defaults.intersection(&available).copied().collect();
    refreshed.extend(added.filter(|task| available.contains(task)).copied());
    for task in removed {
        refreshed.remove(task);
    }
    refreshed
}

fn refreshed_profile_cursor(
    focused: Option<PlanningTaskId>,
    tasks: &[PlanningTaskRow],
    selected: &BTreeSet<PlanningTaskId>,
) -> usize {
    focused
        .and_then(|task| tasks.iter().position(|row| row.id == task))
        .unwrap_or_else(|| first_selected_planning_row(tasks, selected))
}

fn selected_runnable_row(row: &PlanningTaskRow, selected: &BTreeSet<PlanningTaskId>) -> bool {
    selected.contains(&row.id)
        && row.cli_available
        && !row.id.is_inline_action()
        && !matches!(row.artifact_state, PlanningArtifactState::Cached)
}

fn wrapped_cursor(cursor: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let current = cursor.min(len - 1) as isize;
    (current + delta).rem_euclid(len as isize) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn phase_reopen_preserves_selection_and_rebuild_draft() {
        let mut route = PlanningPickerRouteState::default();
        let rows = rows_for(&[
            PlanningTaskId::GatherRepoContext,
            PlanningTaskId::MapEntryPoints,
        ]);
        route.open_phase_profiled(
            WorkflowPhase::Map,
            rows.clone(),
            BTreeSet::from([
                PlanningTaskId::GatherRepoContext,
                PlanningTaskId::MapEntryPoints,
            ]),
            false,
        );
        route.selected_mut().remove(&PlanningTaskId::MapEntryPoints);
        route.toggle_rebuild(PlanningTaskId::GatherRepoContext);

        route.open_phase_profiled(
            WorkflowPhase::Map,
            rows,
            BTreeSet::from([PlanningTaskId::MapEntryPoints]),
            false,
        );

        assert_eq!(
            route.selected(),
            &BTreeSet::from([PlanningTaskId::GatherRepoContext])
        );
        assert_eq!(
            route.rebuild(),
            &BTreeSet::from([PlanningTaskId::GatherRepoContext])
        );
    }

    #[test]
    fn phase_drafts_remain_independent() {
        let mut route = PlanningPickerRouteState::default();
        route.open_phase_profiled(
            WorkflowPhase::Map,
            rows_for(&[PlanningTaskId::GatherRepoContext]),
            BTreeSet::from([PlanningTaskId::GatherRepoContext]),
            false,
        );
        route.selected_mut().clear();
        route.open_phase_profiled(
            WorkflowPhase::Hunt,
            rows_for(&[PlanningTaskId::ScanSecrets]),
            BTreeSet::from([PlanningTaskId::ScanSecrets]),
            false,
        );
        route.open_phase_profiled(
            WorkflowPhase::Map,
            rows_for(&[PlanningTaskId::GatherRepoContext]),
            BTreeSet::from([PlanningTaskId::GatherRepoContext]),
            false,
        );

        assert!(route.selected().is_empty());
    }

    fn rows_for(tasks: &[PlanningTaskId]) -> Vec<PlanningTaskRow> {
        tasks.iter().copied().map(test_row).collect()
    }

    fn test_row(id: PlanningTaskId) -> PlanningTaskRow {
        PlanningTaskRow {
            id,
            label: id.label(),
            tool_name: id.tool_name(),
            artifact_path: PathBuf::from("/tmp/artifact"),
            artifact_state: PlanningArtifactState::Missing,
            artifact_modified: None,
            model_backed: id.is_model_backed(),
            required_cli: None,
            cli_available: true,
            blocker: None,
        }
    }
}
