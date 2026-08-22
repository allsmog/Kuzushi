use crate::app::{
    auth_method_row_kinds, credential_recovery_row_kinds, AuthMethodRowKind, PickerFocus,
    PlanningArtifactState, PlanningOptionEdit, PlanningTaskId, PlanningTaskRow, WorkflowPhase,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupRowId {
    Target,
    Plan,
    Model,
    Credentials,
    Prompt,
    Budget,
    Start,
}

impl SetupRowId {
    pub const ALL: [Self; 7] = [
        Self::Target,
        Self::Plan,
        Self::Model,
        Self::Credentials,
        Self::Prompt,
        Self::Budget,
        Self::Start,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupEditor {
    Target,
    Plan,
    Model,
    Credentials,
    Prompt,
    Budget,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupRouteState {
    cursor: usize,
    focus: PickerFocus,
    editor: Option<SetupEditor>,
    budget_draft: String,
    budget_error: Option<String>,
}

impl SetupRouteState {
    pub(crate) fn open(&mut self) {
        self.focus = PickerFocus::List;
        self.editor = None;
        self.budget_draft.clear();
        self.budget_error = None;
        self.cursor = self.cursor.min(SetupRowId::ALL.len().saturating_sub(1));
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn focus(&self) -> PickerFocus {
        self.focus
    }

    pub(crate) fn set_focus(&mut self, focus: PickerFocus) {
        self.focus = focus;
    }

    pub(crate) fn row(&self) -> SetupRowId {
        SetupRowId::ALL[self.cursor.min(SetupRowId::ALL.len() - 1)]
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor.min(SetupRowId::ALL.len().saturating_sub(1));
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        self.cursor = wrapped_cursor(self.cursor, delta, SetupRowId::ALL.len());
        self.budget_error = None;
    }

    pub(crate) fn begin_editor(&mut self, editor: SetupEditor) {
        self.editor = Some(editor);
        self.budget_error = None;
    }

    pub(crate) fn finish_editor(&mut self) {
        self.editor = None;
    }

    pub(crate) fn editor(&self) -> Option<SetupEditor> {
        self.editor
    }

    pub(crate) fn begin_budget_edit(&mut self, current: Option<f64>) {
        self.begin_editor(SetupEditor::Budget);
        self.budget_draft = current
            .map(|value| format!("{value:.2}"))
            .unwrap_or_default();
    }

    pub(crate) fn budget_draft(&self) -> &str {
        &self.budget_draft
    }

    pub(crate) fn push_budget_char(&mut self, ch: char) {
        self.budget_draft.push(ch);
        self.budget_error = None;
    }

    pub(crate) fn pop_budget_char(&mut self) {
        self.budget_draft.pop();
        self.budget_error = None;
    }

    pub(crate) fn clear_budget_draft(&mut self) {
        self.budget_draft.clear();
        self.budget_error = None;
    }

    pub(crate) fn budget_error(&self) -> Option<&str> {
        self.budget_error.as_deref()
    }

    pub(crate) fn set_budget_error(&mut self, error: impl Into<String>) {
        self.budget_error = Some(error.into());
    }
}

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
    recovery: bool,
}

impl AuthPickerRouteState {
    pub(crate) fn open(&mut self, provider: String) {
        self.cursor = 0;
        self.focus = PickerFocus::List;
        self.rows = auth_method_row_kinds(&provider);
        self.recovery = false;
        self.provider = provider;
        self.key_draft.clear();
    }

    pub(crate) fn open_recovery(&mut self, provider: String) {
        self.cursor = 0;
        self.focus = PickerFocus::List;
        self.rows = credential_recovery_row_kinds(&provider);
        self.recovery = true;
        self.provider = provider;
        self.key_draft.clear();
    }

    pub(crate) fn is_recovery(&self) -> bool {
        self.recovery
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

    pub(crate) fn delete_key_word_left(&mut self) {
        while self
            .key_draft
            .chars()
            .next_back()
            .is_some_and(|ch| !crate::app::is_word_char(ch))
        {
            self.key_draft.pop();
        }
        while self
            .key_draft
            .chars()
            .next_back()
            .is_some_and(crate::app::is_word_char)
        {
            self.key_draft.pop();
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingTargetIntent {
    Phase(WorkflowPhase),
    Full,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetPickerRouteState {
    cursor: usize,
    focus: PickerFocus,
    candidates: Vec<crate::app::TargetCandidate>,
    facts: Option<crate::app::TargetCandidateFacts>,
    facts_loading: bool,
    pending_intent: Option<PendingTargetIntent>,
}

impl TargetPickerRouteState {
    pub(crate) fn open(&mut self, candidates: Vec<crate::app::TargetCandidate>) {
        self.candidates = candidates;
        self.cursor = 0;
        self.focus = PickerFocus::List;
        self.facts = None;
        self.facts_loading = true;
        self.pending_intent = None;
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
        if self.facts.as_ref().map(|facts| &facts.path)
            != self.selected().map(|candidate| &candidate.path)
        {
            self.facts = None;
            self.facts_loading = true;
        }
    }

    #[cfg(test)]
    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor.min(self.candidates.len().saturating_sub(1));
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        self.cursor = wrapped_cursor(self.cursor, delta, self.candidates.len());
        self.facts = None;
        self.facts_loading = true;
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

    pub(crate) fn facts(&self) -> Option<&crate::app::TargetCandidateFacts> {
        self.facts.as_ref()
    }

    pub(crate) fn facts_loading(&self) -> bool {
        self.facts_loading
    }

    pub(crate) fn apply_facts(&mut self, facts: crate::app::TargetCandidateFacts) {
        if self
            .selected()
            .is_some_and(|candidate| candidate.path == facts.path)
        {
            self.facts = Some(facts);
            self.facts_loading = false;
        }
    }

    pub(crate) fn set_pending_intent(&mut self, intent: PendingTargetIntent) {
        self.pending_intent = Some(intent);
    }

    pub(crate) fn take_pending_intent(&mut self) -> Option<PendingTargetIntent> {
        self.pending_intent.take()
    }

    pub(crate) fn clear_pending_intent(&mut self) {
        self.pending_intent = None;
    }

    #[cfg(test)]
    pub(crate) fn pending_intent(&self) -> Option<PendingTargetIntent> {
        self.pending_intent
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanningPickerRouteState {
    phase: Option<WorkflowPhase>,
    cursor: usize,
    selected: BTreeSet<PlanningTaskId>,
    default_selected: BTreeSet<PlanningTaskId>,
    draft_selected: BTreeMap<WorkflowPhase, BTreeSet<PlanningTaskId>>,
    draft_defaults: BTreeMap<WorkflowPhase, BTreeSet<PlanningTaskId>>,
    draft_rebuild: BTreeMap<WorkflowPhase, BTreeSet<PlanningTaskId>>,
    tasks: Vec<PlanningTaskRow>,
    rebuild: BTreeSet<PlanningTaskId>,
    profile_pending: bool,
    focus: PickerFocus,
    option_cursor: usize,
    option_edit: Option<PlanningOptionEdit>,
    option_error: Option<String>,
    return_to_setup: bool,
    /// Workbench page the operator was on when the picker opened. Closing
    /// the picker restores it instead of re-deriving a page from refreshed
    /// reality (which could teleport, e.g. Map → Prove after Esc).
    origin_workbench_page: Option<crate::app::WorkbenchPage>,
    /// The shell view the operator came from, captured for EVERY entry path
    /// (Tab detours, result cards, contextual decks — not just Workbench).
    /// Esc restores it instead of teleporting to a re-derived phase page.
    origin_shell_view: Option<crate::app::ShellView>,
    /// Tools completed since the rows were built: the checklist snapshot no
    /// longer matches on-disk reality and must refresh before it is shown.
    artifacts_stale: bool,
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
        self.return_to_setup = false;
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
            .map(|draft| {
                let previous_defaults =
                    self.draft_defaults.get(&phase).cloned().unwrap_or_default();
                refreshed_profile_selection(draft, &previous_defaults, &defaults, &tasks)
            })
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
        self.selected.extend(self.rebuild.iter().copied());
        self.reconcile_selection_with_reality();
        self.profile_pending = profile_pending;
        self.reset_open_state();
    }

    fn save_phase_draft(&mut self) {
        let Some(phase) = self.phase else {
            return;
        };
        self.draft_selected.insert(phase, self.selected.clone());
        self.draft_defaults
            .insert(phase, self.default_selected.clone());
        self.draft_rebuild.insert(phase, self.rebuild.clone());
    }

    /// `next fresh`: drop remembered per-phase draft selections so the
    /// reopened planner shows honest defaults instead of a stale pass.
    pub(crate) fn reset_phase_drafts(&mut self) {
        self.draft_selected.clear();
        self.draft_defaults.clear();
        self.draft_rebuild.clear();
    }

    fn reconcile_selection_with_reality(&mut self) {
        for row in &self.tasks {
            match selection_override_for_reality(row, self.rebuild.contains(&row.id)) {
                Some(true) => {
                    self.selected.insert(row.id);
                }
                Some(false) => {
                    self.selected.remove(&row.id);
                }
                None => {}
            }
        }
    }

    pub(crate) fn mark_default_cached_for_rebuild(&mut self) {
        let cached_defaults = self
            .tasks
            .iter()
            .filter(|row| self.default_selected.contains(&row.id))
            .filter(|row| matches!(row.artifact_state, PlanningArtifactState::Cached))
            .map(|row| row.id)
            .collect::<BTreeSet<_>>();
        self.rebuild.extend(cached_defaults.iter().copied());
        self.selected.extend(cached_defaults);
    }

    /// A tool finished since the rows were built; the next time the picker
    /// is shown it must re-derive artifact reality first.
    pub(crate) fn mark_artifacts_stale(&mut self) {
        if !self.tasks.is_empty() {
            self.artifacts_stale = true;
        }
    }

    pub(crate) fn artifacts_stale(&self) -> bool {
        self.artifacts_stale
    }

    /// Re-derive every row's on-disk artifact reality and drop now-cached
    /// artifact tasks from the live and drafted selections. Called whenever
    /// the picker becomes visible again after tools ran: the checklist must
    /// show reality, never the snapshot from when it first opened.
    pub(crate) fn refresh_artifact_states(&mut self, target: &std::path::Path) {
        self.artifacts_stale = false;
        if self.tasks.is_empty() {
            return;
        }
        self.tasks = self
            .tasks
            .iter()
            .map(|row| PlanningTaskRow::for_task(row.id, target))
            .collect();
        let now_cached: BTreeSet<PlanningTaskId> = self
            .tasks
            .iter()
            .filter(|row| matches!(row.artifact_state, PlanningArtifactState::Cached))
            .filter(|row| !self.rebuild.contains(&row.id))
            .map(|row| row.id)
            .collect();
        self.selected.retain(|task| !now_cached.contains(task));
        for draft in self.draft_selected.values_mut() {
            draft.retain(|task| !now_cached.contains(task));
        }
        self.reconcile_selection_with_reality();
    }

    fn reset_open_state(&mut self) {
        self.cursor = first_selected_planning_row(&self.tasks, &self.selected);
        self.focus = PickerFocus::List;
        self.option_cursor = 0;
        self.option_edit = None;
        self.option_error = None;
    }

    pub(crate) fn set_return_to_setup(&mut self, value: bool) {
        self.return_to_setup = value;
    }

    pub(crate) fn returns_to_setup(&self) -> bool {
        self.return_to_setup
    }

    pub(crate) fn set_origin_workbench_page(&mut self, page: Option<crate::app::WorkbenchPage>) {
        self.origin_workbench_page = page;
    }

    pub(crate) fn set_origin_shell_view(&mut self, view: Option<crate::app::ShellView>) {
        self.origin_shell_view = view;
    }

    pub(crate) fn take_origin_shell_view(&mut self) -> Option<crate::app::ShellView> {
        self.origin_shell_view.take()
    }

    pub(crate) fn take_origin_workbench_page(&mut self) -> Option<crate::app::WorkbenchPage> {
        self.origin_workbench_page.take()
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
        self.selected.extend(self.rebuild.iter().copied());
        self.tasks = tasks;
        self.reconcile_selection_with_reality();
        self.cursor = refreshed_profile_cursor(focused, &self.tasks, &self.selected);
        self.profile_pending = false;
        self.option_cursor = 0;
        self.option_edit = None;
        self.option_error = None;
    }

    pub(crate) fn profile_pending(&self) -> bool {
        self.profile_pending
    }

    /// The phase the displayed rows were built for, and the phase whose steps
    /// Enter runs. It is not always the engagement's current phase: finishing a
    /// phase from Run Focus advances the engagement without rebuilding these
    /// rows, so anything that names or filters what is on screen must read this
    /// rather than the ledger-derived phase.
    pub(crate) fn phase(&self) -> Option<WorkflowPhase> {
        self.phase
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

    /// The phase's freshly-derived recommendation, before operator edits.
    /// Empty means the planner has nothing left to propose for this target.
    pub(crate) fn default_selected(&self) -> &BTreeSet<PlanningTaskId> {
        &self.default_selected
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

    pub(crate) fn mark_rebuild(&mut self, task: PlanningTaskId) {
        if self.tasks.iter().any(|row| row.id == task) {
            self.rebuild.insert(task);
            self.selected.insert(task);
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

    pub(crate) fn set_cursor_to_task(&mut self, task: PlanningTaskId) -> bool {
        let Some(cursor) = self.tasks.iter().position(|row| row.id == task) else {
            return false;
        };
        self.cursor = cursor;
        self.option_cursor = 0;
        self.option_error = None;
        true
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

fn selection_override_for_reality(row: &PlanningTaskRow, rebuilding: bool) -> Option<bool> {
    if matches!(row.artifact_state, PlanningArtifactState::Cached) && !rebuilding {
        return Some(false);
    }
    match row.last_attempt {
        Some(crate::app::LastAttempt::Completed)
            if matches!(row.artifact_state, PlanningArtifactState::Action) =>
        {
            Some(false)
        }
        Some(crate::app::LastAttempt::Failed { .. }) => Some(true),
        _ => None,
    }
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
            WorkflowPhase::Scan,
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

    #[test]
    fn reopened_draft_inverts_completed_and_failed_current_actions() {
        let mut route = PlanningPickerRouteState::default();
        let tasks = [PlanningTaskId::ScanAgenticSast, PlanningTaskId::ScanSecrets];
        route.open_phase_profiled(
            WorkflowPhase::Scan,
            rows_for(&tasks),
            tasks.into_iter().collect(),
            false,
        );
        let mut refreshed = rows_for(&tasks);
        refreshed[0].artifact_state = PlanningArtifactState::Action;
        refreshed[1].artifact_state = PlanningArtifactState::Action;
        refreshed[0].last_attempt = Some(crate::app::LastAttempt::Completed);
        refreshed[1].last_attempt = Some(crate::app::LastAttempt::Failed {
            resumable: false,
            resume_from: None,
        });

        route.open_phase_profiled(WorkflowPhase::Scan, refreshed, BTreeSet::new(), false);

        assert_eq!(
            route.selected(),
            &BTreeSet::from([PlanningTaskId::ScanSecrets])
        );
    }

    #[test]
    fn reopened_draft_deselects_an_externally_created_artifact() {
        let mut route = PlanningPickerRouteState::default();
        route.open_phase_profiled(
            WorkflowPhase::Map,
            rows_for(&[PlanningTaskId::DecomposeModules]),
            BTreeSet::from([PlanningTaskId::DecomposeModules]),
            false,
        );
        let mut cached = rows_for(&[PlanningTaskId::DecomposeModules]);
        cached[0].artifact_state = PlanningArtifactState::Cached;

        route.open_phase_profiled(WorkflowPhase::Map, cached, BTreeSet::new(), false);

        assert!(route.selected().is_empty());
        assert_eq!(
            route.tasks()[0].artifact_state,
            PlanningArtifactState::Cached
        );
    }

    #[test]
    fn profile_refresh_keeps_a_fresh_cached_rebuild_selected() {
        let task = PlanningTaskId::GatherRepoContext;
        let mut cached = rows_for(&[task]);
        cached[0].artifact_state = PlanningArtifactState::Cached;
        let mut route = PlanningPickerRouteState::default();
        route.open_phase_profiled(
            WorkflowPhase::Map,
            cached.clone(),
            BTreeSet::from([task]),
            true,
        );
        route.mark_default_cached_for_rebuild();

        route.refresh_profiled(cached, BTreeSet::new());

        assert_eq!(route.selected(), &BTreeSet::from([task]));
        assert_eq!(route.rebuild(), &BTreeSet::from([task]));
    }

    #[test]
    fn mutation_survivor_artifact_refresh_clears_the_stale_marker() {
        let target = tempfile::tempdir().expect("temp target");
        let task = PlanningTaskId::GatherRepoContext;
        let mut route = PlanningPickerRouteState::default();
        route.open(rows_for(&[task]), BTreeSet::from([task]));
        route.mark_artifacts_stale();
        assert!(route.artifacts_stale());

        route.refresh_artifact_states(target.path());

        assert!(!route.artifacts_stale());
    }

    #[test]
    fn mutation_survivor_completed_attempt_only_deselects_action_rows() {
        let mut row = test_row(PlanningTaskId::ScanAgenticSast);
        row.last_attempt = Some(crate::app::LastAttempt::Completed);

        assert_eq!(selection_override_for_reality(&row, false), None);
        row.artifact_state = PlanningArtifactState::Action;
        assert_eq!(selection_override_for_reality(&row, false), Some(false));
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
            cached_detail: None,
            last_attempt: None,
        }
    }
}
