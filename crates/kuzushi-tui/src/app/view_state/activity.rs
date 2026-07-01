use kuzushi_core::modules::{BuiltinModule, DagNodeDescriptor, ModuleRegistry};
use kuzushi_core::RunTraceStep;
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

/// Maximum number of trace events kept in memory for the Activity view's
/// right pane. Older events are dropped from `events` but their contribution
/// to per-task aggregates (`steps_done`, `last_label`, `cost_usd`) survives.
pub const ACTIVITY_FEED_RING_CAPACITY: usize = 2000;
const ACTIVITY_TASK_DETAIL_CAPACITY: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneFocus {
    Left,
    Right,
}

impl PaneFocus {
    pub fn toggle(self) -> Self {
        match self {
            PaneFocus::Left => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Left,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityDeckPage {
    Feed,
    Findings,
    AttackSurface,
    Dfd,
    Heatmap,
    AttackPath,
    ExploitChain,
}

impl ActivityDeckPage {
    pub const ALL: [Self; 6] = [
        Self::Findings,
        Self::AttackSurface,
        Self::Dfd,
        Self::Heatmap,
        Self::AttackPath,
        Self::ExploitChain,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Feed => "feed",
            Self::Findings => "findings",
            Self::AttackSurface => "surface",
            Self::Dfd => "dfd",
            Self::Heatmap => "heatmap",
            Self::AttackPath => "path",
            Self::ExploitChain => "chain",
        }
    }

    pub fn scene_page(self) -> Option<crate::scene3d::VizPage> {
        match self {
            Self::Feed | Self::Findings => None,
            Self::AttackSurface => Some(crate::scene3d::VizPage::AttackSurface),
            Self::Dfd => Some(crate::scene3d::VizPage::Dfd),
            Self::Heatmap => Some(crate::scene3d::VizPage::Heatmap),
            Self::AttackPath => Some(crate::scene3d::VizPage::AttackPath),
            Self::ExploitChain => Some(crate::scene3d::VizPage::ExploitChain),
        }
    }

    pub fn from_scene_page(page: crate::scene3d::VizPage) -> Self {
        match page {
            crate::scene3d::VizPage::AttackSurface => Self::AttackSurface,
            crate::scene3d::VizPage::Dfd => Self::Dfd,
            crate::scene3d::VizPage::Heatmap => Self::Heatmap,
            crate::scene3d::VizPage::AttackPath => Self::AttackPath,
            crate::scene3d::VizPage::ExploitChain => Self::ExploitChain,
        }
    }

    pub fn next(self) -> Self {
        let index = Self::ALL.iter().position(|page| *page == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let index = Self::ALL.iter().position(|page| *page == self).unwrap_or(0);
        Self::ALL[(index + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Symbolic state of a DAG task in the Activity view's left pane. Mirrors the
/// shared `ProgressKind` semantics used elsewhere in the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagTaskState {
    Queued,
    Active,
    Done,
    Failing,
    Canceled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagTaskDetailState {
    Active,
    Done,
    Failing,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagTaskDetail {
    pub label: String,
    pub kind: String,
    pub state: DagTaskDetailState,
    pub meta: String,
}

#[derive(Debug, Clone)]
pub struct DagTaskRow {
    pub task_id: String,
    pub module_id: String,
    pub depends_on: Vec<String>,
    pub state: DagTaskState,
    pub started_at: Option<Instant>,
    pub completed_at: Option<Instant>,
    pub steps_done: usize,
    pub cost_usd: f64,
    pub last_label: String,
    pub severity: Option<String>,
    pub details: Vec<DagTaskDetail>,
}

impl DagTaskRow {
    pub fn queued(task_id: String, module_id: String, depends_on: Vec<String>) -> Self {
        Self {
            task_id,
            module_id,
            depends_on,
            state: DagTaskState::Queued,
            started_at: None,
            completed_at: None,
            steps_done: 0,
            cost_usd: 0.0,
            last_label: String::new(),
            severity: None,
            details: Vec::new(),
        }
    }
}

/// One trace event recorded in the Activity feed buffer. We keep the original
/// `RunTraceStep` plus the wall-clock instant we observed it (used for the
/// `HH:MM:SS` prefix in the right pane).
#[derive(Debug, Clone)]
pub struct RecordedTraceEvent {
    pub step: RunTraceStep,
    pub observed_at: Instant,
}

/// Aggregate row for hidden DAG nodes (`pipeline:*`, `systems-hunt:*`,
/// `context-lite:index`). Collapsed into one line in the left pane unless
/// `verbose_subsystems` is toggled.
#[derive(Debug, Clone)]
pub struct SubsystemAggregate {
    pub active_count: usize,
    pub total_count: usize,
    pub last_label: String,
    pub state: DagTaskState,
    pub(crate) hidden_task_states: BTreeMap<String, DagTaskState>,
}

impl Default for SubsystemAggregate {
    fn default() -> Self {
        Self {
            active_count: 0,
            total_count: 0,
            last_label: String::new(),
            state: DagTaskState::Queued,
            hidden_task_states: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
impl SubsystemAggregate {
    pub(crate) fn test_seeded(
        total_count: usize,
        last_label: impl Into<String>,
        state: DagTaskState,
    ) -> Self {
        Self {
            total_count,
            last_label: last_label.into(),
            state,
            ..Self::default()
        }
    }
}

/// Live state for the Activity view. Created at scan/run start, mutated by
/// the trace-event drain pump on every tick, rendered by the activity view.
#[derive(Debug, Clone)]
pub struct ActivitySession {
    pub run_id: String,
    pub started_at: Instant,
    pub tasks: BTreeMap<String, DagTaskRow>,
    pub step_task_ids: BTreeMap<usize, String>,
    pub subsystem_aggregate: SubsystemAggregate,
    pub events: VecDeque<RecordedTraceEvent>,
    pub focus_task: Option<String>,
    pub pane_focus: PaneFocus,
    pub verbose_subsystems: bool,
    pub paused: bool,
    pub feed_scroll: usize,
    pub task_scroll: usize,
    pub deck_page: ActivityDeckPage,
    pub deck_cursor: usize,
    /// True while the feed renderer should auto-scroll to the latest event.
    /// Becomes false the moment the operator manually scrolls the feed; reset
    /// to true on `G` (scroll-to-bottom). Decoupled from `paused` so toggling
    /// pause doesn't unpin a manually-scrolled position.
    pub feed_auto_tail: bool,
}

struct VisibleStepTask {
    task_id: String,
    rolled_up_child: bool,
}

impl ActivitySession {
    pub fn new(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            started_at: Instant::now(),
            tasks: BTreeMap::new(),
            step_task_ids: BTreeMap::new(),
            subsystem_aggregate: SubsystemAggregate::default(),
            events: VecDeque::with_capacity(ACTIVITY_FEED_RING_CAPACITY),
            focus_task: None,
            pane_focus: PaneFocus::Left,
            verbose_subsystems: false,
            paused: false,
            feed_scroll: 0,
            task_scroll: 0,
            deck_page: ActivityDeckPage::Findings,
            deck_cursor: 0,
            feed_auto_tail: false,
        }
    }

    /// Apply one trace step, updating the matching DAG row (or the subsystem
    /// aggregate for hidden modules) and pushing the event onto the ring
    /// buffer. Hidden modules are routed via `is_hidden_module_id`.
    ///
    /// Row mutation rules:
    /// - `kind == "tool"` and `kind == "done"` (or `"tool-complete"`) update
    ///   the matching DAG row and may mint a new row if the seeded topology
    ///   doesn't already contain it (rare: only happens when a producer
    ///   emits a tool boundary outside the registry).
    /// - All other kinds (`reasoning`, `tool-progress`, `tool-start`,
    ///   `refused` without module_id, etc.) are sub-step events that flow
    ///   into the right-pane feed but never create a new DAG row. This
    ///   keeps `TracedRuntime`'s per-LLM emissions from cluttering the
    ///   left pane with phantom `<module>:query` / `<module>:next-step`
    ///   rows that never finish.
    /// Force a tool's DAG row to `Done` on completion — minting it if the
    /// completion event is processed before the row's start step (a channel
    /// race), or transitioning it if it's still spinning. Idempotent for rows
    /// already terminal, and writes no feed event so normal tools that emitted
    /// their own done step don't get a duplicate line.
    pub fn mark_task_done(&mut self, tool_name: &str) {
        let task_id = collapse_doubled_tail(tool_name);
        let module_id = task_id.split(':').next().unwrap_or(&task_id).to_string();
        let row = self
            .tasks
            .entry(task_id.clone())
            .or_insert_with(|| DagTaskRow::queued(task_id, module_id, Vec::new()));
        if matches!(row.state, DagTaskState::Done | DagTaskState::Failing) {
            return;
        }
        row.state = DagTaskState::Done;
        if row.started_at.is_none() {
            row.started_at = Some(Instant::now());
        }
        row.completed_at = Some(Instant::now());
    }

    pub fn apply_step(&mut self, step: RunTraceStep) {
        let module_id = step.module_id.as_deref().unwrap_or("").to_string();
        if !module_id.is_empty() && is_hidden_module_id(&module_id) {
            self.apply_hidden_module_step(&step);
        } else if let Some(verb) = step.verb.as_deref() {
            self.apply_visible_module_step(&module_id, verb, &step);
        }

        let event = RecordedTraceEvent {
            step,
            observed_at: Instant::now(),
        };
        if self.events.len() >= ACTIVITY_FEED_RING_CAPACITY {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn apply_hidden_module_step(&mut self, step: &RunTraceStep) {
        let task_id = hidden_subsystem_task_id(step);
        let current = self
            .subsystem_aggregate
            .hidden_task_states
            .get(&task_id)
            .copied()
            .unwrap_or(DagTaskState::Queued);
        let next = next_activity_row_state(current, step, false);
        self.subsystem_aggregate
            .hidden_task_states
            .insert(task_id, next);
        self.subsystem_aggregate.last_label = step.label.clone();
        sync_subsystem_aggregate(&mut self.subsystem_aggregate);
    }

    fn apply_visible_module_step(&mut self, module_id: &str, verb: &str, step: &RunTraceStep) {
        let Some(target) = self.visible_step_task(module_id, verb, step) else {
            return;
        };
        if let Some(row) = self.activity_row_for_step(&target.task_id, module_id, step) {
            apply_activity_row_step(row, step, target.rolled_up_child);
            self.step_task_ids.insert(step.n, target.task_id);
        }
    }

    /// Map a step's `(module_id, verb)` to a DAG row id. Producers report the
    /// scan umbrella as `sast:scan` + verb `scan`, which naively composes to
    /// `sast:scan:scan` and mints a duplicate next to the seeded `sast:scan`
    /// node. Collapsing a doubled trailing segment fixes it regardless of how
    /// the tool name split across module_id/verb, and is order-independent.
    fn resolve_step_task_id(&self, module_id: &str, verb: &str) -> String {
        collapse_doubled_tail(&format!("{module_id}:{verb}"))
    }

    fn visible_step_task(
        &self,
        module_id: &str,
        verb: &str,
        step: &RunTraceStep,
    ) -> Option<VisibleStepTask> {
        let direct_task_id = self.resolve_step_task_id(module_id, verb);
        let parent_task_id = step
            .parent_step
            .and_then(|parent| self.step_task_ids.get(&parent).cloned());
        if !self.tasks.contains_key(&direct_task_id) {
            if let Some(task_id) = parent_task_id {
                return Some(VisibleStepTask {
                    task_id,
                    rolled_up_child: true,
                });
            }
        }
        (activity_step_mints_row(step) || self.tasks.contains_key(&direct_task_id)).then_some(
            VisibleStepTask {
                task_id: direct_task_id,
                rolled_up_child: false,
            },
        )
    }

    fn activity_row_for_step(
        &mut self,
        task_id: &str,
        module_id: &str,
        step: &RunTraceStep,
    ) -> Option<&mut DagTaskRow> {
        if activity_step_mints_row(step) {
            return Some(self.tasks.entry(task_id.to_string()).or_insert_with(|| {
                DagTaskRow::queued(task_id.to_string(), module_id.to_string(), Vec::new())
            }));
        }
        self.tasks.get_mut(task_id)
    }

    pub fn toggle_pane_focus(&mut self) {
        self.pane_focus = self.pane_focus.toggle();
    }

    pub fn next_deck_page(&mut self) {
        self.set_deck_page(self.deck_page.next());
    }

    pub fn prev_deck_page(&mut self) {
        self.set_deck_page(self.deck_page.prev());
    }

    pub fn set_deck_page(&mut self, page: ActivityDeckPage) {
        self.deck_page = page;
        self.deck_cursor = 0;
        self.feed_scroll = 0;
        self.feed_auto_tail = false;
    }

    pub fn set_deck_scene_page(&mut self, page: crate::scene3d::VizPage) {
        self.set_deck_page(ActivityDeckPage::from_scene_page(page));
    }

    /// Focus that accounts for the collapsed TASKS pane: with no DAG tasks
    /// the OUTPUT pane is the only one on screen, so scrolling and the
    /// header label act on it regardless of the stored toggle state.
    pub fn effective_pane_focus(&self) -> PaneFocus {
        if self.tasks.is_empty() {
            PaneFocus::Right
        } else {
            self.pane_focus
        }
    }

    /// Pre-populate `tasks` with `Queued` rows for every visible DAG node in
    /// the registry, plus seed `subsystem_aggregate.total_count` from hidden
    /// modules. Used at scan start so the DAG pane has rows from the first
    /// frame instead of "(no DAG tasks yet)" while we wait for the first
    /// trace event. Idempotent: existing rows aren't overwritten, so calling
    /// this after some events have already arrived preserves their state.
    pub fn seed_from_registry(&mut self, registry: &ModuleRegistry) {
        let hidden_total = registry
            .all_modules()
            .map(|module| self.seed_registry_module(module))
            .sum();
        self.seed_hidden_subsystem_total(hidden_total);
    }

    pub fn toggle_verbose_subsystems(&mut self) {
        self.verbose_subsystems = !self.verbose_subsystems;
    }

    pub fn toggle_paused(&mut self) {
        self.paused = !self.paused;
    }

    pub fn mark_active_tasks_canceled(&mut self) {
        let now = Instant::now();
        for row in self.tasks.values_mut().filter(|row| row_can_cancel(row)) {
            mark_activity_row_canceled(row, now);
        }
        mark_subsystems_canceled(&mut self.subsystem_aggregate);
    }

    fn seed_registry_module(&mut self, module: &BuiltinModule) -> usize {
        if module.is_hidden() {
            return module.dag_nodes().len();
        }
        for node in module.dag_nodes() {
            self.seed_visible_dag_node(node);
        }
        0
    }

    fn seed_visible_dag_node(&mut self, node: &DagNodeDescriptor) {
        let task_id = node.id.clone();
        let module_id = module_id_for_task_id(&task_id);
        self.tasks
            .entry(task_id.clone())
            .or_insert_with(|| DagTaskRow::queued(task_id, module_id, node.depends_on.clone()));
    }

    fn seed_hidden_subsystem_total(&mut self, hidden_total: usize) {
        if !subsystem_aggregate_is_fresh(&self.subsystem_aggregate) {
            return;
        }
        self.subsystem_aggregate.total_count = hidden_total;
        sync_subsystem_aggregate(&mut self.subsystem_aggregate);
    }
}

fn module_id_for_task_id(task_id: &str) -> String {
    task_id
        .split_once(':')
        .map(|(prefix, _)| prefix)
        .unwrap_or(task_id)
        .to_string()
}

fn subsystem_aggregate_is_fresh(aggregate: &SubsystemAggregate) -> bool {
    aggregate.total_count == 0 && aggregate.active_count == 0
}

fn row_can_cancel(row: &&mut DagTaskRow) -> bool {
    cancelable_task_state(row.state)
}

fn cancelable_task_state(state: DagTaskState) -> bool {
    matches!(state, DagTaskState::Queued | DagTaskState::Active)
}

fn mark_activity_row_canceled(row: &mut DagTaskRow, now: Instant) {
    row.state = DagTaskState::Canceled;
    row.started_at.get_or_insert(now);
    row.completed_at = Some(now);
    row.last_label = "cancel requested; waiting for cleanup".to_string();
    mark_active_details_canceled(row);
}

fn mark_active_details_canceled(row: &mut DagTaskRow) {
    for detail in row
        .details
        .iter_mut()
        .filter(|detail| detail.state == DagTaskDetailState::Active)
    {
        detail.state = DagTaskDetailState::Canceled;
    }
}

/// Drop a trailing colon-segment that duplicates the one before it, so a
/// doubled tool name (`sast:scan:scan`) collapses to `sast:scan`. Leaves normal
/// `module:verb` ids untouched.
pub(crate) fn collapse_doubled_tail(task_id: &str) -> String {
    let segments: Vec<&str> = task_id.split(':').collect();
    let len = segments.len();
    if len >= 2 && segments[len - 1] == segments[len - 2] {
        return segments[..len - 1].join(":");
    }
    task_id.to_string()
}

fn activity_step_mints_row(step: &RunTraceStep) -> bool {
    matches!(
        step.kind.as_str(),
        "tool" | "done" | "tool-complete" | "refused"
    )
}

fn apply_activity_row_step(row: &mut DagTaskRow, step: &RunTraceStep, rolled_up_child: bool) {
    row.steps_done = row.steps_done.saturating_add(1);
    row.last_label = step.label.clone();
    if let Some(cost) = step.cost_usd {
        row.cost_usd += cost;
    }
    row.severity = step.severity.clone();
    record_activity_row_details(row, step);
    row.state = next_activity_row_state(row.state, step, rolled_up_child);
    finalize_activity_row_details(row);
    mark_activity_row_times(row);
}

fn record_activity_row_details(row: &mut DagTaskRow, step: &RunTraceStep) {
    let labels = activity_detail_labels(step);
    if labels.is_empty() {
        return;
    }
    complete_active_details(row);
    for label in labels {
        push_activity_row_detail(row, label, step);
    }
    trim_activity_row_details(row);
}

fn activity_detail_labels(step: &RunTraceStep) -> Vec<String> {
    let label = step.label.trim();
    if label.is_empty() {
        return Vec::new();
    }
    if let Some(action) = agent_action_detail_label(label) {
        return vec![action];
    }
    if let Some(model) = model_detail_label(label) {
        return vec![model];
    }
    split_phase_outline(label).unwrap_or_else(|| vec![label.to_string()])
}

fn split_phase_outline(label: &str) -> Option<Vec<String>> {
    if label.starts_with("final ·") || label.contains(" chars in") {
        return None;
    }
    let parts = label
        .split(" · ")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2 || !parts.iter().all(|part| looks_like_phase_fragment(part)) {
        return None;
    }
    Some(parts.into_iter().map(str::to_string).collect())
}

fn agent_action_detail_label(label: &str) -> Option<String> {
    if let Some(action) = label.strip_prefix("agent-action: ") {
        return Some(format!("tool {}", strip_turn_suffix(action)));
    }
    let call = label.strip_prefix("tool-call · ")?;
    Some(format!(
        "tool {}",
        compact_legacy_tool_call(strip_turn_suffix(call))
    ))
}

fn model_detail_label(label: &str) -> Option<String> {
    label
        .strip_prefix("query · ")
        .map(|body| format!("model {body}"))
        .or_else(|| {
            label
                .strip_prefix("final · ")
                .map(|body| format!("final {body}"))
        })
}

fn strip_turn_suffix(value: &str) -> &str {
    value
        .split(" · turn ")
        .next()
        .and_then(|part| part.split(" (turn ").next())
        .unwrap_or(value)
        .trim()
}

fn compact_legacy_tool_call(call: &str) -> String {
    let Some((name, raw_args)) = call.split_once('(') else {
        return call.trim().to_string();
    };
    let Some(raw_args) = raw_args.strip_suffix(')') else {
        return call.trim().to_string();
    };
    let args = serde_json::from_str(raw_args)
        .ok()
        .and_then(|value| legacy_tool_input_summary(&value));
    match args {
        Some(args) if !args.is_empty() => format!("{} {args}", name.trim()),
        _ => name.trim().to_string(),
    }
}

fn legacy_tool_input_summary(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Object(object) => legacy_object_tool_input_summary(object),
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Array(items) => Some(format!("{} item(s)", items.len())),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Null => None,
    }
}

fn legacy_object_tool_input_summary(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    const KEYS: &[&str] = &[
        "path",
        "file",
        "filePath",
        "file_path",
        "target",
        "query",
        "pattern",
        "symbol",
        "name",
        "command",
        "cmd",
    ];
    KEYS.iter()
        .find_map(|key| object.get(*key).and_then(legacy_tool_input_summary))
        .or_else(|| legacy_fallback_tool_input_summary(object))
}

fn legacy_fallback_tool_input_summary(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let parts = object
        .iter()
        .filter_map(|(key, value)| {
            legacy_tool_input_summary(value).map(|value| format!("{key}={value}"))
        })
        .take(2)
        .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn looks_like_phase_fragment(part: &str) -> bool {
    part.chars().count() <= 36
        && part
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '/' | ' '))
}

fn complete_active_details(row: &mut DagTaskRow) {
    for detail in &mut row.details {
        if detail.state == DagTaskDetailState::Active {
            detail.state = DagTaskDetailState::Done;
        }
    }
}

fn push_activity_row_detail(row: &mut DagTaskRow, label: String, step: &RunTraceStep) {
    let detail = DagTaskDetail {
        label,
        kind: step.kind.clone(),
        state: activity_detail_state(step),
        meta: activity_detail_meta(step),
    };
    if let Some(existing) = row
        .details
        .last_mut()
        .filter(|existing| existing.label == detail.label && existing.kind == detail.kind)
    {
        existing.state = detail.state;
        return;
    }
    row.details.push(detail);
}

fn activity_detail_state(step: &RunTraceStep) -> DagTaskDetailState {
    match (step.severity.as_deref(), step.kind.as_str()) {
        (Some("danger"), _) | (_, "refused") => DagTaskDetailState::Failing,
        (_, "done" | "tool-complete") => DagTaskDetailState::Done,
        _ => DagTaskDetailState::Active,
    }
}

fn activity_detail_meta(step: &RunTraceStep) -> String {
    let mut parts = Vec::new();
    if let Some(latency) = step.latency_ms {
        parts.push(format_latency(latency));
    }
    if let Some(cost) = step.cost_usd.filter(|cost| *cost > 0.0) {
        parts.push(format!("${cost:.4}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(" · "))
    }
}

fn format_latency(ms: u64) -> String {
    if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
    }
}

fn trim_activity_row_details(row: &mut DagTaskRow) {
    let excess = row
        .details
        .len()
        .saturating_sub(ACTIVITY_TASK_DETAIL_CAPACITY);
    if excess > 0 {
        row.details.drain(0..excess);
    }
}

fn finalize_activity_row_details(row: &mut DagTaskRow) {
    if !activity_row_is_terminal(row) {
        return;
    }
    let terminal_state = match row.state {
        DagTaskState::Failing => DagTaskDetailState::Failing,
        DagTaskState::Canceled => DagTaskDetailState::Canceled,
        _ => DagTaskDetailState::Done,
    };
    for detail in &mut row.details {
        if detail.state == DagTaskDetailState::Active {
            detail.state = terminal_state;
        }
    }
}

fn next_activity_row_state(
    current: DagTaskState,
    step: &RunTraceStep,
    rolled_up_child: bool,
) -> DagTaskState {
    match (step.severity.as_deref(), step.kind.as_str(), current) {
        (Some("danger"), _, _) => DagTaskState::Failing,
        (_, "done" | "tool-complete", _) if !rolled_up_child => DagTaskState::Done,
        (_, _, DagTaskState::Queued) => DagTaskState::Active,
        (_, _, DagTaskState::Canceled) => DagTaskState::Canceled,
        (_, _, state) => state,
    }
}

fn mark_activity_row_times(row: &mut DagTaskRow) {
    if row.started_at.is_none() {
        row.started_at = Some(Instant::now());
    }
    if activity_row_is_terminal(row) && row.completed_at.is_none() {
        row.completed_at = Some(Instant::now());
    }
}

fn activity_row_is_terminal(row: &DagTaskRow) -> bool {
    matches!(
        row.state,
        DagTaskState::Done | DagTaskState::Failing | DagTaskState::Canceled
    )
}

/// True for module ids that should never claim a row in the left pane and
/// whose feed events are suppressed unless `verbose_subsystems` is on.
pub fn is_hidden_module_id(module_id: &str) -> bool {
    matches!(module_id, "pipeline" | "systems-hunt" | "context-lite")
}

fn hidden_subsystem_task_id(step: &RunTraceStep) -> String {
    let module_id = step.module_id.as_deref().unwrap_or("subsystem");
    match step.verb.as_deref().filter(|verb| !verb.trim().is_empty()) {
        Some(verb) => collapse_doubled_tail(&format!("{module_id}:{verb}")),
        None => module_id.to_string(),
    }
}

fn sync_subsystem_aggregate(aggregate: &mut SubsystemAggregate) {
    let seeded_total = aggregate.total_count;
    let observed_total = aggregate.hidden_task_states.len();
    aggregate.total_count = seeded_total.max(observed_total);
    aggregate.active_count = aggregate
        .hidden_task_states
        .values()
        .filter(|state| matches!(state, DagTaskState::Active))
        .count();
    aggregate.state = subsystem_state(
        aggregate.total_count,
        observed_total,
        aggregate.hidden_task_states.values().copied(),
    );
}

fn subsystem_state(
    total_count: usize,
    observed_total: usize,
    states: impl Iterator<Item = DagTaskState>,
) -> DagTaskState {
    let states = states.collect::<Vec<_>>();
    let priority = subsystem_priority_state(&states);
    if priority != DagTaskState::Queued {
        return priority;
    }
    if subsystem_all_done(total_count, observed_total, &states) {
        return DagTaskState::Done;
    }
    DagTaskState::Queued
}

fn subsystem_priority_state(states: &[DagTaskState]) -> DagTaskState {
    [
        DagTaskState::Failing,
        DagTaskState::Canceled,
        DagTaskState::Active,
    ]
    .into_iter()
    .find(|state| subsystem_has_state(states, *state))
    .unwrap_or(DagTaskState::Queued)
}

fn subsystem_has_state(states: &[DagTaskState], target: DagTaskState) -> bool {
    states.iter().any(|state| *state == target)
}

fn subsystem_all_done(total_count: usize, observed_total: usize, states: &[DagTaskState]) -> bool {
    observed_total > 0
        && observed_total >= total_count
        && states.iter().all(|state| *state == DagTaskState::Done)
}

fn mark_subsystems_canceled(aggregate: &mut SubsystemAggregate) {
    if !subsystems_have_tasks(aggregate) {
        return;
    }
    cancel_hidden_subsystem_tasks(aggregate);
    sync_or_mark_empty_subsystems_canceled(aggregate);
    aggregate.last_label = "cancel requested; waiting for cleanup".to_string();
}

fn subsystems_have_tasks(aggregate: &SubsystemAggregate) -> bool {
    aggregate.total_count > 0
}

fn cancel_hidden_subsystem_tasks(aggregate: &mut SubsystemAggregate) {
    for state in aggregate
        .hidden_task_states
        .values_mut()
        .filter(|state| cancelable_task_state(**state))
    {
        *state = DagTaskState::Canceled;
    }
}

fn sync_or_mark_empty_subsystems_canceled(aggregate: &mut SubsystemAggregate) {
    if aggregate.hidden_task_states.is_empty() {
        aggregate.state = DagTaskState::Canceled;
        aggregate.active_count = 0;
        return;
    }
    sync_subsystem_aggregate(aggregate);
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::RunTraceStep;

    #[test]
    fn apply_step_creates_row_and_marks_active() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "tool", "started")
                .with_module_id("semgrep")
                .with_verb("scan"),
        );
        let row = session.tasks.get("semgrep:scan").unwrap();
        assert_eq!(row.state, DagTaskState::Active);
        assert_eq!(row.steps_done, 1);
    }

    #[test]
    fn step_with_tool_name_as_module_id_updates_seeded_row() {
        let mut session = ActivitySession::new("r-1");
        // Seed a node keyed by its tool name (as `seed_from_registry` does).
        session.tasks.insert(
            "sast:scan".to_string(),
            DagTaskRow::queued("sast:scan".to_string(), "sast".to_string(), Vec::new()),
        );
        // Producer reports the full tool name as module_id + verb `scan`.
        session.apply_step(
            RunTraceStep::new(1, "tool", "sast:scan start")
                .with_module_id("sast:scan")
                .with_verb("scan"),
        );
        assert!(
            !session.tasks.contains_key("sast:scan:scan"),
            "must not mint a duplicate row"
        );
        assert_eq!(session.tasks["sast:scan"].state, DagTaskState::Active);
    }

    #[test]
    fn doubled_tool_name_step_collapses_without_a_seeded_row() {
        // Order-independent: even with no pre-seeded row, a `sast:scan` +
        // verb `scan` step targets `sast:scan`, never `sast:scan:scan`.
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "tool", "sast:scan start")
                .with_module_id("sast:scan")
                .with_verb("scan"),
        );
        assert!(session.tasks.contains_key("sast:scan"));
        assert!(!session.tasks.contains_key("sast:scan:scan"));
    }

    #[test]
    fn apply_step_done_kind_promotes_to_done_state() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "tool", "started")
                .with_module_id("semgrep")
                .with_verb("scan"),
        );
        session.apply_step(
            RunTraceStep::new(2, "done", "complete")
                .with_module_id("semgrep")
                .with_verb("scan"),
        );
        let row = session.tasks.get("semgrep:scan").unwrap();
        assert_eq!(row.state, DagTaskState::Done);
    }

    #[test]
    fn apply_step_danger_severity_marks_failing() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "tool", "rule load failed")
                .with_module_id("codeql")
                .with_verb("scan")
                .with_severity("danger"),
        );
        let row = session.tasks.get("codeql:scan").unwrap();
        assert_eq!(row.state, DagTaskState::Failing);
    }

    #[test]
    fn hidden_module_routes_into_subsystem_aggregate() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "tool", "task selected")
                .with_module_id("pipeline")
                .with_verb("task-selector"),
        );
        assert!(session.tasks.is_empty());
        assert_eq!(session.subsystem_aggregate.active_count, 1);
        assert_eq!(session.subsystem_aggregate.total_count, 1);
        assert_eq!(session.subsystem_aggregate.state, DagTaskState::Active);
        assert_eq!(session.subsystem_aggregate.last_label, "task selected");
    }

    #[test]
    fn hidden_module_error_marks_subsystem_aggregate_failing() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "refused", "context index failed")
                .with_module_id("context-lite")
                .with_verb("index")
                .with_severity("danger"),
        );

        assert_eq!(session.subsystem_aggregate.total_count, 1);
        assert_eq!(session.subsystem_aggregate.active_count, 0);
        assert_eq!(session.subsystem_aggregate.state, DagTaskState::Failing);
        assert_eq!(
            session.subsystem_aggregate.last_label,
            "context index failed"
        );
    }

    #[test]
    fn mark_active_tasks_canceled_stops_live_rows() {
        let mut session = ActivitySession::new("r-1");
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".to_string(), "triage".to_string(), Vec::new()),
        );
        session.apply_step(
            RunTraceStep::new(1, "tool", "triage start")
                .with_module_id("triage")
                .with_verb("run"),
        );

        session.mark_active_tasks_canceled();

        let row = session.tasks.get("triage:run").unwrap();
        assert_eq!(row.state, DagTaskState::Canceled);
        assert_eq!(row.last_label, "cancel requested; waiting for cleanup");
        assert!(row.completed_at.is_some());
    }

    #[test]
    fn deck_page_changes_reset_cursor_and_feed_scroll() {
        let mut session = ActivitySession::new("r-1");
        session.feed_scroll = 12;
        session.deck_cursor = 5;

        session.next_deck_page();

        assert_eq!(session.deck_page, ActivityDeckPage::AttackSurface);
        assert_eq!(session.deck_cursor, 0);
        assert_eq!(session.feed_scroll, 0);
        assert!(!session.feed_auto_tail);

        session.prev_deck_page();

        assert_eq!(session.deck_page, ActivityDeckPage::Findings);
        assert!(!session.feed_auto_tail);
    }

    #[test]
    fn ring_buffer_evicts_oldest_when_full() {
        let mut session = ActivitySession::new("r-1");
        for i in 0..(ACTIVITY_FEED_RING_CAPACITY + 5) {
            session.apply_step(
                RunTraceStep::new(i, "tool", format!("event {i}"))
                    .with_module_id("semgrep")
                    .with_verb("scan"),
            );
        }
        assert_eq!(session.events.len(), ACTIVITY_FEED_RING_CAPACITY);
        // Per-task aggregates survive eviction.
        let row = session.tasks.get("semgrep:scan").unwrap();
        assert_eq!(row.steps_done, ACTIVITY_FEED_RING_CAPACITY + 5);
    }

    #[test]
    fn child_trace_steps_roll_up_under_their_parent_task() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "tool", "agentic-sast start")
                .with_module_id("agentic-sast")
                .with_verb("scan"),
        );
        session.apply_step(
            RunTraceStep::new(
                2,
                "reasoning",
                "inventory-review · vulnerability-hunt · json-findings",
            )
            .with_module_id("agentic-sast")
            .with_verb("scan")
            .with_parent_step(1),
        );
        session.apply_step(
            RunTraceStep::new(3, "reasoning", "query · reviewed repo inventory")
                .with_module_id("agentic-sast")
                .with_verb("query")
                .with_parent_step(2)
                .with_latency_ms(Some(2_400))
                .with_cost_usd(Some(0.0123)),
        );

        assert!(!session.tasks.contains_key("agentic-sast:query"));
        let row = session.tasks.get("agentic-sast:scan").unwrap();
        assert_eq!(row.steps_done, 3);
        assert!(row
            .details
            .iter()
            .any(|detail| detail.label == "inventory-review"));
        assert!(row
            .details
            .iter()
            .any(|detail| detail.label == "model reviewed repo inventory"
                && detail.meta.contains("2.4s")
                && detail.meta.contains("$0.0123")));
    }

    #[test]
    fn rolled_up_child_done_step_does_not_finish_parent_task() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "tool", "agentic-sast start")
                .with_module_id("agentic-sast")
                .with_verb("scan"),
        );
        session.apply_step(
            RunTraceStep::new(2, "reasoning", "agent loop")
                .with_module_id("agentic-sast")
                .with_verb("scan")
                .with_parent_step(1),
        );
        session.apply_step(
            RunTraceStep::new(3, "done", "final answer")
                .with_module_id("agentic-sast")
                .with_verb("next-step")
                .with_parent_step(2),
        );

        let row = session.tasks.get("agentic-sast:scan").unwrap();
        assert_eq!(row.state, DagTaskState::Active);
        assert!(row.details.iter().any(|detail| {
            detail.label == "final answer" && detail.state == DagTaskDetailState::Done
        }));
    }

    #[test]
    fn agent_action_steps_render_as_tool_actions_under_parent_task() {
        let mut session = parented_task_session("uaf-hunt", "hunt", "uaf-hunt start");
        apply_child_step(
            &mut session,
            3,
            "agent-action: read_source src/lib.rs · turn 1",
        );
        apply_child_step(
            &mut session,
            4,
            "tool-call · grep({\"pattern\":\"unsafe\",\"path\":\"src\"}) (turn 2)",
        );

        let row = session.tasks.get("uaf-hunt:hunt").unwrap();
        assert!(row
            .details
            .iter()
            .any(|detail| detail.label == "tool read_source src/lib.rs"));
        assert!(row
            .details
            .iter()
            .any(|detail| detail.label == "tool grep src"));
    }

    fn parented_task_session(module_id: &str, verb: &str, start_label: &str) -> ActivitySession {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "tool", start_label)
                .with_module_id(module_id)
                .with_verb(verb),
        );
        session.apply_step(
            RunTraceStep::new(2, "reasoning", "agent loop")
                .with_module_id(module_id)
                .with_verb(verb)
                .with_parent_step(1),
        );
        session
    }

    fn apply_child_step(session: &mut ActivitySession, n: usize, label: &str) {
        session.apply_step(
            RunTraceStep::new(n, "tool-progress", label)
                .with_module_id("uaf-hunt")
                .with_verb("next-step")
                .with_parent_step(2),
        );
    }
}
