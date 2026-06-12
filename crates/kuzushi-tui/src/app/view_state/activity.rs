use kuzushi_core::{ModuleRegistry, RunTraceStep};
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

/// Maximum number of trace events kept in memory for the Activity view's
/// right pane. Older events are dropped from `events` but their contribution
/// to per-task aggregates (`steps_done`, `last_label`, `cost_usd`) survives.
pub const ACTIVITY_FEED_RING_CAPACITY: usize = 2000;

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

/// Symbolic state of a DAG task in the Activity view's left pane. Mirrors the
/// shared `ProgressKind` semantics used elsewhere in the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagTaskState {
    Queued,
    Active,
    Done,
    Failing,
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
/// `context-lite:index`). Collapsed into a single muted line in the left pane
/// unless `verbose_subsystems` is toggled.
#[derive(Debug, Default, Clone)]
pub struct SubsystemAggregate {
    pub active_count: usize,
    pub total_count: usize,
    pub last_label: String,
}

/// Live state for the Activity view. Created at scan/run start, mutated by
/// the trace-event drain pump on every tick, rendered by the activity view.
#[derive(Debug, Clone)]
pub struct ActivitySession {
    pub run_id: String,
    pub started_at: Instant,
    pub tasks: BTreeMap<String, DagTaskRow>,
    pub subsystem_aggregate: SubsystemAggregate,
    pub events: VecDeque<RecordedTraceEvent>,
    pub focus_task: Option<String>,
    pub pane_focus: PaneFocus,
    pub verbose_subsystems: bool,
    pub paused: bool,
    pub feed_scroll: usize,
    pub task_scroll: usize,
    /// True while the feed renderer should auto-scroll to the latest event.
    /// Becomes false the moment the operator manually scrolls the feed; reset
    /// to true on `G` (scroll-to-bottom). Decoupled from `paused` so toggling
    /// pause doesn't unpin a manually-scrolled position.
    pub feed_auto_tail: bool,
}

impl ActivitySession {
    pub fn new(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            started_at: Instant::now(),
            tasks: BTreeMap::new(),
            subsystem_aggregate: SubsystemAggregate::default(),
            events: VecDeque::with_capacity(ACTIVITY_FEED_RING_CAPACITY),
            focus_task: None,
            pane_focus: PaneFocus::Left,
            verbose_subsystems: false,
            paused: false,
            feed_scroll: 0,
            task_scroll: 0,
            feed_auto_tail: true,
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
        self.subsystem_aggregate.active_count =
            self.subsystem_aggregate.active_count.saturating_add(1);
        self.subsystem_aggregate.total_count =
            self.subsystem_aggregate.total_count.saturating_add(1);
        self.subsystem_aggregate.last_label = step.label.clone();
    }

    fn apply_visible_module_step(&mut self, module_id: &str, verb: &str, step: &RunTraceStep) {
        let task_id = self.resolve_step_task_id(module_id, verb);
        if let Some(row) = self.activity_row_for_step(&task_id, module_id, step) {
            apply_activity_row_step(row, step);
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
        let mut hidden_total = 0usize;
        for module in registry.all_modules() {
            let hidden = module.is_hidden();
            for node in module.dag_nodes() {
                if hidden {
                    hidden_total += 1;
                    continue;
                }
                let task_id = node.id.clone();
                let module_id = task_id
                    .split_once(':')
                    .map(|(prefix, _)| prefix)
                    .unwrap_or(task_id.as_str())
                    .to_string();
                self.tasks.entry(task_id.clone()).or_insert_with(|| {
                    DagTaskRow::queued(task_id, module_id, node.depends_on.clone())
                });
            }
        }
        // Don't clobber an aggregate that has already accumulated activity;
        // only seed the queued total when the aggregate is fresh.
        if self.subsystem_aggregate.total_count == 0 && self.subsystem_aggregate.active_count == 0 {
            self.subsystem_aggregate.total_count = hidden_total;
        }
    }

    pub fn toggle_verbose_subsystems(&mut self) {
        self.verbose_subsystems = !self.verbose_subsystems;
    }

    pub fn toggle_paused(&mut self) {
        self.paused = !self.paused;
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

fn apply_activity_row_step(row: &mut DagTaskRow, step: &RunTraceStep) {
    row.steps_done = row.steps_done.saturating_add(1);
    row.last_label = step.label.clone();
    if let Some(cost) = step.cost_usd {
        row.cost_usd += cost;
    }
    row.severity = step.severity.clone();
    row.state = next_activity_row_state(row.state, step);
    mark_activity_row_times(row);
}

fn next_activity_row_state(current: DagTaskState, step: &RunTraceStep) -> DagTaskState {
    match (step.severity.as_deref(), step.kind.as_str(), current) {
        (Some("danger"), _, _) => DagTaskState::Failing,
        (_, "done" | "tool-complete", _) => DagTaskState::Done,
        (_, _, DagTaskState::Queued) => DagTaskState::Active,
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
    matches!(row.state, DagTaskState::Done | DagTaskState::Failing)
}

/// True for module ids that should never claim a row in the left pane and
/// whose feed events are suppressed unless `verbose_subsystems` is on.
pub fn is_hidden_module_id(module_id: &str) -> bool {
    matches!(module_id, "pipeline" | "systems-hunt" | "context-lite")
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
        assert_eq!(session.subsystem_aggregate.last_label, "task selected");
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
}
