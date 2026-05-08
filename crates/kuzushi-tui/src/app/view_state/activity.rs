use kuzushi_core::RunTraceStep;
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
        }
    }

    /// Apply one trace step, updating the matching DAG row (or the subsystem
    /// aggregate for hidden modules) and pushing the event onto the ring
    /// buffer. Hidden modules are routed via `is_hidden_module_id`.
    pub fn apply_step(&mut self, step: RunTraceStep) {
        let module_id = step.module_id.as_deref().unwrap_or("").to_string();
        if !module_id.is_empty() && is_hidden_module_id(&module_id) {
            self.subsystem_aggregate.active_count = self
                .subsystem_aggregate
                .active_count
                .saturating_add(1);
            self.subsystem_aggregate.total_count = self
                .subsystem_aggregate
                .total_count
                .saturating_add(1);
            self.subsystem_aggregate.last_label = step.label.clone();
        } else if let Some(verb) = step.verb.as_deref() {
            let task_id = format!("{module_id}:{verb}");
            let row = self
                .tasks
                .entry(task_id.clone())
                .or_insert_with(|| DagTaskRow::queued(task_id.clone(), module_id.clone(), Vec::new()));
            row.steps_done = row.steps_done.saturating_add(1);
            row.last_label = step.label.clone();
            if let Some(cost) = step.cost_usd {
                row.cost_usd += cost;
            }
            row.severity = step.severity.clone();
            // Severity-aware state transition. "danger" pushes Failing; other
            // first-step events flip Queued -> Active. A step labelled "done"
            // (kind == "done" or "tool-complete") promotes Active -> Done.
            row.state = match (step.severity.as_deref(), step.kind.as_str(), row.state) {
                (Some("danger"), _, _) => DagTaskState::Failing,
                (_, "done" | "tool-complete", _) => DagTaskState::Done,
                (_, _, DagTaskState::Queued) => DagTaskState::Active,
                (_, _, current) => current,
            };
            if row.started_at.is_none() {
                row.started_at = Some(Instant::now());
            }
            if matches!(row.state, DagTaskState::Done | DagTaskState::Failing)
                && row.completed_at.is_none()
            {
                row.completed_at = Some(Instant::now());
            }
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

    pub fn toggle_pane_focus(&mut self) {
        self.pane_focus = self.pane_focus.toggle();
    }

    pub fn toggle_verbose_subsystems(&mut self) {
        self.verbose_subsystems = !self.verbose_subsystems;
    }

    pub fn toggle_paused(&mut self) {
        self.paused = !self.paused;
    }
}

/// True for module ids that should never claim a row in the left pane and
/// whose feed events are suppressed unless `verbose_subsystems` is on.
pub fn is_hidden_module_id(module_id: &str) -> bool {
    matches!(
        module_id,
        "pipeline" | "systems-hunt" | "context-lite"
    )
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
