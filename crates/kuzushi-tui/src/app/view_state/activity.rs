use crate::app::{phase_attempt_outcome_from_label, phase_result_policy};
use kuzushi_core::modules::{BuiltinModule, DagNodeDescriptor, ModuleRegistry};
use kuzushi_core::runtime::{RuntimeCost, RuntimeCostReport};
pub use kuzushi_core::workflow_attempts::PhaseResultAction as RunFocusResultAction;
use kuzushi_core::{RunTraceStep, WorkflowPhase};
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

/// Maximum number of trace events kept in memory for the Activity view's
/// right pane. Older events are dropped from `events` but their contribution
/// to per-task aggregates (`steps_done`, `last_label`, `cost_usd`) survives.
pub const ACTIVITY_FEED_RING_CAPACITY: usize = 2000;
const ACTIVITY_TASK_DETAIL_CAPACITY: usize = 6;
const ACTIVITY_TASK_ROW_CAPACITY: usize = 2048;
const ACTIVITY_HIDDEN_TASK_STATE_CAPACITY: usize = 2048;

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
    Canceling,
    Done,
    Partial,
    Failing,
    Blocked,
    Canceled,
    Skipped,
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
    observed_task_count: usize,
}

impl Default for SubsystemAggregate {
    fn default() -> Self {
        Self {
            active_count: 0,
            total_count: 0,
            last_label: String::new(),
            state: DagTaskState::Queued,
            hidden_task_states: BTreeMap::new(),
            observed_task_count: 0,
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
            observed_task_count: total_count,
            ..Self::default()
        }
    }
}

/// Live state for the Activity view. Created at scan/run start, mutated by
/// the trace-event drain pump on every tick, rendered by the activity view.
#[derive(Debug, Clone)]
pub struct ActivitySession {
    pub run_id: String,
    pub run_projection: kuzushi_core::run_lifecycle::RunProjection,
    pub run_presentation_hydration: kuzushi_core::run_lifecycle::RunPresentationHydrationV1,
    /// Engagement phase at the moment this run started. This is transient
    /// presentation state: it keeps a live/finished Activity composition on
    /// the phase that launched it even when newly persisted artifacts advance
    /// the workspace-derived journey underneath the operator.
    pub origin_phase: Option<WorkflowPhase>,
    pub phase_attempt_id: Option<kuzushi_core::run_lifecycle::RunAttemptId>,
    /// Exact shell destination captured before a foreground run opens. Route-
    /// local state (Workbench pane/page/scroll and pinned finding) stays in the
    /// router, so restoring this view restores the full operator context.
    pub run_focus_origin: Option<RunFocusOrigin>,
    pub run_focus_backgrounded: bool,
    pub run_focus_terminal_pending: bool,
    pub run_focus_receipt: Option<RunFocusReceipt>,
    pub sequence_run_refs: Vec<String>,
    pub interaction_count: usize,
    pub rerun_specification: Option<String>,
    pub(crate) operator_question: Option<crate::PendingOperatorQuestion>,
    pub(crate) operator_answer_acknowledgement: Option<String>,
    pub(crate) run_focus_pending_viz: Option<crate::scene3d::VizPage>,
    pub sequence_started_at: Instant,
    pub sequence_run_count: usize,
    pub started_at: Instant,
    pub completed_at: Option<Instant>,
    pub tasks: BTreeMap<String, DagTaskRow>,
    task_order: Vec<String>,
    tool_task_aliases: BTreeMap<String, String>,
    pub step_task_ids: BTreeMap<usize, String>,
    pub subsystem_aggregate: SubsystemAggregate,
    pub events: VecDeque<RecordedTraceEvent>,
    runtime_cost: RuntimeCostReport,
    cost_accounting_error: Option<String>,
    durable_run_item_seq: u64,
    run_item_writer_fault: Option<kuzushi_core::run_lifecycle::RunItemWriterFault>,
    run_item_delivery_failure: Option<kuzushi_core::run_lifecycle::RunItemDeliveryFault>,
    run_item_derivative_tracking: bool,
    run_item_derivative_seq: u64,
    run_item_derivative_failure: Option<kuzushi_core::run_lifecycle::RunItemDeliveryFault>,
}

struct VisibleStepTask {
    task_id: String,
    rolled_up_child: bool,
}

fn derivative_range_fault(
    applied_seq: u64,
    durable_seq: u64,
) -> kuzushi_core::run_lifecycle::RunItemDeliveryFault {
    kuzushi_core::run_lifecycle::RunItemDeliveryFault {
        stage: kuzushi_core::run_lifecycle::RunItemDeliveryFailureStage::DerivativeSubscriber,
        applied_seq,
        durable_seq,
        detail: kuzushi_core::run_lifecycle::SafeText::operator_visible(
            "invalid derivative run-item range notification",
        ),
    }
}

/// Route-local UI state for the Activity surface. The paired `ActivitySession`
/// owns run/DAG/event data; this type owns the operator's current projection of
/// that data: focused task, pane, pause/filter flags, and scroll positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityRouteState {
    pub focus_task: Option<String>,
    pub pane_focus: PaneFocus,
    pub verbose_subsystems: bool,
    pub paused: bool,
    pub feed_scroll: usize,
    pub task_scroll: usize,
    pub task_cursor: usize,
    pub paused_event_count: Option<usize>,
    /// True while the feed renderer should auto-scroll to the latest event.
    /// Becomes false the moment the operator manually scrolls the feed; reset
    /// to true on `G` (scroll-to-bottom). Decoupled from `paused` so toggling
    /// pause doesn't unpin a manually-scrolled position.
    pub feed_auto_tail: bool,
    pub steer_editor: Option<RunFocusSteerEditor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunFocusOrigin {
    pub view: crate::ShellView,
    pub input_mode: crate::InputMode,
    pub auto_return: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunFocusReceipt {
    pub outcome: String,
    pub run_count: usize,
    pub elapsed_secs: u64,
    pub cost: String,
    pub origin_phase: Option<WorkflowPhase>,
    pub attempt_id: Option<String>,
    pub run_refs: Vec<String>,
    pub changed_findings: u64,
    pub changed_artifacts: Vec<String>,
    pub result_summaries: Vec<kuzushi_core::run_artifacts::RunResultSummary>,
    pub interaction_count: usize,
    pub rerun_specification: Option<String>,
    pub actions: Vec<RunFocusResultAction>,
    pub recommended_next: Option<String>,
}

impl RunFocusReceipt {
    pub fn summary(&self) -> String {
        format!(
            "{} · {} run{} · {}s · {}",
            self.outcome,
            self.run_count,
            if self.run_count == 1 { "" } else { "s" },
            self.elapsed_secs,
            self.cost
        )
    }

    pub(crate) fn durable_metadata(&self) -> kuzushi_core::workflow_attempts::PhaseAttemptReceipt {
        kuzushi_core::workflow_attempts::PhaseAttemptReceipt {
            run_count: self.run_count,
            elapsed_secs: self.elapsed_secs,
            cost: self.cost.clone(),
            changed_findings: self.changed_findings,
            changed_artifacts: self.changed_artifacts.clone(),
            interaction_count: self.interaction_count,
            rerun_specification: self.rerun_specification.clone(),
            actions: self.actions.clone(),
            recommended_next: self.recommended_next.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunFocusSteerEditor {
    pub input: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityTerminalContext {
    Run,
    Scan,
}

impl ActivityTerminalContext {
    fn noun(self) -> &'static str {
        match self {
            ActivityTerminalContext::Run => "run",
            ActivityTerminalContext::Scan => "scan",
        }
    }
}

impl Default for ActivityRouteState {
    fn default() -> Self {
        Self {
            focus_task: None,
            pane_focus: PaneFocus::Left,
            verbose_subsystems: false,
            paused: false,
            feed_scroll: 0,
            task_scroll: 0,
            task_cursor: 0,
            paused_event_count: None,
            feed_auto_tail: true,
            steer_editor: None,
        }
    }
}

impl ActivitySession {
    pub fn new(run_id: impl Into<String>) -> Self {
        let run_id = run_id.into();
        Self {
            run_id: run_id.clone(),
            run_projection: kuzushi_core::run_lifecycle::RunProjection::default(),
            run_presentation_hydration:
                kuzushi_core::run_lifecycle::RunPresentationHydrationV1::default(),
            origin_phase: None,
            phase_attempt_id: None,
            run_focus_origin: None,
            run_focus_backgrounded: false,
            run_focus_terminal_pending: false,
            run_focus_receipt: None,
            sequence_run_refs: vec![run_id],
            interaction_count: 0,
            rerun_specification: None,
            operator_question: None,
            operator_answer_acknowledgement: None,
            run_focus_pending_viz: None,
            started_at: Instant::now(),
            sequence_started_at: Instant::now(),
            sequence_run_count: 1,
            completed_at: None,
            tasks: BTreeMap::new(),
            task_order: Vec::new(),
            tool_task_aliases: BTreeMap::new(),
            step_task_ids: BTreeMap::new(),
            subsystem_aggregate: SubsystemAggregate::default(),
            events: VecDeque::with_capacity(ACTIVITY_FEED_RING_CAPACITY),
            runtime_cost: RuntimeCostReport::known(RuntimeCost::ZERO),
            cost_accounting_error: None,
            durable_run_item_seq: 0,
            run_item_writer_fault: None,
            run_item_delivery_failure: None,
            run_item_derivative_tracking: false,
            run_item_derivative_seq: 0,
            run_item_derivative_failure: None,
        }
    }

    /// Capture the workflow phase that launched this activity session.
    pub fn with_origin_phase(mut self, phase: WorkflowPhase) -> Self {
        self.origin_phase = Some(phase);
        self
    }

    pub(crate) fn with_phase_attempt_id(
        mut self,
        attempt_id: kuzushi_core::run_lifecycle::RunAttemptId,
    ) -> Self {
        self.phase_attempt_id = Some(attempt_id);
        self
    }

    pub fn with_rerun_specification(mut self, specification: impl Into<String>) -> Self {
        self.rerun_specification = Some(specification.into());
        self
    }

    pub(crate) fn record_operator_question(&mut self) {
        self.interaction_count = self.interaction_count.saturating_add(1);
    }

    pub fn with_run_focus_origin(mut self, origin: RunFocusOrigin) -> Self {
        self.run_focus_origin = Some(origin);
        self
    }

    pub(crate) fn continue_run_focus_sequence_from(&mut self, prior: &ActivitySession) {
        self.origin_phase = prior.origin_phase.or(self.origin_phase);
        self.phase_attempt_id = prior.phase_attempt_id.or(self.phase_attempt_id);
        self.run_focus_origin = prior.run_focus_origin;
        self.run_focus_backgrounded = prior.run_focus_backgrounded;
        self.run_focus_pending_viz = prior.run_focus_pending_viz;
        self.run_presentation_hydration
            .merge(prior.run_presentation_hydration.clone());
        self.sequence_run_refs = prior.sequence_run_refs.clone();
        if !self.sequence_run_refs.contains(&self.run_id) {
            self.sequence_run_refs.push(self.run_id.clone());
        }
        self.interaction_count = prior.interaction_count;
        self.operator_answer_acknowledgement = prior.operator_answer_acknowledgement.clone();
        self.rerun_specification = self
            .rerun_specification
            .clone()
            .or_else(|| prior.rerun_specification.clone());
        self.tasks = prior.tasks.clone();
        self.task_order = prior.task_order.clone();
        self.sequence_started_at = prior.sequence_started_at;
        self.sequence_run_count = prior.sequence_run_count.saturating_add(1);
        self.runtime_cost = prior.runtime_cost;
        self.cost_accounting_error = prior.cost_accounting_error.clone();
    }

    pub(crate) fn mark_run_focus_terminal_pending(&mut self, outcome: impl Into<String>) {
        self.mark_terminal();
        self.run_focus_terminal_pending = true;
        let outcome = outcome.into();
        let policy = phase_result_policy(
            self.origin_phase,
            phase_attempt_outcome_from_label(&outcome),
            false,
        );
        self.run_focus_receipt = Some(RunFocusReceipt {
            outcome: outcome.clone(),
            run_count: self.sequence_run_count,
            elapsed_secs: self.sequence_started_at.elapsed().as_secs(),
            cost: self.runtime_cost_report().map_or_else(
                |_| "cost accounting error".to_string(),
                |report| {
                    if report.is_unavailable() {
                        "cost not recorded".to_string()
                    } else if report.is_complete() {
                        format!("${:.4}", report.observed_usd())
                    } else {
                        format!(">=${:.4} (metering incomplete)", report.observed_usd())
                    }
                },
            ),
            origin_phase: self.origin_phase,
            attempt_id: self
                .phase_attempt_id
                .map(|attempt_id| attempt_id.to_string()),
            run_refs: self.sequence_run_refs.clone(),
            changed_findings: 0,
            changed_artifacts: Vec::new(),
            result_summaries: Vec::new(),
            interaction_count: self.interaction_count,
            rerun_specification: self.rerun_specification.clone(),
            actions: policy.actions,
            recommended_next: policy.recommended_next,
        });
    }

    /// Construct a session whose phase origin is known at launch time.
    pub fn for_phase(run_id: impl Into<String>, phase: WorkflowPhase) -> Self {
        Self::new(run_id).with_origin_phase(phase)
    }

    pub(crate) fn for_optional_phase(
        run_id: impl Into<String>,
        phase: Option<WorkflowPhase>,
    ) -> Self {
        match phase {
            Some(phase) => Self::for_phase(run_id, phase),
            None => Self::new(run_id),
        }
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.completed_at
            .unwrap_or_else(Instant::now)
            .saturating_duration_since(self.started_at)
            .as_secs()
    }

    pub fn mark_terminal(&mut self) {
        self.completed_at.get_or_insert_with(Instant::now);
    }

    pub(crate) fn runtime_cost_report(&self) -> anyhow::Result<RuntimeCostReport> {
        if let Some(error) = &self.cost_accounting_error {
            anyhow::bail!("{error}");
        }
        Ok(self.runtime_cost)
    }

    pub(crate) fn settle_runtime_cost(&mut self, report: RuntimeCostReport) {
        self.runtime_cost = report;
        self.cost_accounting_error = None;
    }

    pub(crate) fn mark_runtime_cost_incomplete(&mut self) {
        self.runtime_cost = self.runtime_cost.mark_incomplete();
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
        let task_id = self.task_id_for_tool(tool_name);
        let module_id = task_id.split(':').next().unwrap_or(&task_id).to_string();
        self.remember_task(&task_id);
        let row = self
            .tasks
            .entry(task_id.clone())
            .or_insert_with(|| DagTaskRow::queued(task_id, module_id, Vec::new()));
        // A canceled row is terminal: once the operator aborted it, a late
        // worker result must not silently overwrite `× canceled` with `✓ done`
        // and present an aborted run as a clean success.
        if matches!(
            row.state,
            DagTaskState::Done
                | DagTaskState::Partial
                | DagTaskState::Failing
                | DagTaskState::Blocked
                | DagTaskState::Skipped
                | DagTaskState::Canceled
        ) {
            return;
        }
        row.state = DagTaskState::Done;
        if row.started_at.is_none() {
            row.started_at = Some(Instant::now());
        }
        row.completed_at = Some(Instant::now());
    }

    pub fn mark_task_skipped(&mut self, tool_name: &str) {
        let task_id = self.task_id_for_tool(tool_name);
        let module_id = task_id.split(':').next().unwrap_or(&task_id).to_string();
        self.remember_task(&task_id);
        let row = self
            .tasks
            .entry(task_id.clone())
            .or_insert_with(|| DagTaskRow::queued(task_id, module_id, Vec::new()));
        row.state = DagTaskState::Skipped;
        row.started_at.get_or_insert_with(Instant::now);
        row.completed_at = Some(Instant::now());
        row.last_label = "tool reported skipped".to_string();
        finalize_activity_row_details(row);
    }

    pub fn mark_task_partial(&mut self, tool_name: &str, reason: &str) {
        let task_id = self.task_id_for_tool(tool_name);
        let module_id = task_id.split(':').next().unwrap_or(&task_id).to_string();
        self.remember_task(&task_id);
        let row = self
            .tasks
            .entry(task_id.clone())
            .or_insert_with(|| DagTaskRow::queued(task_id, module_id, Vec::new()));
        row.state = DagTaskState::Partial;
        row.started_at.get_or_insert_with(Instant::now);
        row.completed_at = Some(Instant::now());
        row.severity = Some("warn".to_string());
        row.last_label = format!("partial result: {reason}");
        finalize_activity_row_details(row);
    }

    pub fn mark_task_blocked(&mut self, tool_name: &str, reason: &str) {
        let task_id = self.task_id_for_tool(tool_name);
        let module_id = task_id.split(':').next().unwrap_or(&task_id).to_string();
        self.remember_task(&task_id);
        let row = self
            .tasks
            .entry(task_id.clone())
            .or_insert_with(|| DagTaskRow::queued(task_id, module_id, Vec::new()));
        row.state = DagTaskState::Blocked;
        row.started_at.get_or_insert_with(Instant::now);
        row.completed_at = Some(Instant::now());
        row.last_label = reason.to_string();
        finalize_activity_row_details(row);
    }

    pub fn apply_step(&mut self, step: RunTraceStep) {
        self.apply_step_with_cost(step);
    }

    pub fn apply_run_item(
        &mut self,
        item: kuzushi_core::run_lifecycle::RunItemEnvelopeV1,
    ) -> anyhow::Result<()> {
        self.durable_run_item_seq = self.durable_run_item_seq.max(item.seq);
        let delta = self.run_projection.apply_committed(item)?;
        self.apply_projection_delta(&delta);
        Ok(())
    }

    pub(crate) fn observe_committed_range(
        &mut self,
        range: kuzushi_core::run_lifecycle::CommittedRange,
    ) {
        if range.first_seq == 0 || range.first_seq > range.through_seq {
            self.run_item_delivery_failure =
                Some(kuzushi_core::run_lifecycle::RunItemDeliveryFault {
                    stage:
                        kuzushi_core::run_lifecycle::RunItemDeliveryFailureStage::RangeSubscriber,
                    applied_seq: self.run_projection.last_committed_seq,
                    durable_seq: self.durable_run_item_seq,
                    detail: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                        "invalid durable run-item range notification",
                    ),
                });
            return;
        }
        self.run_item_derivative_tracking = true;
        self.durable_run_item_seq = self.durable_run_item_seq.max(range.through_seq);
    }

    pub(crate) fn observe_derivative_range(
        &mut self,
        range: kuzushi_core::run_lifecycle::CommittedRange,
    ) {
        self.run_item_derivative_tracking = true;
        if range.first_seq == 0 || range.first_seq > range.through_seq {
            self.run_item_derivative_failure = Some(derivative_range_fault(
                self.run_item_derivative_seq,
                self.durable_run_item_seq,
            ));
            return;
        }
        self.run_item_derivative_seq = self.run_item_derivative_seq.max(range.through_seq);
        self.run_item_derivative_failure = None;
    }

    pub(crate) fn record_run_item_writer_fault(
        &mut self,
        fault: kuzushi_core::run_lifecycle::RunItemWriterFault,
    ) {
        self.durable_run_item_seq = self.durable_run_item_seq.max(fault.last_durable_seq);
        self.run_item_writer_fault = Some(fault);
    }

    pub(crate) fn record_run_item_delivery_fault(
        &mut self,
        fault: kuzushi_core::run_lifecycle::RunItemDeliveryFault,
    ) {
        self.durable_run_item_seq = self.durable_run_item_seq.max(fault.durable_seq);
        if fault.is_derivative() {
            self.run_item_derivative_tracking = true;
            self.run_item_derivative_failure = Some(fault);
        } else {
            self.run_item_delivery_failure = Some(fault);
        }
    }

    pub fn effective_run_lifecycle_health(
        &self,
    ) -> kuzushi_core::run_lifecycle::RunLifecycleHealth {
        use kuzushi_core::run_lifecycle::RunLifecycleHealth;
        let RunLifecycleHealth {
            integrity,
            progress,
            ..
        } = self.run_projection.lifecycle_health();
        let applied_seq = self.run_projection.last_committed_seq;
        let durable_seq = self.durable_run_item_seq.max(applied_seq);
        RunLifecycleHealth {
            integrity,
            durability: self.effective_durability_health(durable_seq),
            progress,
            delivery: self.effective_delivery_health(applied_seq, durable_seq),
            derivative_delivery: self.effective_derivative_health(durable_seq),
        }
    }

    fn effective_durability_health(
        &self,
        durable_seq: u64,
    ) -> kuzushi_core::run_lifecycle::RunDurabilityHealth {
        use kuzushi_core::run_lifecycle::RunDurabilityHealth;
        self.run_item_writer_fault.as_ref().map_or(
            RunDurabilityHealth::Durable {
                through_seq: durable_seq,
            },
            |fault| RunDurabilityHealth::Failed {
                last_durable_seq: fault.last_durable_seq,
                stage: fault.stage,
                detail: fault.detail.clone(),
                execution_may_have_occurred: fault.execution_may_have_occurred,
            },
        )
    }

    fn effective_delivery_health(
        &self,
        applied_seq: u64,
        durable_seq: u64,
    ) -> kuzushi_core::run_lifecycle::RunDeliveryHealth {
        use kuzushi_core::run_lifecycle::RunDeliveryHealth;
        if let Some(fault) = self.run_item_delivery_failure.as_ref() {
            return RunDeliveryHealth::Failed {
                applied_seq,
                stage: fault.stage,
                detail: fault.detail.clone(),
            };
        }
        if applied_seq < durable_seq {
            RunDeliveryHealth::CatchingUp {
                applied_seq,
                durable_seq,
            }
        } else {
            RunDeliveryHealth::Current {
                through_seq: applied_seq,
            }
        }
    }

    fn effective_derivative_health(
        &self,
        durable_seq: u64,
    ) -> kuzushi_core::run_lifecycle::RunDerivativeDeliveryHealth {
        use kuzushi_core::run_lifecycle::RunDerivativeDeliveryHealth;
        if !self.run_item_derivative_tracking {
            return RunDerivativeDeliveryHealth::NotObserved;
        }
        if let Some(fault) = self.run_item_derivative_failure.as_ref() {
            return RunDerivativeDeliveryHealth::Failed {
                applied_seq: fault.applied_seq,
                durable_seq: durable_seq.max(fault.durable_seq),
                stage: fault.stage,
                detail: fault.detail.clone(),
            };
        }
        if self.run_item_derivative_seq < durable_seq {
            return RunDerivativeDeliveryHealth::CatchingUp {
                applied_seq: self.run_item_derivative_seq,
                durable_seq,
            };
        }
        RunDerivativeDeliveryHealth::Current {
            through_seq: self.run_item_derivative_seq,
        }
    }

    fn apply_projection_delta(&mut self, delta: &kuzushi_core::run_lifecycle::ProjectionDelta) {
        self.runtime_cost = self.run_projection.effective_cost();
        self.cost_accounting_error = None;
        if self.run_projection.tasks.is_empty() {
            return;
        }
        if delta.plan_changed || !delta.task_ids.is_empty() {
            self.task_order = typed_task_order(&self.run_projection);
        }
        for task_id in &delta.task_ids {
            let Some(task) = self.run_projection.tasks.get(task_id) else {
                continue;
            };
            let key = task_id.to_string();
            let prior = self.tasks.get(&key);
            let row = typed_task_row(&self.run_projection, key.clone(), task, prior);
            self.tasks.insert(key, row);
        }
    }

    pub(crate) fn apply_step_with_cost(&mut self, step: RunTraceStep) -> Option<RuntimeCostReport> {
        let call_cost = self.record_terminal_model_call_cost(&step);
        let module_id = step.module_id.as_deref().unwrap_or("").to_string();
        if !module_id.is_empty() && is_hidden_module_id(&module_id) {
            self.apply_hidden_module_step(&step);
        } else if let Some(verb) = step.verb.as_deref() {
            self.apply_visible_module_step(&module_id, verb, &step, call_cost);
        }

        let event = RecordedTraceEvent {
            step,
            observed_at: Instant::now(),
        };
        self.push_recorded_event(event);
        call_cost
    }

    fn record_terminal_model_call_cost(
        &mut self,
        step: &RunTraceStep,
    ) -> Option<RuntimeCostReport> {
        let cost = match kuzushi_core::run_artifacts::terminal_model_call_cost_report(step) {
            Ok(cost) => cost,
            Err(error) => {
                self.record_cost_accounting_error(error);
                return None;
            }
        };
        if let Some(cost) = cost {
            match self.runtime_cost.checked_add(cost, "Activity runtime cost") {
                Ok(total) => self.runtime_cost = total,
                Err(error) => self.record_cost_accounting_error(error),
            }
        }
        cost
    }

    fn record_cost_accounting_error(&mut self, error: impl std::fmt::Display) {
        self.cost_accounting_error
            .get_or_insert_with(|| format!("Activity cost invalid: {error}"));
    }

    fn push_recorded_event(&mut self, event: RecordedTraceEvent) {
        if self.events.len() >= ACTIVITY_FEED_RING_CAPACITY {
            if let Some(evicted) = self.events.pop_front() {
                self.step_task_ids.remove(&evicted.step.n);
            }
        }
        self.events.push_back(event);
    }

    fn apply_hidden_module_step(&mut self, step: &RunTraceStep) {
        let task_id = hidden_subsystem_task_id(step);
        self.reserve_hidden_task_capacity(&task_id);
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

    fn apply_visible_module_step(
        &mut self,
        module_id: &str,
        verb: &str,
        step: &RunTraceStep,
        call_cost: Option<RuntimeCostReport>,
    ) {
        let Some(target) = self.visible_step_task(module_id, verb, step) else {
            return;
        };
        if let Some(row) = self.activity_row_for_step(&target.task_id, module_id, step) {
            if let Err(error) =
                apply_activity_row_step(row, step, target.rolled_up_child, call_cost)
            {
                self.record_cost_accounting_error(error);
            }
            self.step_task_ids.insert(step.n, target.task_id);
        }
    }

    /// Map a step's `(module_id, verb)` to a DAG row id. Producers report the
    /// scan umbrella as `sast:scan` + verb `scan`, which naively composes to
    /// `sast:scan:scan` and mints a duplicate next to the seeded `sast:scan`
    /// node. Collapsing a doubled trailing segment fixes it regardless of how
    /// the tool name split across module_id/verb, and is order-independent.
    fn resolve_step_task_id(&self, module_id: &str, verb: &str) -> String {
        self.task_id_for_tool(&format!("{module_id}:{verb}"))
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
            self.reserve_visible_task_capacity(task_id);
            self.remember_task(task_id);
            return Some(self.tasks.entry(task_id.to_string()).or_insert_with(|| {
                DagTaskRow::queued(task_id.to_string(), module_id.to_string(), Vec::new())
            }));
        }
        self.tasks.get_mut(task_id)
    }

    fn reserve_visible_task_capacity(&mut self, protected_task_id: &str) {
        if self.tasks.len() < ACTIVITY_TASK_ROW_CAPACITY
            || self.tasks.contains_key(protected_task_id)
        {
            return;
        }
        if let Some(evicted_task_id) =
            visible_task_eviction_candidate(&self.tasks, protected_task_id)
        {
            self.tasks.remove(&evicted_task_id);
            self.task_order
                .retain(|task_id| task_id != &evicted_task_id);
            self.step_task_ids
                .retain(|_, task_id| task_id != &evicted_task_id);
        }
    }

    fn reserve_hidden_task_capacity(&mut self, protected_task_id: &str) {
        if self
            .subsystem_aggregate
            .hidden_task_states
            .contains_key(protected_task_id)
        {
            return;
        }
        self.subsystem_aggregate.observed_task_count = self
            .subsystem_aggregate
            .observed_task_count
            .saturating_add(1);
        if self.subsystem_aggregate.hidden_task_states.len() < ACTIVITY_HIDDEN_TASK_STATE_CAPACITY {
            return;
        }
        if let Some(evicted_task_id) =
            hidden_task_eviction_candidate(&self.subsystem_aggregate, protected_task_id)
        {
            self.subsystem_aggregate
                .hidden_task_states
                .remove(&evicted_task_id);
        }
    }

    /// Legacy adapter for pre-typed manual Activity sessions. New run-backed
    /// sessions receive runtime task instances from `RunProjection` and must
    /// never turn capability descriptors into pretend work items.
    pub fn seed_from_registry_legacy(&mut self, registry: &ModuleRegistry) {
        let hidden_total = registry
            .all_modules()
            .map(|module| self.seed_registry_module(module))
            .sum();
        self.seed_hidden_subsystem_total(hidden_total);
    }

    pub(crate) fn seed_task_sequence(&mut self, task_ids: impl IntoIterator<Item = String>) {
        for task_id in task_ids {
            let module_id = module_id_for_task_id(&task_id);
            self.remember_task(&task_id);
            self.tasks
                .entry(task_id.clone())
                .or_insert_with(|| DagTaskRow::queued(task_id, module_id, Vec::new()));
        }
    }

    pub(crate) fn bind_tool_task(&mut self, tool_name: &str, task_id: String) {
        self.tool_task_aliases
            .insert(collapse_doubled_tail(tool_name), task_id);
    }

    fn task_id_for_tool(&self, tool_name: &str) -> String {
        let canonical = collapse_doubled_tail(tool_name);
        self.tool_task_aliases
            .get(&canonical)
            .cloned()
            .unwrap_or(canonical)
    }

    pub(crate) fn ordered_task_rows(&self) -> Vec<&DagTaskRow> {
        let mut rows = self
            .task_order
            .iter()
            .filter_map(|task_id| self.tasks.get(task_id))
            .collect::<Vec<_>>();
        rows.extend(
            self.tasks
                .iter()
                .filter(|(task_id, _)| !self.task_order.contains(task_id))
                .map(|(_, row)| row),
        );
        rows
    }

    pub(crate) fn task_is_sequence_owned(&self, task_id: &str) -> bool {
        self.task_order.iter().any(|known| known == task_id)
    }

    fn remember_task(&mut self, task_id: &str) {
        if !self.task_order.iter().any(|known| known == task_id) {
            self.task_order.push(task_id.to_string());
        }
    }

    pub fn mark_active_tasks_canceled(&mut self) {
        let now = Instant::now();
        for row in self.tasks.values_mut().filter(|row| row_can_cancel(row)) {
            mark_activity_row_canceled(row, now);
        }
        mark_subsystems_canceled(&mut self.subsystem_aggregate);
        self.completed_at.get_or_insert(now);
    }

    pub fn mark_active_tasks_canceling(&mut self) {
        let now = Instant::now();
        for row in self.tasks.values_mut().filter(|row| row_can_cancel(row)) {
            mark_activity_row_canceling(row, now);
        }
        mark_subsystems_canceling(&mut self.subsystem_aggregate);
    }

    pub fn mark_incomplete_tasks_after_success(&mut self, context: ActivityTerminalContext) {
        let now = Instant::now();
        for row in self.tasks.values_mut() {
            mark_activity_row_success_terminal(row, now, context);
        }
        self.completed_at.get_or_insert(now);
    }

    pub fn mark_incomplete_tasks_after_failure(&mut self) {
        let now = Instant::now();
        for row in self.tasks.values_mut() {
            mark_activity_row_failure_terminal(row, now);
        }
        self.completed_at.get_or_insert(now);
    }

    pub fn mark_incomplete_tasks_after_skipped(&mut self) {
        let now = Instant::now();
        for row in self.tasks.values_mut() {
            if matches!(
                row.state,
                DagTaskState::Queued | DagTaskState::Active | DagTaskState::Canceling
            ) {
                mark_never_started_row_skipped(row, now, "not run after tool skipped");
            }
        }
        self.completed_at.get_or_insert(now);
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

impl ActivityRouteState {
    pub fn toggle_pane_focus(&mut self) {
        self.pane_focus = self.pane_focus.toggle();
    }

    pub fn selected_task_id<'a>(&'a self, session: &'a ActivitySession) -> Option<&'a str> {
        self.focus_task
            .as_deref()
            .filter(|task_id| session.tasks.contains_key(*task_id))
            .or_else(|| self.task_id_at_cursor(session))
    }

    pub fn task_id_at_cursor<'a>(&self, session: &'a ActivitySession) -> Option<&'a str> {
        session
            .ordered_task_rows()
            .get(self.task_cursor.min(self.task_cursor_max(session)))
            .map(|row| row.task_id.as_str())
    }

    pub fn focus_task_at_cursor(&mut self, session: &ActivitySession) -> Option<String> {
        let task_id = self.task_id_at_cursor(session)?.to_string();
        self.focus_task = Some(task_id.clone());
        Some(task_id)
    }

    pub fn shift_task_cursor(&mut self, session: &ActivitySession, amount: isize) {
        let next = shift_index(self.task_cursor, amount, self.task_cursor_max(session));
        self.set_task_cursor(session, next);
    }

    pub fn move_task_cursor_to_top(&mut self, session: &ActivitySession) {
        self.set_task_cursor(session, 0);
    }

    pub fn move_task_cursor_to_bottom(&mut self, session: &ActivitySession) {
        self.set_task_cursor(session, self.task_cursor_max(session));
    }

    fn set_task_cursor(&mut self, session: &ActivitySession, index: usize) {
        self.task_cursor = index.min(self.task_cursor_max(session));
        self.task_scroll = self.task_cursor;
    }

    fn task_cursor_max(&self, session: &ActivitySession) -> usize {
        session.tasks.len().saturating_sub(1)
    }

    /// Focus that accounts for the collapsed TASKS pane: with no DAG tasks
    /// the OUTPUT pane is the only one on screen, so scrolling and the
    /// header label act on it regardless of the stored toggle state.
    pub fn effective_pane_focus(&self, session: &ActivitySession) -> PaneFocus {
        if session.tasks.is_empty() {
            PaneFocus::Right
        } else {
            self.pane_focus
        }
    }

    pub fn toggle_verbose_subsystems(&mut self) {
        self.verbose_subsystems = !self.verbose_subsystems;
    }

    pub fn toggle_paused(&mut self, event_count: usize) {
        if self.paused {
            self.paused = false;
            self.paused_event_count = None;
        } else {
            self.paused = true;
            self.paused_event_count = Some(event_count);
        }
    }

    pub fn reset_presentation_state(&mut self) {
        self.focus_task = None;
        self.pane_focus = PaneFocus::Left;
        self.paused = false;
        self.paused_event_count = None;
        self.feed_scroll = 0;
        self.task_scroll = 0;
        self.task_cursor = 0;
        self.feed_auto_tail = true;
        self.steer_editor = None;
    }

    pub fn open_steer_editor(&mut self) {
        self.steer_editor = Some(RunFocusSteerEditor::default());
    }

    pub fn close_steer_editor(&mut self) {
        self.steer_editor = None;
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

fn visible_task_eviction_candidate(
    tasks: &BTreeMap<String, DagTaskRow>,
    protected_task_id: &str,
) -> Option<String> {
    tasks
        .iter()
        .find(|(task_id, row)| {
            task_id.as_str() != protected_task_id && activity_row_is_terminal(row)
        })
        .or_else(|| {
            tasks
                .iter()
                .find(|(task_id, _)| task_id.as_str() != protected_task_id)
        })
        .map(|(task_id, _)| task_id.clone())
}

fn hidden_task_eviction_candidate(
    aggregate: &SubsystemAggregate,
    protected_task_id: &str,
) -> Option<String> {
    aggregate
        .hidden_task_states
        .iter()
        .find(|(task_id, state)| {
            task_id.as_str() != protected_task_id && terminal_task_state(**state)
        })
        .or_else(|| {
            aggregate
                .hidden_task_states
                .iter()
                .find(|(task_id, _)| task_id.as_str() != protected_task_id)
        })
        .map(|(task_id, _)| task_id.clone())
}

fn row_can_cancel(row: &&mut DagTaskRow) -> bool {
    cancelable_task_state(row.state)
}

fn cancelable_task_state(state: DagTaskState) -> bool {
    matches!(
        state,
        DagTaskState::Queued | DagTaskState::Active | DagTaskState::Canceling
    )
}

fn terminal_task_state(state: DagTaskState) -> bool {
    matches!(
        state,
        DagTaskState::Done
            | DagTaskState::Partial
            | DagTaskState::Failing
            | DagTaskState::Blocked
            | DagTaskState::Canceled
            | DagTaskState::Skipped
    )
}

fn mark_activity_row_canceled(row: &mut DagTaskRow, now: Instant) {
    if row.state == DagTaskState::Queued {
        mark_never_started_row_skipped(row, now, "not run after cancel");
        return;
    }
    row.state = DagTaskState::Canceled;
    row.started_at.get_or_insert(now);
    row.completed_at = Some(now);
    row.last_label = "cancel requested; waiting for cleanup".to_string();
    mark_active_details_canceled(row);
}

fn mark_activity_row_canceling(row: &mut DagTaskRow, now: Instant) {
    if row.state == DagTaskState::Queued {
        mark_never_started_row_skipped(row, now, "not run after cancel");
        return;
    }
    row.state = DagTaskState::Canceling;
    row.started_at.get_or_insert(now);
    row.completed_at = None;
    row.last_label = "cancel requested; cleanup in progress".to_string();
}

fn mark_never_started_row_skipped(row: &mut DagTaskRow, now: Instant, label: &str) {
    row.state = DagTaskState::Skipped;
    row.completed_at = Some(now);
    row.last_label = label.to_string();
    finalize_activity_row_details(row);
}

fn mark_activity_row_success_terminal(
    row: &mut DagTaskRow,
    now: Instant,
    context: ActivityTerminalContext,
) {
    match row.state {
        DagTaskState::Active | DagTaskState::Canceling => {
            row.state = DagTaskState::Done;
            row.completed_at = Some(now);
            finalize_activity_row_details(row);
        }
        DagTaskState::Queued => {
            row.state = DagTaskState::Skipped;
            row.completed_at = Some(now);
            row.last_label = format!("not run in this {}", context.noun());
            finalize_activity_row_details(row);
        }
        _ => {}
    }
}

fn mark_activity_row_failure_terminal(row: &mut DagTaskRow, now: Instant) {
    match row.state {
        DagTaskState::Active | DagTaskState::Canceling => {
            row.state = DagTaskState::Failing;
            row.completed_at = Some(now);
            row.severity = Some("danger".to_string());
            row.last_label = "run failed".to_string();
            finalize_activity_row_details(row);
        }
        DagTaskState::Queued => {
            row.state = DagTaskState::Skipped;
            row.completed_at = Some(now);
            row.last_label = "skipped after failure".to_string();
            finalize_activity_row_details(row);
        }
        _ => {}
    }
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

fn apply_activity_row_step(
    row: &mut DagTaskRow,
    step: &RunTraceStep,
    rolled_up_child: bool,
    call_cost: Option<RuntimeCostReport>,
) -> anyhow::Result<()> {
    row.steps_done = row.steps_done.saturating_add(1);
    row.last_label = step.label.clone();
    if let Some(cost) = call_cost {
        row.cost_usd = RuntimeCost::from_usd(row.cost_usd, "Activity task cost")?
            .checked_add(
                RuntimeCost::from_usd(cost.observed_usd(), "Activity model-call cost")?,
                "Activity task cost",
            )?
            .usd();
    }
    row.severity = step.severity.clone();
    record_activity_row_details(row, step);
    row.state = next_activity_row_state(row.state, step, rolled_up_child);
    finalize_activity_row_details(row);
    mark_activity_row_times(row);
    Ok(())
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
    if let Some(cost) = step.cost_usd.and_then(activity_detail_cost) {
        parts.push(cost);
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(" · "))
    }
}

fn activity_detail_cost(cost: f64) -> Option<String> {
    match RuntimeCost::from_usd(cost, "Activity detail cost") {
        Ok(cost) if cost.usd() > 0.0 => Some(format!("${:.4}", cost.usd())),
        Ok(_) => None,
        Err(_) => Some("cost accounting error".to_string()),
    }
}

fn format_latency(ms: u64) -> String {
    if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
    }
}

fn typed_task_order(projection: &kuzushi_core::run_lifecycle::RunProjection) -> Vec<String> {
    let mut order = projection
        .plan
        .iter()
        .flat_map(|plan| plan.task_ids.iter())
        .filter(|task_id| projection.tasks.contains_key(task_id))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    for task_id in &projection.task_order {
        let task_id = task_id.to_string();
        if !order.contains(&task_id) {
            order.push(task_id);
        }
    }
    order
}

fn typed_task_row(
    projection: &kuzushi_core::run_lifecycle::RunProjection,
    task_id: String,
    task: &kuzushi_core::run_lifecycle::TaskProjection,
    prior: Option<&DagTaskRow>,
) -> DagTaskRow {
    let title = task.title.as_str();
    let mut row = DagTaskRow::queued(task_id.clone(), title.to_string(), Vec::new());
    row.state = typed_task_state(task.status);
    row.started_at = typed_started_at(task.status, prior);
    row.completed_at = typed_completed_at(task.status, prior);
    row.last_label = task.detail.as_ref().map_or_else(
        || typed_status_label(task.status).to_string(),
        ToString::to_string,
    );
    row.details = typed_call_details(projection, &task_id);
    row.steps_done = row
        .details
        .iter()
        .filter(|detail| detail.state != DagTaskDetailState::Active)
        .count();
    row.cost_usd = typed_task_cost(projection, &task_id);
    row.severity = typed_task_severity(task.status);
    row
}

fn typed_started_at(
    status: kuzushi_core::run_lifecycle::RunItemStatus,
    prior: Option<&DagTaskRow>,
) -> Option<Instant> {
    if status == kuzushi_core::run_lifecycle::RunItemStatus::Pending {
        return prior.and_then(|row| row.started_at);
    }
    prior
        .and_then(|row| row.started_at)
        .or_else(|| Some(Instant::now()))
}

fn typed_completed_at(
    status: kuzushi_core::run_lifecycle::RunItemStatus,
    prior: Option<&DagTaskRow>,
) -> Option<Instant> {
    status.is_terminal().then(|| {
        prior
            .and_then(|row| row.completed_at)
            .unwrap_or_else(Instant::now)
    })
}

fn typed_call_details(
    projection: &kuzushi_core::run_lifecycle::RunProjection,
    task_id: &str,
) -> Vec<DagTaskDetail> {
    projection
        .calls
        .values()
        .filter(|call| call.task_id.is_some_and(|id| id.to_string() == task_id))
        .rev()
        .take(ACTIVITY_TASK_DETAIL_CAPACITY)
        .map(|call| DagTaskDetail {
            label: call.label.to_string(),
            kind: match call.kind {
                kuzushi_core::run_lifecycle::CallKind::Tool => "tool",
                kuzushi_core::run_lifecycle::CallKind::Model => "model",
            }
            .to_string(),
            state: typed_detail_state(call.status),
            meta: typed_cost_meta(call.cost),
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn typed_task_cost(projection: &kuzushi_core::run_lifecycle::RunProjection, task_id: &str) -> f64 {
    projection
        .calls
        .values()
        .filter(|call| call.task_id.is_some_and(|id| id.to_string() == task_id))
        .filter_map(|call| call.cost.observed_usd_if_available())
        .sum()
}

// Meta strings render appended to the row label, so each carries its own
// leading separator (the latency/cost meta does the same with " (…)").
// Unavailable cost renders nothing: the header and HEALTH pane already
// disclose it once, and repeating "cost not recorded" on every task row
// both spams the screen and eats the row's truncation budget.
fn typed_cost_meta(cost: RuntimeCostReport) -> String {
    if cost.is_unavailable() {
        return String::new();
    }
    if cost.is_complete() {
        return format!(" · ${:.4}", cost.observed_usd());
    }
    format!(" · >=${:.4} (metering incomplete)", cost.observed_usd())
}

fn typed_task_state(status: kuzushi_core::run_lifecycle::RunItemStatus) -> DagTaskState {
    use kuzushi_core::run_lifecycle::RunItemStatus::*;
    match status {
        Pending => DagTaskState::Queued,
        Running => DagTaskState::Active,
        Completed => DagTaskState::Done,
        Partial => DagTaskState::Partial,
        Skipped => DagTaskState::Skipped,
        Failed | Interrupted => DagTaskState::Failing,
        Canceled => DagTaskState::Canceled,
    }
}

fn typed_detail_state(status: kuzushi_core::run_lifecycle::RunItemStatus) -> DagTaskDetailState {
    use kuzushi_core::run_lifecycle::RunItemStatus::*;
    match status {
        Pending | Running => DagTaskDetailState::Active,
        Completed | Skipped => DagTaskDetailState::Done,
        Partial | Failed | Interrupted => DagTaskDetailState::Failing,
        Canceled => DagTaskDetailState::Canceled,
    }
}

fn typed_status_label(status: kuzushi_core::run_lifecycle::RunItemStatus) -> &'static str {
    use kuzushi_core::run_lifecycle::RunItemStatus::*;
    match status {
        Pending => "pending",
        Running => "running",
        Completed => "completed",
        Partial => "partial",
        Skipped => "skipped",
        Failed => "failed",
        Canceled => "canceled",
        Interrupted => "interrupted",
    }
}

fn typed_task_severity(status: kuzushi_core::run_lifecycle::RunItemStatus) -> Option<String> {
    use kuzushi_core::run_lifecycle::RunItemStatus::*;
    match status {
        Partial => Some("warn".to_string()),
        Failed | Interrupted => Some("danger".to_string()),
        _ => None,
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
        DagTaskState::Partial | DagTaskState::Failing | DagTaskState::Blocked => {
            DagTaskDetailState::Failing
        }
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
        (_, _, DagTaskState::Canceled) => DagTaskState::Canceled,
        (_, _, DagTaskState::Blocked) => DagTaskState::Blocked,
        (_, _, DagTaskState::Canceling) => DagTaskState::Canceling,
        (_, _, DagTaskState::Skipped) => DagTaskState::Skipped,
        (_, _, DagTaskState::Partial) => DagTaskState::Partial,
        (Some("danger"), _, _) if !rolled_up_child => DagTaskState::Failing,
        (_, _, DagTaskState::Failing) => DagTaskState::Failing,
        (_, "done" | "tool-complete", _) if !rolled_up_child => DagTaskState::Done,
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
    matches!(
        row.state,
        DagTaskState::Done
            | DagTaskState::Partial
            | DagTaskState::Failing
            | DagTaskState::Blocked
            | DagTaskState::Canceled
            | DagTaskState::Skipped
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
    let observed_total = aggregate
        .observed_task_count
        .max(aggregate.hidden_task_states.len());
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
        DagTaskState::Partial,
        DagTaskState::Blocked,
        DagTaskState::Canceled,
        DagTaskState::Canceling,
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

fn mark_subsystems_canceling(aggregate: &mut SubsystemAggregate) {
    if !subsystems_have_tasks(aggregate) {
        return;
    }
    for state in aggregate.hidden_task_states.values_mut() {
        if *state == DagTaskState::Active {
            *state = DagTaskState::Canceling;
        } else if *state == DagTaskState::Queued {
            *state = DagTaskState::Canceled;
        }
    }
    aggregate.state = match aggregate.state {
        DagTaskState::Active => DagTaskState::Canceling,
        DagTaskState::Queued => DagTaskState::Canceled,
        state => state,
    };
    aggregate.active_count = 0;
    aggregate.last_label = "cancel requested; cleanup in progress".to_string();
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

fn shift_index(current: usize, amount: isize, max: usize) -> usize {
    if amount.is_negative() {
        current.saturating_sub(amount.unsigned_abs())
    } else {
        current.saturating_add(amount as usize).min(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::PendingOperatorQuestion;
    use kuzushi_core::RunTraceStep;

    /// Meta strings append directly to the row label: without its own
    /// leading separator the card reads "context:build$0.0100". Unavailable
    /// cost stays silent — the header/HEALTH pane disclose it once.
    #[test]
    fn typed_cost_meta_carries_its_own_separator() {
        let unavailable = typed_cost_meta(kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE);
        assert_eq!(unavailable, "", "per-row 'cost not recorded' is noise");

        let known = kuzushi_core::runtime::RuntimeCostReport::known(
            kuzushi_core::runtime::RuntimeCost::from_usd(0.01, "test").unwrap(),
        );
        let meta = typed_cost_meta(known);
        assert!(
            format!("context:build{meta}").contains("context:build · $"),
            "label+meta must not concatenate without a separator: {meta:?}"
        );
    }

    #[test]
    fn live_delivery_health_moves_from_catching_up_to_replay_equivalent() {
        use kuzushi_core::run_lifecycle::{CommittedRange, RunDeliveryHealth};
        let first = lifecycle_notice("run-catchup", 1, None, "first");
        let second = lifecycle_notice("run-catchup", 2, Some(first.event_hash.clone()), "second");
        let mut session = ActivitySession::new("run-catchup");
        session.observe_committed_range(CommittedRange {
            first_seq: 1,
            through_seq: 2,
        });

        assert_eq!(
            session.effective_run_lifecycle_health().delivery,
            RunDeliveryHealth::CatchingUp {
                applied_seq: 0,
                durable_seq: 2,
            }
        );
        session.apply_run_item(first.clone()).unwrap();
        assert_eq!(
            session.effective_run_lifecycle_health().delivery,
            RunDeliveryHealth::CatchingUp {
                applied_seq: 1,
                durable_seq: 2,
            }
        );
        session.apply_run_item(second.clone()).unwrap();
        assert_eq!(
            session.effective_run_lifecycle_health().delivery,
            RunDeliveryHealth::Current { through_seq: 2 }
        );
        assert_eq!(
            session.run_projection,
            kuzushi_core::run_lifecycle::reduce_run_items([first, second])
        );
    }

    #[test]
    fn catchup_and_integrity_corruption_remain_distinct_health_axes() {
        use kuzushi_core::run_lifecycle::{CommittedRange, ProjectionHealth, RunDeliveryHealth};
        let mut session = ActivitySession::new("run-corrupt");
        session.observe_committed_range(CommittedRange {
            first_seq: 1,
            through_seq: 1,
        });
        let gap = lifecycle_notice("run-corrupt", 2, None, "gap");

        assert!(session.apply_run_item(gap).is_err());
        let health = session.effective_run_lifecycle_health();
        assert!(matches!(
            health.integrity,
            ProjectionHealth::Degraded { .. }
        ));
        assert_eq!(
            health.delivery,
            RunDeliveryHealth::CatchingUp {
                applied_seq: 0,
                durable_seq: 2,
            }
        );
    }

    #[test]
    fn structured_writer_fault_is_exposed_on_the_durability_axis() {
        use kuzushi_core::run_lifecycle::{
            PersistenceFailureStage, RunDurabilityHealth, RunItemWriterFault, SafeText,
        };
        let mut session = ActivitySession::new("run-fault");
        session.record_run_item_writer_fault(RunItemWriterFault {
            stage: PersistenceFailureStage::Sync,
            last_durable_seq: 4,
            detail: SafeText::operator_visible("disk sync failed"),
            execution_may_have_occurred: true,
        });

        assert!(matches!(
            session.effective_run_lifecycle_health().durability,
            RunDurabilityHealth::Failed {
                last_durable_seq: 4,
                stage: PersistenceFailureStage::Sync,
                execution_may_have_occurred: true,
                ..
            }
        ));
    }

    #[test]
    fn derivative_fault_never_forges_canonical_delivery_failure() {
        use kuzushi_core::run_lifecycle::{
            CommittedRange, RunDeliveryHealth, RunDerivativeDeliveryHealth,
            RunItemDeliveryFailureStage, RunItemDeliveryFault, SafeText,
        };
        let item = lifecycle_notice("run-derivative", 1, None, "committed");
        let mut session = ActivitySession::new("run-derivative");
        session.observe_committed_range(CommittedRange {
            first_seq: 1,
            through_seq: 1,
        });
        session.apply_run_item(item).unwrap();
        session.record_run_item_delivery_fault(RunItemDeliveryFault {
            stage: RunItemDeliveryFailureStage::CompatibilityProjection,
            applied_seq: 0,
            durable_seq: 1,
            detail: SafeText::operator_visible("compatibility write failed"),
        });

        let failed = session.effective_run_lifecycle_health();
        assert_eq!(
            failed.delivery,
            RunDeliveryHealth::Current { through_seq: 1 }
        );
        assert!(matches!(
            failed.derivative_delivery,
            RunDerivativeDeliveryHealth::Failed { applied_seq: 0, .. }
        ));
        session.observe_derivative_range(CommittedRange {
            first_seq: 1,
            through_seq: 1,
        });
        assert_eq!(
            session.effective_run_lifecycle_health().derivative_delivery,
            RunDerivativeDeliveryHealth::Current { through_seq: 1 }
        );
    }

    fn lifecycle_notice(
        run_id: &str,
        seq: u64,
        previous_hash: Option<String>,
        message: &str,
    ) -> kuzushi_core::run_lifecycle::RunItemEnvelopeV1 {
        use kuzushi_core::run_lifecycle::{
            DiagnosticLevel, RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemV1,
            SafeText,
        };
        RunItemEnvelopeV1::new(
            seq,
            RunId::parse(run_id).unwrap(),
            RunItemId::new(),
            RunItemSource::Persistence,
            RunItemV1::DiagnosticNotice {
                level: DiagnosticLevel::Info,
                message: SafeText::operator_visible(message),
            },
            previous_hash,
        )
        .unwrap()
    }

    #[test]
    fn phase_origin_does_not_mint_an_effectful_attempt_identity() {
        let session = ActivitySession::for_phase("advisory", WorkflowPhase::Scan);

        assert_eq!(session.origin_phase, Some(WorkflowPhase::Scan));
        assert!(session.phase_attempt_id.is_none());
    }

    #[test]
    fn continued_run_focus_sequence_accumulates_cost_and_run_count() {
        let mut first = ActivitySession::new("run-1");
        first.apply_step(
            RunTraceStep::new(1, "reasoning", "model call complete")
                .with_latency_ms(Some(1))
                .with_cost_usd(Some(0.25))
                .with_model_metadata("test:model", "test", "prompt-hash"),
        );
        let mut second = ActivitySession::new("run-2");
        second.continue_run_focus_sequence_from(&first);
        second.apply_step(
            RunTraceStep::new(2, "reasoning", "model call complete")
                .with_latency_ms(Some(1))
                .with_cost_usd(Some(0.50))
                .with_model_metadata("test:model", "test", "prompt-hash"),
        );
        second.mark_run_focus_terminal_pending("completed");

        let receipt = second.run_focus_receipt.expect("sequence receipt");
        assert_eq!(receipt.run_count, 2);
        assert_eq!(receipt.cost, "$0.7500");
    }

    #[test]
    fn continued_run_focus_sequence_preserves_the_ordered_plan_checklist() {
        let mut first = ActivitySession::new("run-context");
        first.seed_task_sequence([
            "context:build".to_string(),
            "entry-points:extract".to_string(),
        ]);
        first.mark_task_done("context:build");

        let mut second = ActivitySession::new("run-entry-points");
        second.continue_run_focus_sequence_from(&first);

        let rows = second.ordered_task_rows();
        assert_eq!(
            rows.iter()
                .map(|row| row.task_id.as_str())
                .collect::<Vec<_>>(),
            vec!["context:build", "entry-points:extract"]
        );
        assert_eq!(rows[0].state, DagTaskState::Done);
        assert_eq!(rows[1].state, DagTaskState::Queued);
    }

    #[test]
    fn planned_tasks_sharing_a_tool_keep_distinct_activity_rows() {
        let mut session = ActivitySession::new("run-stride");
        session.seed_task_sequence([
            "threat-model:build[stride]".to_string(),
            "threat-model:build[pasta]".to_string(),
        ]);
        session.bind_tool_task(
            "threat-model:build",
            "threat-model:build[stride]".to_string(),
        );
        session.mark_task_partial("threat-model:build", "no topology");

        assert_eq!(
            session.tasks["threat-model:build[stride]"].state,
            DagTaskState::Partial
        );
        assert_eq!(
            session.tasks["threat-model:build[pasta]"].state,
            DagTaskState::Queued
        );
        assert!(!session.tasks.contains_key("threat-model:build"));
    }

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
        // Seed a node keyed by its tool name (as the legacy adapter does).
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
    fn canceling_marks_never_started_rows_skipped() {
        let mut session = ActivitySession::new("r-1");
        session.tasks.insert(
            "codeql:scan".to_string(),
            DagTaskRow::queued("codeql:scan".to_string(), "codeql".to_string(), Vec::new()),
        );

        session.mark_active_tasks_canceling();

        let row = session.tasks.get("codeql:scan").unwrap();
        assert_eq!(row.state, DagTaskState::Skipped);
        assert_eq!(row.last_label, "not run after cancel");
        assert!(row.started_at.is_none());
        assert!(row.completed_at.is_some());
    }

    #[test]
    fn late_completion_does_not_flip_a_canceled_task_to_done() {
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

        // Most tools don't honor mid-flight cancel: the worker still returns a
        // result, which drives mark_task_done and can also emit late trace
        // steps. The canceled row must stay canceled.
        session.mark_task_done("triage:run");
        session.apply_step(
            RunTraceStep::new(2, "done", "triage complete")
                .with_module_id("triage")
                .with_verb("run"),
        );
        session.apply_step(
            RunTraceStep::new(3, "tool", "late failure")
                .with_module_id("triage")
                .with_verb("run")
                .with_severity("danger"),
        );

        let row = session.tasks.get("triage:run").unwrap();
        assert_eq!(row.state, DagTaskState::Canceled);
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
        assert_eq!(session.step_task_ids.len(), ACTIVITY_FEED_RING_CAPACITY);
        assert!(!session.step_task_ids.contains_key(&0));
        assert!(session
            .step_task_ids
            .contains_key(&(ACTIVITY_FEED_RING_CAPACITY + 4)));
        // Per-task aggregates survive eviction.
        let row = session.tasks.get("semgrep:scan").unwrap();
        assert_eq!(row.steps_done, ACTIVITY_FEED_RING_CAPACITY + 5);
    }

    #[test]
    fn task_rows_are_capped_and_evict_terminal_rows_first() {
        let mut session = ActivitySession::new("r-1");
        for i in 0..ACTIVITY_TASK_ROW_CAPACITY {
            session.apply_step(
                RunTraceStep::new(i, "tool", format!("tool {i} started"))
                    .with_module_id(format!("tool-{i:04}"))
                    .with_verb("scan"),
            );
        }
        session.tasks.get_mut("tool-0000:scan").unwrap().state = DagTaskState::Done;

        session.apply_step(
            RunTraceStep::new(ACTIVITY_TASK_ROW_CAPACITY, "tool", "new tool started")
                .with_module_id("tool-new")
                .with_verb("scan"),
        );

        assert_eq!(session.tasks.len(), ACTIVITY_TASK_ROW_CAPACITY);
        assert!(!session.tasks.contains_key("tool-0000:scan"));
        assert!(session.tasks.contains_key("tool-new:scan"));
        assert!(!session
            .step_task_ids
            .values()
            .any(|task_id| task_id == "tool-0000:scan"));
    }

    #[test]
    fn hidden_subsystem_states_are_capped_but_total_tracks_observed_tasks() {
        let mut session = ActivitySession::new("r-1");
        for i in 0..ACTIVITY_HIDDEN_TASK_STATE_CAPACITY {
            session.apply_step(
                RunTraceStep::new(i, "done", format!("hidden {i} done"))
                    .with_module_id("pipeline")
                    .with_verb(format!("task-{i:04}")),
            );
        }

        session.apply_step(
            RunTraceStep::new(
                ACTIVITY_HIDDEN_TASK_STATE_CAPACITY,
                "tool",
                "new hidden task",
            )
            .with_module_id("pipeline")
            .with_verb("task-new"),
        );

        assert_eq!(
            session.subsystem_aggregate.hidden_task_states.len(),
            ACTIVITY_HIDDEN_TASK_STATE_CAPACITY
        );
        assert_eq!(
            session.subsystem_aggregate.total_count,
            ACTIVITY_HIDDEN_TASK_STATE_CAPACITY + 1
        );
        assert_eq!(session.subsystem_aggregate.active_count, 1);
        assert!(session
            .subsystem_aggregate
            .hidden_task_states
            .contains_key("pipeline:task-new"));
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
                .with_cost_usd(Some(0.0123))
                .with_model_metadata("test:model", "test", "prompt-hash"),
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
    fn rolled_up_child_danger_step_does_not_fail_parent_task() {
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
            RunTraceStep::new(3, "refused", "retryable model call failed")
                .with_module_id("agentic-sast")
                .with_verb("query")
                .with_parent_step(2)
                .with_severity("danger"),
        );

        let row = session.tasks.get("agentic-sast:scan").unwrap();
        assert_eq!(row.state, DagTaskState::Active);
        assert!(row.details.iter().any(|detail| {
            detail.label == "retryable model call failed"
                && detail.state == DagTaskDetailState::Failing
        }));
    }

    #[test]
    fn terminal_success_sweeps_incomplete_rows() {
        let mut session = ActivitySession::new("r-1");
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".to_string(), "triage".to_string(), Vec::new()),
        );
        session.tasks.insert(
            "verify:finding".to_string(),
            DagTaskRow::queued(
                "verify:finding".to_string(),
                "verify".to_string(),
                vec!["triage:run".to_string()],
            ),
        );
        session.apply_step(
            RunTraceStep::new(1, "tool", "triage start")
                .with_module_id("triage")
                .with_verb("run"),
        );

        session.mark_incomplete_tasks_after_success(ActivityTerminalContext::Run);

        assert_eq!(
            session.tasks.get("triage:run").unwrap().state,
            DagTaskState::Done
        );
        assert_eq!(
            session.tasks.get("verify:finding").unwrap().state,
            DagTaskState::Skipped
        );
    }

    #[test]
    fn settled_session_elapsed_time_uses_terminal_timestamp() {
        let mut session = ActivitySession::new("r-settled");
        session.started_at = Instant::now() - std::time::Duration::from_secs(10);
        session.completed_at = Some(session.started_at + std::time::Duration::from_secs(3));

        assert_eq!(session.elapsed_secs(), 3);
    }

    #[test]
    fn terminal_failure_sweeps_incomplete_rows() {
        let mut session = ActivitySession::new("r-1");
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".to_string(), "triage".to_string(), Vec::new()),
        );
        session.tasks.insert(
            "verify:finding".to_string(),
            DagTaskRow::queued(
                "verify:finding".to_string(),
                "verify".to_string(),
                vec!["triage:run".to_string()],
            ),
        );
        session.apply_step(
            RunTraceStep::new(1, "tool", "triage start")
                .with_module_id("triage")
                .with_verb("run"),
        );

        session.mark_incomplete_tasks_after_failure();

        assert_eq!(
            session.tasks.get("triage:run").unwrap().state,
            DagTaskState::Failing
        );
        assert_eq!(
            session.tasks.get("verify:finding").unwrap().state,
            DagTaskState::Skipped
        );
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
