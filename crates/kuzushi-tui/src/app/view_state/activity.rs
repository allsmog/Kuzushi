use crate::app::{phase_attempt_outcome_from_label, phase_result_policy};
use kuzushi_core::runtime::{RuntimeCost, RuntimeCostReport};
pub use kuzushi_core::workflow_attempts::PhaseResultAction as RunFocusResultAction;
use kuzushi_core::WorkflowPhase;
use std::collections::BTreeMap;
use std::time::Instant;

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
    /// The earlier run in this Run Focus sequence that owns the row, when
    /// it was inherited across a run boundary. `None` = the focused run.
    /// Header counters and status chips must never attribute a prior run's
    /// failures to the run on screen.
    pub prior_run_ref: Option<String>,
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
            prior_run_ref: None,
        }
    }

    pub(crate) fn operator_name(&self) -> &str {
        if looks_like_typed_task_id(&self.task_id) {
            &self.module_id
        } else {
            &self.task_id
        }
    }
}

fn looks_like_typed_task_id(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| value.as_bytes().get(index) == Some(&b'-'))
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

/// Live state for the Activity view. Created at scan/run start, updated from
/// committed lifecycle items on every tick, and rendered by the activity view.
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
    pub subsystem_aggregate: SubsystemAggregate,
    last_run_item_at: Option<Instant>,
    open_model_call_started_at: Option<Instant>,
    runtime_cost: RuntimeCostReport,
    cost_accounting_error: Option<String>,
    durable_run_item_seq: u64,
    run_item_writer_fault: Option<kuzushi_core::run_lifecycle::RunItemWriterFault>,
    run_item_delivery_failure: Option<kuzushi_core::run_lifecycle::RunItemDeliveryFault>,
    run_item_derivative_tracking: bool,
    run_item_derivative_seq: u64,
    run_item_derivative_failure: Option<kuzushi_core::run_lifecycle::RunItemDeliveryFault>,
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
    /// One-line receipt WITHOUT cost: on Run Focus the header owns the cost
    /// line, and this summary restating it was the third cost on one screen.
    /// Surfaces that need cost (the phase card) append `self.cost` explicitly.
    pub fn summary(&self) -> String {
        format!(
            "{} · {} run{} · {}s",
            self.outcome,
            self.run_count,
            if self.run_count == 1 { "" } else { "s" },
            self.elapsed_secs,
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
            subsystem_aggregate: SubsystemAggregate::default(),
            last_run_item_at: None,
            open_model_call_started_at: None,
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
        // Inherited rows keep their history visible but belong to the run
        // that produced them: counters and status chips for THIS run must
        // not absorb a previous run's failures (item 5c).
        for row in self.tasks.values_mut() {
            if row.prior_run_ref.is_none() {
                row.prior_run_ref = Some(prior.run_id.clone());
            }
        }
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

    /// Force a tool's semantic row to `Done` when a mode-specific terminal
    /// receipt arrives before the final committed lifecycle item is drained.
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

    pub fn apply_run_item(
        &mut self,
        item: kuzushi_core::run_lifecycle::RunItemEnvelopeV1,
    ) -> anyhow::Result<()> {
        let observed_at = Instant::now();
        let starts_model_call = matches!(
            &item.item,
            kuzushi_core::run_lifecycle::RunItemV1::ModelCallStarted { .. }
        );
        self.durable_run_item_seq = self.durable_run_item_seq.max(item.seq);
        let delta = self.run_projection.apply_committed(item)?;
        if starts_model_call {
            self.open_model_call_started_at.get_or_insert(observed_at);
        }
        if !self.has_running_model_call() {
            self.open_model_call_started_at = None;
        }
        self.last_run_item_at = Some(observed_at);
        self.apply_projection_delta(&delta);
        Ok(())
    }

    fn has_running_model_call(&self) -> bool {
        use kuzushi_core::run_lifecycle::{CallKind, RunItemStatus};
        self.run_projection
            .calls
            .values()
            .any(|call| call.kind == CallKind::Model && call.status == RunItemStatus::Running)
    }

    pub(crate) fn event_count(&self) -> usize {
        self.run_projection.timeline.len()
    }

    pub(crate) fn last_run_item_at(&self) -> Option<Instant> {
        self.last_run_item_at
    }

    pub(crate) fn open_model_call_age(&self, now: Instant) -> Option<std::time::Duration> {
        self.open_model_call_started_at
            .and_then(|started_at| now.checked_duration_since(started_at))
    }

    #[cfg(test)]
    pub(crate) fn set_last_run_item_at_for_test(&mut self, observed_at: Instant) {
        self.last_run_item_at = Some(observed_at);
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

    /// Bind trace-minted rows for `tool_name` onto the ONE seeded planned row
    /// whose decoration-stripped id matches, regardless of which launch path
    /// started the tool — otherwise a plan-seeded `threat-model:build[stride]`
    /// row and the trace's `threat-model:build` row show as two tasks for one
    /// logical run. Ambiguous matches (two planned rows sharing a tool) never
    /// alias, and rows inherited from a prior run are out of scope (item 5c).
    pub(crate) fn alias_tool_to_unique_planned_row(&mut self, tool_name: &str) {
        let canonical = collapse_doubled_tail(tool_name);
        let mut matching = self.tasks.values().filter(|row| {
            row.prior_run_ref.is_none() && strip_task_decoration(&row.task_id) == canonical
        });
        let (Some(row), None) = (matching.next(), matching.next()) else {
            return;
        };
        let task_id = row.task_id.clone();
        if task_id != canonical {
            self.bind_tool_task(tool_name, task_id);
        }
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

fn row_can_cancel(row: &&mut DagTaskRow) -> bool {
    cancelable_task_state(row.state)
}

fn cancelable_task_state(state: DagTaskState) -> bool {
    matches!(
        state,
        DagTaskState::Queued | DagTaskState::Active | DagTaskState::Canceling
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
/// A planned row id minus its planner decoration (`tool[variant]` → `tool`).
fn strip_task_decoration(task_id: &str) -> &str {
    task_id.split('[').next().unwrap_or(task_id).trim_end()
}

pub(crate) fn collapse_doubled_tail(task_id: &str) -> String {
    let segments: Vec<&str> = task_id.split(':').collect();
    let len = segments.len();
    if len >= 2 && segments[len - 1] == segments[len - 2] {
        return segments[..len - 1].join(":");
    }
    task_id.to_string()
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
    row.last_label = typed_task_latest_label(projection, &task_id, task);
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

fn typed_task_latest_label(
    projection: &kuzushi_core::run_lifecycle::RunProjection,
    task_id: &str,
    task: &kuzushi_core::run_lifecycle::TaskProjection,
) -> String {
    if task.status == kuzushi_core::run_lifecycle::RunItemStatus::Running {
        if let Some(progress) = latest_task_progress(projection, task_id) {
            return progress;
        }
    }
    task.detail.as_ref().map_or_else(
        || typed_status_label(task.status).to_string(),
        ToString::to_string,
    )
}

fn latest_task_progress(
    projection: &kuzushi_core::run_lifecycle::RunProjection,
    task_id: &str,
) -> Option<String> {
    projection.timeline.iter().rev().find_map(|envelope| {
        if !envelope.task_id.is_some_and(|id| id.to_string() == task_id) {
            return None;
        }
        let kuzushi_core::run_lifecycle::RunItemV1::ToolCallProgress {
            message,
            completed,
            total,
        } = &envelope.item
        else {
            return None;
        };
        Some(typed_progress_label(message, *completed, *total))
    })
}

fn typed_progress_label(
    message: &kuzushi_core::run_lifecycle::SafeText,
    completed: Option<u64>,
    total: Option<u64>,
) -> String {
    match (completed, total) {
        (Some(completed), Some(total)) => format!("{message} · {completed}/{total}"),
        _ => message.to_string(),
    }
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
        .call_order
        .iter()
        .filter_map(|call_id| projection.calls.get(call_id).map(|call| (*call_id, call)))
        .filter(|(_, call)| call.task_id.is_some_and(|id| id.to_string() == task_id))
        .rev()
        .take(ACTIVITY_TASK_DETAIL_CAPACITY)
        .map(|(call_id, call)| DagTaskDetail {
            label: call.label.to_string(),
            kind: match call.kind {
                kuzushi_core::run_lifecycle::CallKind::Tool => "tool",
                kuzushi_core::run_lifecycle::CallKind::Model => "model",
            }
            .to_string(),
            state: typed_detail_state(call.status),
            meta: typed_call_meta(projection, call_id, call),
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn typed_call_meta(
    projection: &kuzushi_core::run_lifecycle::RunProjection,
    call_id: kuzushi_core::run_lifecycle::RunCallId,
    call: &kuzushi_core::run_lifecycle::CallProjection,
) -> String {
    if call.status == kuzushi_core::run_lifecycle::RunItemStatus::Running {
        if let Some(progress) = projection.timeline.iter().rev().find_map(|envelope| {
            if envelope.call_id != Some(call_id) {
                return None;
            }
            let kuzushi_core::run_lifecycle::RunItemV1::ToolCallProgress {
                message,
                completed,
                total,
            } = &envelope.item
            else {
                return None;
            };
            Some(typed_progress_label(message, *completed, *total))
        }) {
            return format!(" · {progress}");
        }
    }
    typed_cost_meta(call.cost)
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
        Blocked => DagTaskState::Blocked,
        Failed | Interrupted => DagTaskState::Failing,
        Canceled => DagTaskState::Canceled,
    }
}

fn typed_detail_state(status: kuzushi_core::run_lifecycle::RunItemStatus) -> DagTaskDetailState {
    use kuzushi_core::run_lifecycle::RunItemStatus::*;
    match status {
        Pending | Running => DagTaskDetailState::Active,
        Completed | Skipped => DagTaskDetailState::Done,
        Partial | Blocked | Failed | Interrupted => DagTaskDetailState::Failing,
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
        Blocked => "blocked",
        Failed => "failed",
        Canceled => "canceled",
        Interrupted => "interrupted",
    }
}

fn typed_task_severity(status: kuzushi_core::run_lifecycle::RunItemStatus) -> Option<String> {
    use kuzushi_core::run_lifecycle::RunItemStatus::*;
    match status {
        Partial => Some("warn".to_string()),
        Blocked => Some("warn".to_string()),
        Failed | Interrupted => Some("danger".to_string()),
        _ => None,
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
    fn typed_active_task_exposes_its_latest_exact_substep() {
        let (projection, task_id) = active_task_projection();
        let task = &projection.tasks[&task_id];
        let row = typed_task_row(&projection, task_id.to_string(), task, None);

        assert_eq!(row.last_label, "Scanning repository files · 421/832");
        assert_eq!(row.details.len(), 1);
        assert!(row.details[0]
            .meta
            .contains("Scanning repository files · 421/832"));
    }

    fn active_task_projection() -> (
        kuzushi_core::run_lifecycle::RunProjection,
        kuzushi_core::run_lifecycle::RunTaskId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        let run_id = RunId::parse("run-active-substep").unwrap();
        let task_id = RunTaskId::new();
        let task_item_id = RunItemId::new();
        let call_item_id = RunItemId::new();
        let call_id = RunCallId::new();
        let mut items = Vec::new();
        push_active_work(&mut items, &run_id, task_id, task_item_id);
        push_active_call_start(&mut items, &run_id, task_id, call_id, call_item_id);
        push_active_progress(&mut items, &run_id, task_id, call_id, call_item_id);
        (reduce_run_items(items), task_id)
    }

    fn push_active_work(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
        task_item_id: kuzushi_core::run_lifecycle::RunItemId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        push_lifecycle_item(
            items,
            run_id,
            RunItemId::new(),
            RunItemV1::PlanUpdated {
                revision: 1,
                title: SafeText::operator_visible("Scan target"),
                status: RunItemStatus::Running,
                task_ids: vec![task_id],
            },
            None,
            None,
        );
        push_lifecycle_item(
            items,
            run_id,
            task_item_id,
            RunItemV1::TaskUpdated {
                title: SafeText::operator_visible("Run static analyzers"),
                status: RunItemStatus::Running,
                detail: None,
            },
            Some(task_id),
            None,
        );
    }

    fn push_active_call_start(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
        call_item_id: kuzushi_core::run_lifecycle::RunItemId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        push_lifecycle_item(
            items,
            run_id,
            call_item_id,
            RunItemV1::ToolCallRequested {
                tool_name: SafeText::operator_visible("semgrep:scan"),
                operation_fingerprint: OperationFingerprint::from_bytes(b"substep"),
                safe_option_names: Vec::new(),
            },
            Some(task_id),
            Some(call_id),
        );
        push_lifecycle_item(
            items,
            run_id,
            call_item_id,
            RunItemV1::ToolCallStarted {
                tool_name: SafeText::operator_visible("semgrep:scan"),
                runtime: None,
                model: None,
            },
            Some(task_id),
            Some(call_id),
        );
    }

    fn push_active_progress(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
        call_item_id: kuzushi_core::run_lifecycle::RunItemId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        push_lifecycle_item(
            items,
            run_id,
            call_item_id,
            RunItemV1::ToolCallProgress {
                message: SafeText::operator_visible("Scanning repository files"),
                completed: Some(421),
                total: Some(832),
            },
            Some(task_id),
            Some(call_id),
        );
    }

    fn push_lifecycle_item(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        item: kuzushi_core::run_lifecycle::RunItemV1,
        task_id: Option<kuzushi_core::run_lifecycle::RunTaskId>,
        call_id: Option<kuzushi_core::run_lifecycle::RunCallId>,
    ) {
        use kuzushi_core::run_lifecycle::{RunItemEnvelopeV1, RunItemSource};
        let previous = items.last().map(|item| item.event_hash.clone());
        let mut envelope = RunItemEnvelopeV1::new(
            items.len() as u64 + 1,
            run_id.clone(),
            item_id,
            RunItemSource::Workflow,
            item,
            previous,
        )
        .unwrap();
        if let Some(task_id) = task_id {
            envelope = envelope.with_task(task_id).unwrap();
        }
        if let Some(call_id) = call_id {
            envelope = envelope.with_call(call_id).unwrap();
        }
        items.push(envelope);
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
            stage: RunItemDeliveryFailureStage::StorageProjection,
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
        first.settle_runtime_cost(RuntimeCostReport::known(
            RuntimeCost::from_usd(0.25, "test").unwrap(),
        ));
        let mut second = ActivitySession::new("run-2");
        second.continue_run_focus_sequence_from(&first);
        second.settle_runtime_cost(RuntimeCostReport::known(
            RuntimeCost::from_usd(0.75, "test").unwrap(),
        ));
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
}
