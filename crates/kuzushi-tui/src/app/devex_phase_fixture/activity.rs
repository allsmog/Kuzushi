use super::*;

pub(super) fn seed(app: &mut ShellApp, lifecycle: PhaseFixtureLifecycle) {
    seed_budget(app);
    let started_at = Instant::now() - Duration::from_secs(42);
    let mut activity = ActivitySession::for_phase("map-phase-run", WorkflowPhase::Map);
    activity.started_at = started_at;
    seed_trace(&mut activity);
    seed_tasks(&mut activity, lifecycle, started_at);
    if lifecycle == PhaseFixtureLifecycle::Settled {
        activity.completed_at = Some(started_at + Duration::from_secs(42));
    }
    app.set_activity(Some(activity));
}

fn seed_budget(app: &mut ShellApp) {
    let current = app.session().session_cost_usd();
    if current < 0.37 {
        app.record_cost(0.37 - current);
    }
    app.session_mut().set_session_budget_usd(Some(2.0));
}

fn seed_tasks(
    activity: &mut ActivitySession,
    lifecycle: PhaseFixtureLifecycle,
    started_at: Instant,
) {
    activity.tasks.clear();
    let context_state = match lifecycle {
        PhaseFixtureLifecycle::Live => DagTaskState::Active,
        PhaseFixtureLifecycle::Settled => DagTaskState::Done,
    };
    let context = task_row("context:build", "context", context_state, 0.12, started_at);
    let inventory = task_row(
        "repository-inventory:build",
        "repository-inventory",
        DagTaskState::Done,
        0.03,
        started_at,
    );
    activity.tasks.insert(context.task_id.clone(), context);
    activity.tasks.insert(inventory.task_id.clone(), inventory);
}

fn task_row(
    task_id: &str,
    module_id: &str,
    state: DagTaskState,
    cost_usd: f64,
    started_at: Instant,
) -> DagTaskRow {
    let mut row = DagTaskRow::queued(task_id.to_string(), module_id.to_string(), Vec::new());
    row.state = state;
    row.started_at = Some(started_at);
    row.completed_at =
        (state == DagTaskState::Done).then_some(started_at + Duration::from_secs(18));
    row.steps_done = usize::from(task_id == "context:build") * 3;
    row.cost_usd = cost_usd;
    row.last_label = "phase reference projection".to_string();
    row
}

fn seed_trace(activity: &mut ActivitySession) {
    use kuzushi_core::run_lifecycle::{RunCallId, RunItemId};
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    for item in fixture_call_items() {
        apply_trace_item(activity, item_id, Some(call_id), item);
    }
    for label in fixture_reasoning_summaries() {
        apply_trace_item(activity, RunItemId::new(), None, reasoning_item(label));
    }
}

fn fixture_call_items() -> Vec<kuzushi_core::run_lifecycle::RunItemV1> {
    use kuzushi_core::run_lifecycle::*;
    vec![
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("context:build"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"phase reference"),
            safe_option_names: Vec::new(),
        },
        RunItemV1::ToolCallStarted {
            tool_name: SafeText::operator_visible("context:build"),
            runtime: Some(SafeText::operator_visible("native")),
            model: None,
        },
        RunItemV1::ToolCallProgress {
            message: SafeText::operator_visible("Indexing repository files"),
            completed: Some(421),
            total: Some(832),
        },
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Completed,
            cost: kuzushi_core::runtime::RuntimeCostReport::known(
                kuzushi_core::runtime::RuntimeCost::ZERO,
            ),
            result_artifact: None,
            preview: vec![SafeText::operator_visible("3 entrypoints · 2 trust zones")],
            warning_count: 0,
            error_count: 0,
        },
    ]
}

fn fixture_reasoning_summaries() -> [&'static str; 6] {
    [
        "Identified public entrypoints",
        "Mapped external client",
        "Mapped application API",
        "Mapped orders data store",
        "Recorded edge trust boundary",
        "Recorded data trust boundary",
    ]
}

fn reasoning_item(label: &str) -> kuzushi_core::run_lifecycle::RunItemV1 {
    kuzushi_core::run_lifecycle::RunItemV1::SafeReasoningSummary {
        text: kuzushi_core::run_lifecycle::SafeText::operator_visible(label),
        redaction_policy_version: 1,
    }
}

fn apply_trace_item(
    activity: &mut ActivitySession,
    item_id: kuzushi_core::run_lifecycle::RunItemId,
    call_id: Option<kuzushi_core::run_lifecycle::RunCallId>,
    item: kuzushi_core::run_lifecycle::RunItemV1,
) {
    use kuzushi_core::run_lifecycle::*;
    let seq = activity.run_projection.last_committed_seq + 1;
    let envelope = RunItemEnvelopeV1::new(
        seq,
        RunId::parse(&activity.run_id).expect("fixture run id"),
        item_id,
        RunItemSource::Workflow,
        item,
        activity.run_projection.last_event_hash.clone(),
    )
    .expect("fixture lifecycle item");
    let envelope = match call_id {
        Some(call_id) => envelope.with_call(call_id).expect("fixture call identity"),
        None => envelope,
    };
    activity
        .apply_run_item(envelope)
        .expect("apply fixture lifecycle item");
}
