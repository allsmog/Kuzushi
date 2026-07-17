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
    let rows = [
        ("tool-start", "indexing bounded source roots", 0.01),
        ("tool-progress", "reading workspace manifests", 0.01),
        ("tool-progress", "indexed 3 source files", 0.01),
        ("reasoning", "identifying public entrypoints", 0.02),
        ("tool-progress", "mapped external client", 0.01),
        ("tool-progress", "mapped application API", 0.01),
        ("tool-progress", "mapped orders data store", 0.01),
        ("reasoning", "recording edge trust boundary", 0.02),
        ("reasoning", "recording data trust boundary", 0.02),
        ("done", "3 entrypoints · 2 trust zones", 0.01),
    ];
    for (index, (kind, label, cost)) in rows.into_iter().enumerate() {
        activity.apply_step(trace_step(index + 1, kind, label, cost));
    }
}

fn trace_step(n: usize, kind: &str, label: &str, cost: f64) -> RunTraceStep {
    RunTraceStep {
        n,
        kind: kind.to_string(),
        label: label.to_string(),
        latency_ms: Some(18 + n as u64),
        cost_usd: Some(cost),
        observed_cost_usd: None,
        provider_spend_unresolved: false,
        call_attempted: Some(true),
        module_id: Some("context".to_string()),
        verb: Some("build".to_string()),
        parent_step: None,
        severity: None,
        started_at_ms: Some(1_720_580_088_000 + n as u64),
        model: Some("openai:gpt-5.4".to_string()),
        provider: Some("openai".to_string()),
        prompt_hash: Some(format!("fnv1a64:phase-{n}")),
    }
}
