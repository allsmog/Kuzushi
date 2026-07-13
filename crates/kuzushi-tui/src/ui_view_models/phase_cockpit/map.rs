use super::{ActivityTaskCountModel, MapArtifactMetric, MapConsoleRow, MapPhaseModel};
use crate::{ActivitySession, DagTaskState, RecordedTraceEvent, ShellApp};
use kuzushi_core::WorkflowPhase;

const MAP_CONSOLE_ROW_LIMIT: usize = 200;

pub(super) fn map_phase_model(app: &ShellApp) -> MapPhaseModel {
    let artifact_metrics = artifact_metrics(app);
    let Some(session) = app.activity() else {
        return empty_map_phase_model(app, artifact_metrics);
    };
    let skip = session.events.len().saturating_sub(MAP_CONSOLE_ROW_LIMIT);
    let console = session
        .events
        .iter()
        .skip(skip)
        .map(map_console_row)
        .collect();
    let run_cost = session.runtime_cost_report();
    MapPhaseModel {
        run_id: Some(session.run_id.clone()),
        elapsed_secs: Some(session.elapsed_secs()),
        run_cost_usd: run_cost.as_ref().map_or(0.0, |cost| cost.observed_usd()),
        run_cost_complete: run_cost.as_ref().is_ok_and(|cost| cost.is_complete()),
        run_cost_invalid: run_cost.is_err(),
        task_counts: activity_task_counts(session),
        console,
        hidden_console_rows: skip,
        artifact_metrics,
        empty_hint: map_console_empty_hint(session),
    }
}

fn map_console_empty_hint(session: &ActivitySession) -> Option<&'static str> {
    if !session.events.is_empty() {
        return None;
    }
    if session.completed_at.is_some() {
        return Some("activity completed without trace events");
    }
    Some("activity is live; waiting for the first trace event")
}

fn empty_map_phase_model(
    app: &ShellApp,
    artifact_metrics: Vec<MapArtifactMetric>,
) -> MapPhaseModel {
    let empty_hint = match super::journey_model(app).map(|journey| journey.current) {
        Some(WorkflowPhase::Map) | None => "no map activity yet — use `next` to start",
        Some(_) => "no map activity was recorded for this workspace",
    };
    MapPhaseModel {
        run_id: None,
        elapsed_secs: None,
        run_cost_usd: 0.0,
        run_cost_complete: true,
        run_cost_invalid: false,
        task_counts: ActivityTaskCountModel::default(),
        console: Vec::new(),
        hidden_console_rows: 0,
        artifact_metrics,
        empty_hint: Some(empty_hint),
    }
}

fn artifact_metrics(app: &ShellApp) -> Vec<MapArtifactMetric> {
    let mut metrics = Vec::new();
    if let Some(files) = app.domain().context_view().files_indexed {
        metrics.push(metric("files", files));
    }
    let dfd = super::super::dfd_model(app);
    if dfd.empty_hint.is_none() {
        metrics.push(MapArtifactMetric {
            label: "dfd",
            value: format!("{}n/{}f", dfd.nodes.len(), dfd.flows.len()),
        });
    }
    push_nonzero(&mut metrics, "findings", app.findings().len());
    push_nonzero(&mut metrics, "chains", app.domain().exploit_chains().len());
    metrics
}

fn metric(label: &'static str, value: u64) -> MapArtifactMetric {
    MapArtifactMetric {
        label,
        value: value.to_string(),
    }
}

fn push_nonzero(metrics: &mut Vec<MapArtifactMetric>, label: &'static str, value: usize) {
    if value > 0 {
        metrics.push(MapArtifactMetric {
            label,
            value: value.to_string(),
        });
    }
}

fn map_console_row(event: &RecordedTraceEvent) -> MapConsoleRow {
    let cost = event.step.cost_usd.and_then(|cost| {
        kuzushi_core::runtime::RuntimeCost::from_usd(cost, "map console cost")
            .ok()
            .map(kuzushi_core::runtime::RuntimeCost::usd)
    });
    MapConsoleRow {
        sequence: event.step.n,
        started_at_ms: event.step.started_at_ms,
        kind: event.step.kind.clone(),
        label: event.step.label.clone(),
        module: event.step.module_id.clone(),
        verb: event.step.verb.clone(),
        severity: event.step.severity.clone(),
        latency_ms: event.step.latency_ms,
        cost_usd: cost,
        cost_invalid: event.step.cost_usd.is_some() && cost.is_none(),
    }
}

fn activity_task_counts(session: &ActivitySession) -> ActivityTaskCountModel {
    ActivityTaskCountModel {
        total: session.tasks.len(),
        queued: task_count(session, DagTaskState::Queued),
        active: task_count(session, DagTaskState::Active),
        canceling: task_count(session, DagTaskState::Canceling),
        completed: task_count(session, DagTaskState::Done),
        failed: task_count(session, DagTaskState::Failing),
        blocked: task_count(session, DagTaskState::Blocked),
        canceled: task_count(session, DagTaskState::Canceled),
        skipped: task_count(session, DagTaskState::Skipped),
    }
}

fn task_count(session: &ActivitySession, state: DagTaskState) -> usize {
    session
        .tasks
        .values()
        .filter(|row| row.state == state)
        .count()
}
