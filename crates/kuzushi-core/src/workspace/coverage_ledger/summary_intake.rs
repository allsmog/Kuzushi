use super::store::{BaselineRow, CoverageLedger};
use crate::modules::{tool_phase, WorkflowPhase};
use crate::run_artifacts::RunSummary;
use crate::workspace::ROOT_SCOPE_ID;
use anyhow::Result;
use std::path::Path;

/// Record historical Git metadata from a persisted run summary.
///
/// Only completed phase-bearing summaries with Git provenance are recorded.
/// Legacy rows do not validate selected scope, exact content or accepted
/// context; callers must not interpret them as complete coverage receipts.
pub fn record_baseline_from_summary(
    target: &Path,
    summary: &RunSummary,
) -> Result<Option<BaselineRow>> {
    let Some(row) = baseline_candidate(summary) else {
        return Ok(None);
    };
    CoverageLedger::open(target)?.record_baseline(&row)?;
    Ok(Some(row))
}

fn baseline_candidate(summary: &RunSummary) -> Option<BaselineRow> {
    if summary.status != "completed" {
        return None;
    }
    let revision = summary.target_git.clone()?;
    let phase = summary_phase(summary)?;
    Some(BaselineRow {
        scope_id: ROOT_SCOPE_ID.to_string(),
        phase,
        mode: "default".to_string(),
        run_id: summary.run_id.clone(),
        revision,
        ts_unix: baseline_timestamp(summary),
    })
}

fn summary_phase(summary: &RunSummary) -> Option<WorkflowPhase> {
    match summary.tool.as_deref() {
        Some(tool) => tool_phase(tool),
        None if summary.kind == "scan" => Some(WorkflowPhase::Scan),
        None => None,
    }
}

fn baseline_timestamp(summary: &RunSummary) -> i64 {
    summary.completed_at_unix.unwrap_or(summary.started_at_unix) as i64
}
