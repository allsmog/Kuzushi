//! Reap an owned child and publish its stop before orphan recovery can race it.
use super::{load_run_summary_without_repair, ToolRunRecord};
use crate::scan::{CancellationDisposition, RegisteredChild};
use anyhow::{Context, Result};

/// Keep an existing terminal result. A child stopped before publishing its start
/// has no run to finalize. Provider reservations are never settled or refunded here.
pub fn stop_tool_run_child(
    record: ToolRunRecord<'_>,
    child: &RegisteredChild,
    disposition: CancellationDisposition,
) -> Result<Option<super::RunSummary>> {
    let _guard = super::run_ledger::acquire_run_terminal_lock(record.target, record.run_id)?;
    child
        .kill_and_wait()
        .context("Could not stop campaign job child")?;
    let path = super::checked_run_artifact_path(record.target, record.run_id, "run.json")?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let summary = super::run_summary_store::recover_published_terminal_under_lock(
        record.target,
        load_run_summary_without_repair(record.target, record.run_id)?,
    )?;
    if summary.status != "running" {
        return Ok(Some(summary));
    }
    let (status, reason) = stop_reason(disposition);
    super::tool_run_record::record_stopped_under_lock(record, status, reason)?;
    load_run_summary_without_repair(record.target, record.run_id).map(Some)
}

fn stop_reason(disposition: CancellationDisposition) -> (&'static str, &'static str) {
    match disposition {
        CancellationDisposition::Canceled => ("canceled", "operator stopped the campaign job"),
        CancellationDisposition::Interrupted => ("interrupted", "campaign job supervision stopped"),
    }
}

#[cfg(all(test, unix))]
mod tests;
