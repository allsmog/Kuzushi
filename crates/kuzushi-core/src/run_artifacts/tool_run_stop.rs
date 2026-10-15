//! Record a caller-owned execution stop before orphan recovery can race it.
use super::{load_run_summary_without_repair, ToolRunRecord};
use crate::run_lifecycle::RunItemStatus;
use anyhow::Result;

/// Keep an existing terminal result. A child stopped before publishing its start
/// has no run to finalize. Provider reservations are never settled or refunded here.
pub fn record_tool_run_stop(
    record: ToolRunRecord<'_>,
    disposition: RunItemStatus,
    stop_execution: impl FnOnce() -> Result<()>,
) -> Result<Option<super::RunSummary>> {
    let (status, reason) = stop_reason(disposition)?;
    let _guard = super::run_ledger::acquire_run_terminal_lock(record.target, record.run_id)?;
    stop_execution()?;
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
    super::tool_run_record::record_stopped_under_lock(record, status, reason)?;
    load_run_summary_without_repair(record.target, record.run_id).map(Some)
}

fn stop_reason(disposition: RunItemStatus) -> Result<(&'static str, &'static str)> {
    match disposition {
        RunItemStatus::Canceled => Ok(("canceled", "operator stopped the campaign job")),
        RunItemStatus::Interrupted => Ok(("interrupted", "campaign job supervision stopped")),
        _ => anyhow::bail!("execution stop must be canceled or interrupted"),
    }
}

#[cfg(all(test, unix))]
mod tests;
