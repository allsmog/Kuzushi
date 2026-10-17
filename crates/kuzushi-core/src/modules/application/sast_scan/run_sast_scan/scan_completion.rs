//! Publish Scan coverage only after final source verification has settled.
use super::*;
use crate::module_result::{tool_result_status, ToolResultStatus};

pub(super) fn publish(
    ctx: &ToolExecutionContext<'_>,
    run: &str,
    findings_count: usize,
    artifacts: &SastRunArtifacts,
    result: &mut Value,
) -> Result<()> {
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "Scan was stopped before coverage publication"
    );
    let store = sast_store(ctx)?;
    let complete = tool_result_status(result) == ToolResultStatus::Completed;
    let receipt = finalize_receipt(result, complete)?;
    if !complete {
        store.record_run_finished(run, "partial", findings_count)?;
    }
    let scan = receipt.scan.context("Final Scan coverage is unavailable")?;
    record_sast_scan_stage(artifacts, receipt.outcome, receipt.run_refs, scan.clone())?;
    super::super::reconcile_completed_scan::after_receipt(store, run, receipt.outcome, &scan)
}

fn finalize_receipt(result: &mut Value, complete: bool) -> Result<PhaseStageReceipt> {
    let stages = result
        .pointer_mut("/data/phaseStages")
        .and_then(Value::as_array_mut)
        .context("Final Scan phase stages are unavailable")?;
    let stage = stages
        .iter_mut()
        .find(|stage| stage.get("phase").and_then(Value::as_str) == Some("scan"))
        .context("Final result has no Scan coverage")?;
    let mut receipt: PhaseStageReceipt = serde_json::from_value(stage.clone())?;
    if !complete {
        receipt.outcome = PhaseStageOutcome::Partial;
    }
    *stage = json!(receipt);
    if !complete {
        align_partial_output(result);
    }
    Ok(receipt)
}

fn align_partial_output(result: &mut Value) {
    let Some(output) = result.get("output").and_then(Value::as_str) else {
        return;
    };
    let lines = output.lines().map(str::to_string).collect::<Vec<_>>();
    result["output"] = json!(sast_terminal_output(&lines, true));
}

#[cfg(test)]
mod tests;
