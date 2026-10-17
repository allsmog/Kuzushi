//! Direct license results only establish their own target, engine and policy.
use super::*;

pub(super) fn validate(result: &Value, receipt: Option<&PhaseStageReceipt>) -> Result<()> {
    let Some(receipt) = receipt else {
        return Ok(());
    };
    let scan = receipt
        .scan
        .as_ref()
        .context("Direct license scan coverage is unavailable")?;
    let [engine] = scan.engines.as_slice() else {
        anyhow::bail!("Direct license result must record exactly one engine");
    };
    validate_scope(result, scan)?;
    validate_engine(result, receipt, engine)
}

fn validate_scope(result: &Value, scan: &ScanStageData) -> Result<()> {
    anyhow::ensure!(
        scan.scope.paths.is_empty(),
        "Direct license scan cannot invent path restrictions"
    );
    anyhow::ensure!(
        scan.plan.engines == ["license-scan"],
        "Direct license plan names another engine"
    );
    anyhow::ensure!(
        Some(scan.scope.target.as_str()) == result.pointer("/data/target").and_then(Value::as_str),
        "Direct license result target differs from its coverage"
    );
    anyhow::ensure!(
        scan.target_snapshot.target == scan.scope.target,
        "Direct license snapshot target differs from its coverage"
    );
    Ok(())
}

fn validate_engine(
    result: &Value,
    receipt: &PhaseStageReceipt,
    engine: &ScanStageEngine,
) -> Result<()> {
    use crate::module_result::{tool_result_status, ToolResultStatus};
    anyhow::ensure!(
        engine.engine == "license-scan",
        "Direct license result names another engine"
    );
    anyhow::ensure!(
        engine.rule_ids.is_some(),
        "Direct license rule policy is unavailable"
    );
    let complete = match tool_result_status(result) {
        ToolResultStatus::Completed => true,
        ToolResultStatus::Partial => false,
        _ => anyhow::bail!("An unsuccessful direct license result cannot establish coverage"),
    };
    let expected = if complete {
        ScanEngineStageOutcome::Complete
    } else {
        ScanEngineStageOutcome::Partial
    };
    let outcome = if complete {
        PhaseStageOutcome::Completed
    } else {
        PhaseStageOutcome::Partial
    };
    anyhow::ensure!(
        engine.outcome == expected && receipt.outcome == outcome,
        "Direct license result contradicts its coverage outcome"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
