//! Evidence of reassessment is independent of whether absence proves a fix.
use crate::findings::tool_components;
use crate::run_artifacts::{PhaseStageOutcome, PhaseStageReceipt, ScanEngineStageOutcome, ScanStageData};

/// A reason the later run cannot establish that this finding was reassessed.
/// `None` means covered but not observed, never a finding verdict or fix claim.
/// Explicit completed engine receipts are required, including for clean scans.
pub fn scan_reassessment_block(
    base_target: Option<&str>,
    compare_status: &str,
    receipt: Option<&PhaseStageReceipt>,
    file: &str,
    tool: &str,
) -> Option<&'static str> {
    if compare_status != "completed" { return Some("later run did not complete"); }
    let Some(receipt) = receipt else { return Some("scan coverage receipt is unavailable"); };
    if receipt.outcome != PhaseStageOutcome::Completed { return Some("scan phase did not complete"); }
    let Some(scan) = &receipt.scan else { return Some("scan coverage is unknown"); };
    covered_finding_block(base_target, scan, file, tool)
}

fn covered_finding_block(
    base_target: Option<&str>, scan: &ScanStageData, file: &str, tool: &str,
) -> Option<&'static str> {
    if base_target != Some(scan.scope.target.as_str()) { return Some("later run scanned a different target"); }
    if !scan.scope.covers_file(file) { return Some("finding path is outside the recorded scan scope"); }
    completed_engine_block(scan, tool)
}

fn completed_engine_block(scan: &ScanStageData, tool: &str) -> Option<&'static str> {
    if tool_components(tool).next().is_none() { return Some("finding engine is unknown"); }
    let complete = |name| scan.engines.iter().any(|engine|
        engine.engine == name && engine.outcome == ScanEngineStageOutcome::Complete);
    (!tool_components(tool).all(complete)).then_some("finding engine has no completed scan receipt")
}

#[cfg(test)]
mod tests;
