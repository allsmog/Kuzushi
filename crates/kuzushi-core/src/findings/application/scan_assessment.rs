//! Evidence of reassessment is independent of whether absence proves a fix.
use crate::findings::tool_components;
use crate::run_artifacts::{
    PhaseStageOutcome, PhaseStageReceipt, ScanEngineStageOutcome, ScanStageData,
};

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
    if compare_status != "completed" {
        return Some("later run did not complete");
    }
    let Some(receipt) = receipt else {
        return Some("scan coverage receipt is unavailable");
    };
    if receipt.outcome != PhaseStageOutcome::Completed {
        return Some("scan phase did not complete");
    }
    let Some(scan) = &receipt.scan else {
        return Some("scan coverage is unknown");
    };
    covered_finding_block(base_target, scan, file, tool)
}

/// Rule-aware reassessment for callers holding the original finding identity.
/// Legacy receipts remain readable, but cannot prove an unrecorded license policy.
pub fn scan_reassessment_block_for_rule(
    base_target: Option<&str>,
    compare_status: &str,
    receipt: Option<&PhaseStageReceipt>,
    file: &str,
    tool: &str,
    rule_id: &str,
) -> Option<&'static str> {
    if let Some(reason) = scan_reassessment_block(base_target, compare_status, receipt, file, tool)
    {
        return Some(reason);
    }
    let engines = &receipt?.scan.as_ref()?.engines;
    scan_rule_coverage_block(engines, tool, rule_id)
}

pub(crate) fn scan_rule_coverage_block(
    engines: &[crate::run_artifacts::ScanStageEngine],
    tool: &str,
    rule_id: &str,
) -> Option<&'static str> {
    tool_components(tool).find_map(|component| {
        let rules = engines
            .iter()
            .find(|engine| engine.engine == component)
            .and_then(|engine| engine.rule_ids.as_ref());
        match rules {
            Some(rules) if !rules.iter().any(|rule| rule == rule_id) => {
                Some("finding rule was not enabled in the later scan")
            }
            None if matches!(
                component,
                "license-scan" | "iac-scan" | "cargo-audit" | "govulncheck"
            ) =>
            {
                Some("finding rule coverage was not recorded")
            }
            _ => None,
        }
    })
}

fn covered_finding_block(
    base_target: Option<&str>,
    scan: &ScanStageData,
    file: &str,
    tool: &str,
) -> Option<&'static str> {
    if base_target != Some(scan.scope.target.as_str()) {
        return Some("later run scanned a different target");
    }
    if !scan.scope.covers_file(file) {
        return Some("finding path is outside the recorded scan scope");
    }
    completed_engine_block(scan, tool)
}

fn completed_engine_block(scan: &ScanStageData, tool: &str) -> Option<&'static str> {
    if tool_components(tool).next().is_none() {
        return Some("finding engine is unknown");
    }
    let complete = |name| {
        scan.engines.iter().any(|engine| {
            engine.engine == name && engine.outcome == ScanEngineStageOutcome::Complete
        })
    };
    (!tool_components(tool).all(complete)).then_some("finding engine has no completed scan receipt")
}

#[cfg(test)]
mod tests;
