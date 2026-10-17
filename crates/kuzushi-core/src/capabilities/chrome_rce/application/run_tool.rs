use super::collect_findings::collect_findings;
use crate::findings::{persist_tool_findings_to_with_status, Finding, ToolFindingsSink};
use crate::run_lifecycle::RunItemStatus;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

pub(crate) fn run_scan(
    target: &Path,
    persistence: ToolFindingsSink<'_>,
    max_findings: usize,
) -> Result<Value> {
    anyhow::ensure!(
        max_findings > 0,
        "chrome-rce:scan maxFindings must be positive"
    );
    require_scan_target(target)?;
    let (findings, limited) = scan_target(target, max_findings)?;
    let status = if limited {
        RunItemStatus::Partial
    } else {
        RunItemStatus::Completed
    };
    let persisted = persist_chrome_rce_findings(target, &findings, persistence, status)?;
    Ok(scan_response(
        target,
        findings,
        persisted,
        max_findings,
        limited,
    ))
}

fn require_scan_target(target: &Path) -> Result<()> {
    if !target.is_dir() {
        anyhow::bail!(
            "chrome-rce:scan target is not a directory: {}",
            target.display()
        );
    }
    Ok(())
}

fn scan_target(target: &Path, limit: usize) -> Result<(Vec<Finding>, bool)> {
    let mut findings = Vec::new();
    let limited = collect_findings(target, target, &mut findings, limit)?;
    Ok((findings, limited))
}

fn persist_chrome_rce_findings(
    target: &Path,
    findings: &[Finding],
    persistence: ToolFindingsSink<'_>,
    status: RunItemStatus,
) -> Result<Option<crate::findings::GenericPersistedRun>> {
    persist_tool_findings_to_with_status(persistence, target, findings, status)
}

fn scan_response(
    target: &Path,
    findings: Vec<Finding>,
    persisted: impl serde::Serialize,
    max_findings: usize,
    limited: bool,
) -> Value {
    let summary = format!(
        "chrome-rce:scan found {} finding{} under {}",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        target.display()
    );
    let data = json!({
        "target": target.display().to_string(),
        "count": findings.len(),
        "findings": findings,
        "persisted": persisted,
        "inspection": {"maxFindings":max_findings, "findingLimitReached":limited},
    });
    if limited {
        let warning =
            format!("Finding limit {max_findings} reached; remaining source was not inspected.");
        let summary = format!("chrome-rce:scan partial: {warning}");
        return crate::module_result::partial_output_result(
            summary.clone(),
            summary,
            vec![json!(warning)],
            data,
        );
    }
    crate::module_result::completed_output_result(summary.clone(), summary, data)
}
