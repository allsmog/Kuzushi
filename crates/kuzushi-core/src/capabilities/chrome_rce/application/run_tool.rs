use super::collect_findings::collect_findings;
use crate::capabilities::chrome_rce::adapters::changed_files;
use crate::capabilities::chrome_rce::domain::hot_path_finding;
use crate::findings::{persist_tool_findings, Finding, FindingStore};
use crate::workspace::WorkspaceTarget;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

#[derive(Clone)]
pub(crate) struct ChromeRcePersistence<'a> {
    pub(crate) finding_run_id: String,
    pub(crate) workspace: Option<&'a WorkspaceTarget>,
    pub(crate) findings_store: Option<&'a FindingStore>,
}

pub(crate) fn run_scan(target: &Path, persistence: ChromeRcePersistence<'_>) -> Result<Value> {
    require_scan_target(target)?;
    let findings = scan_target(target)?;
    let persisted = persist_chrome_rce_findings(target, &findings, persistence)?;
    Ok(scan_response(target, findings, persisted))
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

fn scan_target(target: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    collect_findings(target, target, &mut findings)?;
    Ok(findings)
}

fn persist_chrome_rce_findings(
    target: &Path,
    findings: &[Finding],
    persistence: ChromeRcePersistence<'_>,
) -> Result<Option<crate::findings::GenericPersistedRun>> {
    persist_tool_findings(
        persistence.finding_run_id,
        target,
        findings,
        persistence.workspace,
        persistence.findings_store,
    )
}

fn scan_response(target: &Path, findings: Vec<Finding>, persisted: impl serde::Serialize) -> Value {
    let summary = format!(
        "chrome-rce:scan found {} finding{} under {}",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        target.display()
    );
    crate::module_result::completed_output_result(
        summary.clone(),
        summary,
        json!({
            "target": target.display().to_string(),
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        }),
    )
}

pub(crate) fn run_review_trigger(
    target: &Path,
    diff_base: Option<&str>,
    persistence: ChromeRcePersistence<'_>,
) -> Result<Value> {
    let Some(diff_base) = diff_base else {
        return Ok(skipped_review_response(target));
    };
    review_trigger_with_diff_base(target, diff_base, persistence)
}

fn review_trigger_with_diff_base(
    target: &Path,
    diff_base: &str,
    persistence: ChromeRcePersistence<'_>,
) -> Result<Value> {
    let changed = changed_files(target, diff_base)?;
    let findings = hot_path_findings(&changed);
    let persisted = persist_chrome_rce_findings(target, &findings, persistence)?;
    Ok(review_response(
        target, diff_base, changed, findings, persisted,
    ))
}

fn hot_path_findings(changed: &[String]) -> Vec<Finding> {
    changed
        .iter()
        .filter_map(|file| hot_path_finding(file))
        .collect()
}

fn skipped_review_response(target: &Path) -> Value {
    let summary = "chrome-rce:review-trigger skipped: pass diffBase to enable PR hot-path review.";
    crate::module_result::skipped_output_result(
        summary,
        summary,
        Vec::new(),
        json!({
            "target": target.display().to_string(),
            "count": 0,
            "findings": [],
        }),
    )
}

fn review_response(
    target: &Path,
    diff_base: &str,
    changed: Vec<String>,
    findings: Vec<Finding>,
    persisted: impl serde::Serialize,
) -> Value {
    let summary = format!(
        "chrome-rce:review-trigger matched {} hot path{} vs {}",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        diff_base
    );
    crate::module_result::completed_output_result(
        summary.clone(),
        summary,
        json!({
            "target": target.display().to_string(),
            "diffBase": diff_base,
            "changedFiles": changed,
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        }),
    )
}
