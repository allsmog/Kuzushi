use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::findings::{Finding, Severity};

use super::json_fields::{read_object_string, read_object_string_array, read_object_u64};
use super::ToolExecutionContext;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct GenericPersistedRun {
    run_id: String,
    findings_db: String,
}

pub(super) fn normalize_reported_file_path(path: String, target: &Path) -> String {
    let candidate = PathBuf::from(path.trim());
    if candidate.is_absolute() {
        return candidate
            .strip_prefix(target)
            .unwrap_or(&candidate)
            .display()
            .to_string();
    }
    path.trim().to_string()
}

pub(super) fn normalize_agent_json_findings(
    raw: Value,
    target: &Path,
    tool_slug: &str,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let findings_value = match raw {
        Value::Object(object) => object
            .get("findings")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        Value::Array(items) => Value::Array(items),
        _ => Value::Array(Vec::new()),
    };
    let Value::Array(items) = findings_value else {
        anyhow::bail!("{tool_slug} adapter output parse failed: findings must be an array");
    };
    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        let rule_id = read_object_string(&object, &["ruleId", "rule_id", "id"])
            .unwrap_or_else(|| format!("{tool_slug}/finding"));
        let file_path = normalize_reported_file_path(
            read_object_string(&object, &["filePath", "file_path", "path"])
                .unwrap_or_else(|| "unknown".to_string()),
            target,
        );
        let start_line = read_object_u64(&object, &["startLine", "start_line", "line"])
            .filter(|line| *line > 0)
            .unwrap_or(1) as u32;
        let end_line = read_object_u64(&object, &["endLine", "end_line"])
            .filter(|line| *line > 0)
            .map(|line| line as u32);
        let severity = generic_severity(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or("medium"),
        );
        let mut message = read_object_string(&object, &["message", "title", "summary"])
            .unwrap_or_else(|| rule_id.clone());
        for (label, keys) in [
            ("Evidence", &["evidence", "proof"][..]),
            ("CWE", &["cwe"][..]),
            ("Control", &["control"][..]),
            ("Recommendation", &["recommendation", "recommendedFix"][..]),
        ] {
            if let Some(value) = read_object_string(&object, keys) {
                message.push_str(&format!("\n{label}: {value}"));
            } else {
                let values = read_object_string_array(&object, keys);
                if !values.is_empty() {
                    message.push_str(&format!("\n{label}: {}", values.join(", ")));
                }
            }
        }
        findings.push(Finding::new_tool(
            tool_slug.to_string(),
            rule_id,
            file_path,
            start_line,
            end_line,
            severity,
            message,
        ));
    }
    Ok(findings)
}

fn generic_severity(value: &str) -> Severity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" | "error" => Severity::High,
        "medium" | "warning" => Severity::Medium,
        "low" => Severity::Low,
        "info" | "informational" => Severity::Info,
        _ => Severity::Unknown,
    }
}

pub(super) fn persist_tool_findings(
    tool_slug: &str,
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<GenericPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = format!("{tool_slug}-{}", Uuid::new_v4());
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;
    Ok(Some(GenericPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

pub(super) fn render_generic_findings_output(
    tool_name: &str,
    target: &Path,
    findings: &[Finding],
    persisted: &Option<GenericPersistedRun>,
) -> String {
    let mut lines = vec![format!(
        "{tool_name} complete for {}\n  Findings: {}",
        target.display(),
        findings.len()
    )];
    if let Some(persisted) = persisted {
        lines.push(format!(
            "  Persisted run: {} ({})",
            persisted.run_id, persisted.findings_db
        ));
    }
    if !findings.is_empty() {
        lines.push(String::new());
        lines.push("Top findings:".to_string());
        for finding in findings.iter().take(10) {
            lines.push(format!(
                "  - {} - {} - {}:{}",
                finding.severity.as_str(),
                finding.rule_id,
                finding.file_path,
                finding.start_line
            ));
        }
    }
    lines.join("\n")
}
