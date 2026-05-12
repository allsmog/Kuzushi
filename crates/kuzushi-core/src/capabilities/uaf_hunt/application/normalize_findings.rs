use crate::findings::{Finding, Severity};
use anyhow::Result;
use serde_json::Value;

pub(crate) fn normalize_uaf_hunt_findings(
    raw: &Value,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let array = raw
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut findings = Vec::new();
    for item in array.iter().take(max_findings) {
        if let Some(finding) = parse_one(item) {
            findings.push(finding);
        }
    }
    Ok(findings)
}

fn parse_one(item: &Value) -> Option<Finding> {
    let rule_id = item
        .get("ruleId")
        .or_else(|| item.get("rule_id"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let file_path = item
        .get("filePath")
        .or_else(|| item.get("file_path"))
        .or_else(|| item.get("file"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let start_line = item
        .get("startLine")
        .or_else(|| item.get("start_line"))
        .or_else(|| item.get("line"))
        .and_then(Value::as_u64)
        .unwrap_or(1) as u32;
    let end_line = item
        .get("endLine")
        .or_else(|| item.get("end_line"))
        .and_then(Value::as_u64)
        .map(|line| line as u32);
    let severity = item
        .get("severity")
        .and_then(Value::as_str)
        .map(severity_from_label)
        .unwrap_or(Severity::High);
    let message = item
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| item.get("title").and_then(Value::as_str))
        .unwrap_or("uaf-hunt: temporal memory safety issue")
        .to_string();
    let trace_block = item.get("trace").map(|trace| {
        let alloc = trace
            .get("allocSite")
            .or_else(|| trace.get("alloc_site"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let free = trace
            .get("freeSite")
            .or_else(|| trace.get("free_site"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let use_site = trace
            .get("useSite")
            .or_else(|| trace.get("use_site"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let rationale = trace
            .get("rationale")
            .and_then(Value::as_str)
            .unwrap_or("");
        format!(
            "\n\nalloc: {alloc}\nfree:  {free}\nuse:   {use_site}\nrationale: {rationale}",
        )
    });
    let full_message = match trace_block {
        Some(trace) => format!("{message}{trace}"),
        None => message,
    };

    Some(Finding::new_tool(
        "uaf-hunt",
        rule_id,
        file_path,
        start_line.max(1),
        end_line,
        severity,
        full_message,
    ))
}

fn severity_from_label(label: &str) -> Severity {
    match label.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" | "MED" => Severity::Medium,
        "LOW" => Severity::Low,
        "INFO" | "INFORMATION" | "INFORMATIONAL" => Severity::Info,
        _ => Severity::High,
    }
}
