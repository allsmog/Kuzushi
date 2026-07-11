use crate::findings::{Finding, Severity};
use anyhow::Result;
use serde_json::Value;

pub(crate) fn normalize_uaf_hunt_findings(
    raw: &Value,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let array = uaf_finding_items(raw)?;
    let mut findings = Vec::new();
    for item in array.iter().take(max_findings) {
        findings.push(parse_one(item)?);
    }
    Ok(findings)
}

fn uaf_finding_items(raw: &Value) -> Result<&Vec<Value>> {
    let Some(findings) = raw.get("findings") else {
        anyhow::bail!("uaf-hunt output parse failed: object missing findings array");
    };
    let Some(items) = findings.as_array() else {
        anyhow::bail!("uaf-hunt output parse failed: findings must be an array");
    };
    Ok(items)
}

fn parse_one(item: &Value) -> Result<Finding> {
    let rule_id = required_finding_string(item, &["ruleId", "rule_id"], "ruleId")?;
    let file_path = required_finding_string(item, &["filePath", "file_path", "file"], "filePath")?;
    let start_line = read_u64(item, &["startLine", "start_line", "line"]).unwrap_or(1) as u32;
    let end_line = read_u64(item, &["endLine", "end_line"]).map(|line| line as u32);
    let severity = read_severity(item);
    let full_message = full_message_with_trace(item);
    Ok(Finding::new_tool(
        "uaf-hunt",
        rule_id,
        file_path,
        start_line.max(1),
        end_line,
        severity,
        full_message,
    ))
}

fn required_finding_string<'a>(item: &'a Value, keys: &[&str], label: &str) -> Result<&'a str> {
    read_required_str(item, keys)
        .ok_or_else(|| anyhow::anyhow!("uaf-hunt finding missing required {label}"))
}

fn read_required_str<'a>(item: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| item.get(*key))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn read_optional_str<'a>(item: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| item.get(*key))
        .and_then(Value::as_str)
}

fn read_u64(item: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| item.get(*key))
        .and_then(Value::as_u64)
}

fn read_severity(item: &Value) -> Severity {
    item.get("severity")
        .and_then(Value::as_str)
        .map(severity_from_label)
        .unwrap_or(Severity::Unknown)
}

fn full_message_with_trace(item: &Value) -> String {
    let message = read_optional_str(item, &["message", "title"])
        .unwrap_or("uaf-hunt: temporal memory safety issue");
    match item.get("trace").map(render_trace_block) {
        Some(trace) => format!("{message}{trace}"),
        None => message.to_string(),
    }
}

fn render_trace_block(trace: &Value) -> String {
    let alloc = read_optional_str(trace, &["allocSite", "alloc_site"]).unwrap_or("");
    let free = read_optional_str(trace, &["freeSite", "free_site"]).unwrap_or("");
    let use_site = read_optional_str(trace, &["useSite", "use_site"]).unwrap_or("");
    let rationale = read_optional_str(trace, &["rationale"]).unwrap_or("");
    format!("\n\nalloc: {alloc}\nfree:  {free}\nuse:   {use_site}\nrationale: {rationale}",)
}

fn severity_from_label(label: &str) -> Severity {
    match label.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" | "MED" => Severity::Medium,
        "LOW" => Severity::Low,
        "INFO" | "INFORMATION" | "INFORMATIONAL" => Severity::Info,
        _ => Severity::Unknown,
    }
}
