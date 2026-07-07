use super::*;

use crate::capabilities::agentic_sast::{agentic_severity, normalize_reported_file_path};
use crate::Finding;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintFlow {
    pub(crate) cwe: String,
    pub(crate) severity: String,
    pub(crate) stages: Vec<TaintFlowStage>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintFlowStage {
    pub(crate) message: String,
    pub(crate) file_path: String,
    pub(crate) line: u32,
    pub(crate) snippet: String,
}

pub(crate) fn normalize_taint_iris_findings(
    raw: Value,
    target: &Path,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let items = taint_findings_items(raw)?;
    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        findings.push(taint_finding_from_object(object, target));
    }
    Ok(findings)
}

fn taint_findings_items(raw: Value) -> Result<Vec<Value>> {
    match raw {
        Value::Object(object) => taint_findings_items_from_object(object),
        Value::Array(items) => Ok(items),
        _ => anyhow::bail!("taint-iris output parse failed: expected an object or findings array"),
    }
}

fn taint_findings_items_from_object(object: Map<String, Value>) -> Result<Vec<Value>> {
    let Some(findings) = object.get("findings") else {
        anyhow::bail!("taint-iris output parse failed: object missing findings array");
    };
    let Value::Array(items) = findings.clone() else {
        anyhow::bail!("taint-iris output parse failed: findings must be an array");
    };
    Ok(items)
}

fn taint_finding_from_object(object: Map<String, Value>, target: &Path) -> Finding {
    let cwe = read_object_string(&object, &["cwe", "CWE"]).unwrap_or_else(|| "CWE".to_string());
    let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
        .unwrap_or_else(|| format!("taint-iris/{}", sanitize_rule_segment(&cwe)));
    let file_path = taint_file_path(&object, target);
    let start_line = taint_start_line(&object);
    let severity = agentic_severity(
        read_object_string(&object, &["severity"])
            .as_deref()
            .unwrap_or(""),
    );
    let message = taint_message(&object, &rule_id, &cwe);
    Finding::new_tool(
        "taint-iris",
        rule_id,
        file_path,
        start_line,
        None,
        severity,
        message,
    )
}

fn taint_file_path(object: &Map<String, Value>, target: &Path) -> String {
    normalize_reported_file_path(
        read_object_string(object, &["filePath", "file_path"])
            .unwrap_or_else(|| "unknown".to_string()),
        target,
    )
}

fn taint_start_line(object: &Map<String, Value>) -> u32 {
    read_object_u64(object, &["startLine", "start_line"])
        .filter(|value| *value > 0)
        .unwrap_or(1) as u32
}

fn taint_message(object: &Map<String, Value>, rule_id: &str, cwe: &str) -> String {
    let title = read_object_string(object, &["title"]).unwrap_or_else(|| rule_id.to_string());
    let detail = read_object_string(object, &["message"]).unwrap_or_else(|| title.clone());
    let mut message = format!("{title}\n\n{detail}\nCWE: {cwe}");
    append_taint_string_field(
        &mut message,
        object,
        &["sourceSinkTrace", "source_sink_trace"],
        "\nSource-to-sink trace: ",
    );
    append_taint_string_field(&mut message, object, &["confidence"], "\nConfidence: ");
    append_taint_string_field(
        &mut message,
        object,
        &["exploitPreconditions", "exploit_preconditions"],
        "\nExploit preconditions: ",
    );
    append_taint_path_summary(&mut message, object);
    message
}

fn append_taint_string_field(
    message: &mut String,
    object: &Map<String, Value>,
    keys: &[&str],
    prefix: &str,
) {
    if let Some(value) = read_object_string(object, keys) {
        message.push_str(prefix);
        message.push_str(value.trim());
    }
}

fn append_taint_path_summary(message: &mut String, object: &Map<String, Value>) {
    if let Some(path_summary) = summarize_taint_path(object) {
        message.push_str("\nTaint path:\n");
        message.push_str(&path_summary);
    }
}

/// Extract structured source→sink flows from the raw taint-iris output, parallel
/// to [`normalize_taint_iris_findings`]. The findings flatten each path into
/// `Finding.message` text; these preserve the ordered stages so the TUI can draw
/// the attack-path diagram without re-parsing prose. Additive — the findings are
/// unchanged.
pub(crate) fn extract_taint_flows(raw: &Value, max_findings: usize) -> Vec<TaintFlow> {
    raw_taint_findings(raw)
        .iter()
        .take(max_findings)
        .filter_map(taint_flow_from_finding)
        .collect()
}

fn raw_taint_findings(raw: &Value) -> &[Value] {
    match raw {
        Value::Object(object) => object
            .get("findings")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default(),
        Value::Array(items) => items.as_slice(),
        _ => &[],
    }
}

fn taint_flow_from_finding(item: &Value) -> Option<TaintFlow> {
    let object = item.as_object()?;
    let path = read_object_value(object, &["taintPath", "taint_path"])?.as_array()?;
    let stages: Vec<TaintFlowStage> = path.iter().filter_map(taint_flow_stage).collect();
    if stages.is_empty() {
        return None;
    }
    Some(TaintFlow {
        cwe: read_object_string(object, &["cwe", "CWE"]).unwrap_or_else(|| "CWE".to_string()),
        severity: read_object_string(object, &["severity"])
            .unwrap_or_else(|| "medium".to_string()),
        stages,
    })
}

fn taint_flow_stage(item: &Value) -> Option<TaintFlowStage> {
    let step = item.as_object()?;
    Some(TaintFlowStage {
        message: read_object_string(step, &["message"]).unwrap_or_default(),
        file_path: read_object_string(step, &["filePath", "file_path"]).unwrap_or_default(),
        line: read_object_u64(step, &["line", "startLine", "start_line"]).unwrap_or(0) as u32,
        snippet: read_object_string(step, &["snippet"]).unwrap_or_default(),
    })
}

pub(crate) fn summarize_taint_path(object: &Map<String, Value>) -> Option<String> {
    let path = read_object_value(object, &["taintPath", "taint_path"])?.as_array()?;
    let mut lines = Vec::new();
    for item in path.iter().take(20) {
        let Value::Object(step) = item else {
            continue;
        };
        let file_path = read_object_string(step, &["filePath", "file_path"])
            .unwrap_or_else(|| "unknown".to_string());
        let line = read_object_u64(step, &["line", "startLine", "start_line"]).unwrap_or(1);
        let message = read_object_string(step, &["message"]).unwrap_or_default();
        let snippet = read_object_string(step, &["snippet"]).unwrap_or_default();
        let mut rendered = format!("- {file_path}:{line}");
        if !message.is_empty() {
            rendered.push_str(": ");
            rendered.push_str(&message);
        }
        if !snippet.is_empty() {
            rendered.push_str(" | ");
            rendered.push_str(&snippet);
        }
        lines.push(rendered);
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

pub(crate) fn sanitize_rule_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').to_string()
}

pub(crate) fn read_object_value<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

pub(crate) fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn read_object_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    read_object_value(object, keys).and_then(Value::as_u64)
}
