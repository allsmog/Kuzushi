use super::*;
use anyhow::Context;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GenericPersistedRun {
    pub(crate) run_id: String,
    pub(crate) findings_db: String,
}

pub(crate) fn normalize_reported_file_path(path: String, target: &Path) -> String {
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

pub(crate) fn normalize_agent_json_findings(
    raw: Value,
    target: &Path,
    tool_slug: &str,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let items = agent_findings_items(raw, tool_slug)?;
    Ok(items
        .into_iter()
        .take(max_findings)
        .filter_map(|item| agent_finding_from_item(item, target, tool_slug))
        .collect())
}

pub(crate) fn generic_severity(value: &str) -> Severity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" | "error" => Severity::High,
        "medium" | "warning" => Severity::Medium,
        "low" => Severity::Low,
        "info" | "informational" => Severity::Info,
        _ => Severity::Unknown,
    }
}

fn agent_findings_items(raw: Value, tool_slug: &str) -> Result<Vec<Value>> {
    let findings_value = match raw {
        Value::Object(object) => object
            .get("findings")
            .cloned()
            .with_context(|| format!("{tool_slug} adapter output missing `findings` array"))?,
        Value::Array(items) => return Ok(items),
        _ => anyhow::bail!("{tool_slug} adapter output parse failed: expected object or array"),
    };
    let Value::Array(items) = findings_value else {
        anyhow::bail!("{tool_slug} adapter output parse failed: findings must be an array");
    };
    Ok(items)
}

fn agent_finding_from_item(item: Value, target: &Path, tool_slug: &str) -> Option<Finding> {
    let Value::Object(object) = item else {
        return None;
    };
    let rule_id = read_object_string(&object, &["ruleId", "rule_id", "id"])
        .unwrap_or_else(|| format!("{tool_slug}/finding"));
    let file_path = agent_finding_file_path(&object, target);
    let start_line = agent_finding_start_line(&object);
    let end_line = agent_finding_end_line(&object);
    let mut message =
        read_object_string(&object, &["message", "title", "summary"]).unwrap_or(rule_id.clone());
    let severity = agent_finding_severity(&object, &mut message);
    append_agent_finding_context(&object, &mut message);
    let finding = Finding::new_tool(
        tool_slug.to_string(),
        rule_id,
        file_path,
        start_line,
        end_line,
        severity,
        message,
    );
    Some(with_agent_finding_metadata(finding, &object))
}

fn with_agent_finding_metadata(mut finding: Finding, object: &Map<String, Value>) -> Finding {
    finding.symbol_locator =
        read_object_string(object, &["symbolLocator", "symbol_locator", "symbol"]);
    finding.rule_version = read_object_string(object, &["ruleVersion", "rule_version"]);
    finding
}

fn agent_finding_file_path(object: &Map<String, Value>, target: &Path) -> String {
    normalize_reported_file_path(
        read_object_string(object, &["filePath", "file_path", "path"])
            .unwrap_or_else(|| "unknown".to_string()),
        target,
    )
}

fn agent_finding_start_line(object: &Map<String, Value>) -> u32 {
    read_object_u64(object, &["startLine", "start_line", "line"])
        .filter(|line| *line > 0)
        .unwrap_or(1) as u32
}

fn agent_finding_end_line(object: &Map<String, Value>) -> Option<u32> {
    read_object_u64(object, &["endLine", "end_line"])
        .filter(|line| *line > 0)
        .map(|line| line as u32)
}

fn agent_finding_severity(object: &Map<String, Value>, message: &mut String) -> Severity {
    match read_object_string(object, &["severity"]) {
        Some(label) => severity_from_agent_label(&label, message),
        None => {
            message.push_str("\nSeverity: unknown (adapter output missing severity)");
            Severity::Unknown
        }
    }
}

fn severity_from_agent_label(label: &str, message: &mut String) -> Severity {
    let severity = generic_severity(label);
    if matches!(severity, Severity::Unknown) {
        message.push_str(&format!(
            "\nSeverity: unknown (unrecognized adapter severity: {label})"
        ));
    }
    severity
}

fn append_agent_finding_context(object: &Map<String, Value>, message: &mut String) {
    for (label, keys) in agent_context_fields() {
        if let Some(value) = read_object_string(object, keys) {
            message.push_str(&format!("\n{label}: {value}"));
            continue;
        }
        let values = read_object_string_array(object, keys);
        if !values.is_empty() {
            message.push_str(&format!("\n{label}: {}", values.join(", ")));
        }
    }
}

fn agent_context_fields() -> [(&'static str, &'static [&'static str]); 4] {
    [
        ("Evidence", &["evidence", "proof"]),
        ("CWE", &["cwe"]),
        ("Control", &["control"]),
        ("Recommendation", &["recommendation", "recommendedFix"]),
    ]
}

fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn read_object_string_array(object: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn read_object_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_u64)
}

#[cfg(test)]
mod metadata_tests {
    use super::*;

    #[test]
    fn generic_agent_findings_keep_optional_symbol_and_rule_version() {
        let findings = normalize_agent_json_findings(
            serde_json::json!({
                "findings": [{
                    "ruleId": "CWE-89",
                    "ruleVersion": "2026.08",
                    "symbolLocator": "crate::db::execute",
                    "filePath": "src/db.rs",
                    "startLine": 12,
                    "severity": "high",
                    "message": "candidate"
                }]
            }),
            Path::new("/repo"),
            "agentic-sast",
            10,
        )
        .unwrap();

        assert_eq!(findings[0].rule_version.as_deref(), Some("2026.08"));
        assert_eq!(
            findings[0].symbol_locator.as_deref(),
            Some("crate::db::execute")
        );
    }
}
