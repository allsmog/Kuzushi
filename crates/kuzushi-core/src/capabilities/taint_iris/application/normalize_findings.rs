use super::*;

pub(crate) fn normalize_taint_iris_findings(
    raw: Value,
    target: &Path,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let findings_value = match raw {
        Value::Object(object) => object
            .get("findings")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        Value::Array(items) => Value::Array(items),
        _ => anyhow::bail!("taint-iris output parse failed: expected an object or findings array"),
    };
    let Value::Array(items) = findings_value else {
        anyhow::bail!("taint-iris output parse failed: findings must be an array");
    };

    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        let cwe = read_object_string(&object, &["cwe", "CWE"]).unwrap_or_else(|| "CWE".to_string());
        let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
            .unwrap_or_else(|| format!("taint-iris/{}", sanitize_rule_segment(&cwe)));
        let file_path = normalize_reported_file_path(
            read_object_string(&object, &["filePath", "file_path"])
                .unwrap_or_else(|| "unknown".to_string()),
            target,
        );
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .filter(|value| *value > 0)
            .unwrap_or(1) as u32;
        let severity = agentic_severity(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or("medium"),
        );
        let title = read_object_string(&object, &["title"]).unwrap_or_else(|| rule_id.clone());
        let detail = read_object_string(&object, &["message"]).unwrap_or_else(|| title.clone());
        let mut message = format!("{title}\n\n{detail}\nCWE: {cwe}");
        if let Some(trace) = read_object_string(&object, &["sourceSinkTrace", "source_sink_trace"])
        {
            message.push_str("\nSource-to-sink trace: ");
            message.push_str(trace.trim());
        }
        if let Some(confidence) = read_object_string(&object, &["confidence"]) {
            message.push_str("\nConfidence: ");
            message.push_str(confidence.trim());
        }
        if let Some(preconditions) =
            read_object_string(&object, &["exploitPreconditions", "exploit_preconditions"])
        {
            message.push_str("\nExploit preconditions: ");
            message.push_str(preconditions.trim());
        }
        if let Some(path_summary) = summarize_taint_path(&object) {
            message.push_str("\nTaint path:\n");
            message.push_str(&path_summary);
        }
        findings.push(Finding::new_tool(
            "taint-iris",
            rule_id,
            file_path,
            start_line,
            None,
            severity,
            message,
        ));
    }
    Ok(findings)
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

fn normalize_reported_file_path(path: String, target: &Path) -> String {
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
