use super::*;

pub(crate) fn positive_usize(input: &Value, keys: &[&str], default: usize) -> Result<usize> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            let Some(number) = value.as_u64() else {
                anyhow::bail!("systems-hunt {key} must be a positive integer");
            };
            if number == 0 {
                anyhow::bail!("systems-hunt {key} must be a positive integer");
            }
            return Ok(number as usize);
        }
    }
    Ok(default)
}

pub(crate) fn bool_option(input: &Value, keys: &[&str], default: bool) -> Result<bool> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            let Some(value) = value.as_bool() else {
                anyhow::bail!("systems-hunt {key} must be a boolean");
            };
            return Ok(value);
        }
    }
    Ok(default)
}

pub(crate) fn optional_nonempty_string(input: &Value, key: &str) -> Result<Option<String>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        anyhow::bail!("systems-hunt {key} must be a string");
    };
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

pub(crate) fn artifact_root(target: &Path, raw: &str) -> Result<PathBuf> {
    let configured = raw.trim();
    let configured = if configured.is_empty() {
        Path::new(".kuzushi/systems-hunt")
    } else {
        Path::new(configured)
    };
    if configured
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        anyhow::bail!(
            "systems-hunt artifactDir must stay inside the repository root: {}",
            configured.display()
        );
    }
    let candidate = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        target.join(configured)
    };
    let relative = candidate.strip_prefix(target).with_context(|| {
        format!(
            "systems-hunt artifactDir {} must stay inside {}",
            candidate.display(),
            target.display()
        )
    })?;
    crate::workspace::validated_workspace_descendant(target, relative)
}

pub(crate) fn write_artifact(
    target: &Path,
    root: &Path,
    fingerprint: &str,
    artifact: &Value,
) -> Result<PathBuf> {
    anyhow::ensure!(
        Path::new(fingerprint).components().count() == 1
            && !matches!(fingerprint, "" | "." | "..")
            && !fingerprint.contains('/')
            && !fingerprint.contains('\\'),
        "systems-hunt artifact fingerprint is not a safe file name"
    );
    let relative_root = root.strip_prefix(target).with_context(|| {
        format!(
            "systems-hunt artifact root {} is outside {}",
            root.display(),
            target.display()
        )
    })?;
    let relative = relative_root.join(format!("{fingerprint}.json"));
    let body = format!("{}\n", serde_json::to_string_pretty(artifact)?);
    crate::workspace::write_workspace_file(target, relative, body.as_bytes())
}

pub(crate) fn resolve_codeql_db_path(target: &Path) -> Option<PathBuf> {
    crate::codeql_repository_execution::resolve_managed_codeql_database(target)
        .ok()
        .flatten()
        .map(|database| database.path)
}

pub(crate) fn path_relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

pub(crate) fn normalize_relative_path(value: String) -> String {
    let path = Path::new(value.trim());
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str().map(ToString::to_string),
            Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn format_inventory(inventory: &[(String, String)]) -> String {
    inventory
        .iter()
        .map(|(path, body)| format!("## {path}\n```text\n{}\n```", body.trim()))
        .collect::<Vec<_>>()
        .join("\n\n")
}

pub(crate) fn parse_severity(value: String) -> Severity {
    Severity::from_label(&value)
}

pub(crate) fn string_field(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn first_string_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .map(|key| string_field(object.get(*key)))
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

pub(crate) fn optional_string(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

pub(crate) fn first_line_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> u64 {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(positive_line_number)
        .unwrap_or(1)
}

fn positive_line_number(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64().filter(|line| *line > 0),
        Value::Array(items) => items.iter().find_map(positive_line_number),
        Value::String(text) => positive_line_number_from_text(text),
        _ => None,
    }
}

fn positive_line_number_from_text(text: &str) -> Option<u64> {
    text.split(['-', ':', '–', '—', '\u{2013}', '\u{2014}'])
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|line| *line > 0)
}

pub(crate) fn first_string_array_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Vec<String> {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .map(string_array_from_value)
        .find(|items| !items.is_empty())
        .unwrap_or_default()
}

fn string_array_from_value(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().filter_map(string_from_array_item).collect(),
        Value::String(value) => trimmed_nonempty(value).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn string_from_array_item(value: &Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        return trimmed_nonempty(value);
    }

    let object = value.as_object()?;
    ["text", "message", "description", "note", "title"]
        .iter()
        .filter_map(|key| object.get(*key).and_then(Value::as_str))
        .find_map(trimmed_nonempty)
}

fn trimmed_nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

pub(crate) fn collect_finding_body(object: &serde_json::Map<String, Value>, title: &str) -> String {
    const PREFERRED_KEYS: &[&str] = &[
        "message",
        "summary",
        "description",
        "evidence",
        "rationale",
        "details",
        "notes",
        "trigger",
        "mechanism",
        "analysis",
        "bug",
        "explanation",
        "root_cause",
        "rootCause",
        "body",
        "content",
        "proof",
        "issue",
        "writeup",
        "writeUp",
        "narrative",
    ];

    let preferred = first_string_field(object, PREFERRED_KEYS);
    if !preferred.is_empty() {
        return preferred;
    }

    object
        .iter()
        .filter(|(key, _)| !is_structural_finding_key(key))
        .filter_map(|(_, value)| value.as_str().and_then(long_finding_text))
        .next()
        .unwrap_or_else(|| title.to_string())
}

fn is_structural_finding_key(key: &str) -> bool {
    const STRUCTURAL_KEYS: &[&str] = &[
        "id",
        "title",
        "name",
        "filePath",
        "file_path",
        "file",
        "path",
        "function",
        "functionName",
        "fn",
        "startLine",
        "start_line",
        "endLine",
        "end_line",
        "line",
        "lines",
        "lineRange",
        "line_range",
        "line_start",
        "lineStart",
        "line_end",
        "lineEnd",
        "anchorLine",
        "anchorLines",
        "severity",
        "confidence",
        "cwe",
        "cwes",
        "domain",
        "domains",
        "ruleId",
        "rule_id",
    ];

    STRUCTURAL_KEYS
        .iter()
        .any(|structural_key| structural_key.eq_ignore_ascii_case(key))
}

fn long_finding_text(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() >= 32).then(|| value.to_string())
}

pub(crate) fn build_finding_message(
    title: &str,
    description: &str,
    function: Option<&str>,
    evidence: &[String],
    impact: Option<&str>,
    hardening_notes: &[String],
    reasoning: Option<&str>,
) -> String {
    let mut sections = vec![format!("{title}: {description}")];
    push_optional_section(&mut sections, "Function", function);
    push_bulleted_section(&mut sections, "Evidence", evidence);
    push_optional_section(&mut sections, "Impact", impact);
    push_bulleted_section(&mut sections, "Recommendation", hardening_notes);
    push_optional_section(&mut sections, "Reasoning", reasoning);
    sections.push("Systems hunt artifact: pending".to_string());
    sections.join("\n\n")
}

fn push_optional_section(sections: &mut Vec<String>, label: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        sections.push(format!("{label}: {value}"));
    }
}

fn push_bulleted_section(sections: &mut Vec<String>, label: &str, values: &[String]) {
    let values = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() {
        return;
    }

    let mut block = format!("{label}:");
    for value in values {
        block.push_str("\n  - ");
        block.push_str(value);
    }
    sections.push(block);
}
