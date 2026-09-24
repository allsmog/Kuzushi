use super::*;

/// Normalization outcome: what survived plus WHY each rejected entry was
/// dropped. Rejections are never silent — callers trace and count them.
pub(crate) struct NormalizedCarliniFindings {
    pub(crate) kept: Vec<Finding>,
    pub(crate) rejected_count: usize,
    pub(crate) rejected: Vec<String>,
}

pub(crate) const MAX_CARLINI_REJECTION_REASONS: usize = 10;

impl NormalizedCarliniFindings {
    fn reject(&mut self, reason: String) {
        self.rejected_count += 1;
        if self.rejected.len() < MAX_CARLINI_REJECTION_REASONS {
            self.rejected.push(bounded_text(&reason, 240));
        }
    }
}

pub(crate) fn normalize_findings(
    raw: Value,
    target: &Path,
    max_findings: usize,
    actor_fingerprint: &str,
) -> Result<NormalizedCarliniFindings> {
    let items = carlini_findings_items(raw)?;
    let mut normalized = NormalizedCarliniFindings {
        kept: Vec::new(),
        rejected_count: 0,
        rejected: Vec::new(),
    };
    for item in items {
        match carlini_finding_from_value(item, target, actor_fingerprint) {
            Ok(finding) if normalized.kept.len() < max_findings => normalized.kept.push(finding),
            Ok(_) => {}
            Err(reason) => normalized.reject(reason),
        }
    }
    Ok(normalized)
}

fn carlini_finding_from_value(
    item: Value,
    target: &Path,
    actor_fingerprint: &str,
) -> Result<Finding, String> {
    let Value::Object(object) = item else {
        return Err("findings entry is not a JSON object".to_string());
    };
    carlini_finding_from_object(object, target, actor_fingerprint)
}

fn carlini_findings_items(raw: Value) -> Result<Vec<Value>> {
    match raw {
        Value::Object(object) => carlini_findings_items_from_object(object),
        Value::Array(items) => Ok(items),
        _ => anyhow::bail!(
            "carlini-threat-hunt output parse failed: expected object or findings array"
        ),
    }
}

fn carlini_findings_items_from_object(object: Map<String, Value>) -> Result<Vec<Value>> {
    let Some(findings) = object.get("findings") else {
        anyhow::bail!("carlini-threat-hunt output parse failed: object missing findings array");
    };
    let Value::Array(items) = findings.clone() else {
        anyhow::bail!("carlini-threat-hunt output parse failed: findings must be an array");
    };
    Ok(items)
}

fn carlini_finding_from_object(
    mut object: Map<String, Value>,
    target: &Path,
    actor_fingerprint: &str,
) -> Result<Finding, String> {
    normalize_carlini_finding_contract(&mut object, target)?;
    let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
        .unwrap_or_else(|| "carlini-threat-hunt/finding".to_string());
    let file_path = read_object_string(&object, &["filePath"]).expect("normalized filePath");
    let start_line = read_positive_line(&object, &["startLine"]).expect("normalized startLine");
    let end_line = read_positive_line(&object, &["endLine"]);
    let severity = read_object_string(&object, &["severity"])
        .map(|value| carlini_severity(&value))
        .expect("normalized severity");
    let message = carlini_message(&object, &rule_id);
    let mut finding = Finding::new_tool(
        MODULE_ID,
        rule_id,
        file_path,
        start_line as u32,
        end_line.map(|line| line as u32),
        severity,
        message,
    );
    finding.actor_fingerprint = Some(actor_fingerprint.to_string());
    Ok(finding)
}

fn normalize_carlini_finding_contract(
    object: &mut Map<String, Value>,
    target: &Path,
) -> Result<(), String> {
    let location =
        carlini_location(object, target).ok_or_else(|| rejected_finding_reason(object))?;
    let severity = normalized_carlini_severity(object)?;
    let title = required_carlini_text(object, &["title", "message", "ruleId", "rule_id"], "title")?;
    let message = required_carlini_text(object, &["message", "title"], "message")?;
    let rule_id = read_object_string(object, &["ruleId", "rule_id"])
        .unwrap_or_else(|| "carlini-threat-hunt/finding".to_string());
    object.insert("title".to_string(), Value::String(title));
    object.insert("message".to_string(), Value::String(message));
    object.insert("severity".to_string(), Value::String(severity));
    object.insert("ruleId".to_string(), Value::String(rule_id));
    apply_carlini_location(object, location);
    normalize_optional_carlini_text(object);
    normalize_carlini_cwes(object);
    Ok(())
}

fn normalized_carlini_severity(object: &Map<String, Value>) -> Result<String, String> {
    let value = read_object_string(object, &["severity"])
        .ok_or_else(|| "finding is missing required severity".to_string())?;
    let severity = carlini_severity(&value);
    (severity != Severity::Unknown)
        .then(|| severity.as_str().to_string())
        .ok_or_else(|| format!("finding has unsupported severity {value:?}"))
}

fn required_carlini_text(
    object: &Map<String, Value>,
    keys: &[&str],
    field: &str,
) -> Result<String, String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(compact_carlini_value))
        .ok_or_else(|| format!("finding is missing required {field}"))
}

fn apply_carlini_location(object: &mut Map<String, Value>, location: (String, u32, Option<u32>)) {
    object.insert("filePath".to_string(), Value::String(location.0));
    object.insert("startLine".to_string(), json!(location.1));
    if let Some(end_line) = location.2 {
        object.insert("endLine".to_string(), json!(end_line));
    } else {
        object.remove("endLine");
        object.remove("end_line");
    }
}

fn normalize_optional_carlini_text(object: &mut Map<String, Value>) {
    for key in ["evidence", "confidence", "likelihood", "impact"] {
        match object.get(key).and_then(compact_carlini_value) {
            Some(text) => object.insert(key.to_string(), Value::String(text)),
            None => object.remove(key),
        };
    }
}

fn normalize_carlini_cwes(object: &mut Map<String, Value>) {
    let Some(cwe) = object.get("cwe") else {
        return;
    };
    let values: Vec<String> = match cwe {
        Value::Array(items) => items.iter().filter_map(compact_carlini_value).collect(),
        value => compact_carlini_value(value).into_iter().collect(),
    };
    object.insert("cwe".to_string(), json!(values));
}

fn rejected_finding_reason(object: &Map<String, Value>) -> String {
    let label = read_object_string(object, &["title", "ruleId", "rule_id", "message"])
        .unwrap_or_else(|| "untitled".to_string());
    let label = label.chars().take(80).collect::<String>();
    format!("no usable filePath/startLine location ({label})")
}

fn carlini_location(
    object: &Map<String, Value>,
    target: &Path,
) -> Option<(String, u32, Option<u32>)> {
    if let Some(location) = declared_carlini_location(object, target) {
        return Some(location);
    }
    location_from_narrative_fields(object, target)
}

fn declared_carlini_location(
    object: &Map<String, Value>,
    target: &Path,
) -> Option<(String, u32, Option<u32>)> {
    let file_path = read_object_string(object, &["filePath", "file_path", "file", "path"])?;
    let file_path = normalize_declared_file_path(target, &file_path)?;
    let start_line =
        read_positive_line(object, &["startLine", "start_line", "line"]).unwrap_or(1) as u32;
    let end_line = read_positive_line(object, &["endLine", "end_line"]).map(|value| value as u32);
    Some((file_path, start_line, end_line))
}

/// Lenient fallback: the actor anchored the finding in prose instead of the
/// contract fields. Recover the first `path[:line]` token that names a real
/// file inside the target rather than dropping a paid finding.
fn location_from_narrative_fields(
    object: &Map<String, Value>,
    target: &Path,
) -> Option<(String, u32, Option<u32>)> {
    ["location", "evidence", "source", "sink", "trace", "hops"]
        .iter()
        .filter_map(|key| object.get(*key))
        .find_map(|value| location_from_evidence_value(value, target))
}

fn location_from_evidence_value(
    value: &Value,
    target: &Path,
) -> Option<(String, u32, Option<u32>)> {
    location_from_evidence_value_at_depth(value, target, 0)
}

fn location_from_evidence_value_at_depth(
    value: &Value,
    target: &Path,
    depth: usize,
) -> Option<(String, u32, Option<u32>)> {
    if depth >= 16 {
        return None;
    }
    match value {
        Value::String(text) => first_existing_file_line(text, target),
        Value::Array(items) => items
            .iter()
            .find_map(|item| location_from_evidence_value_at_depth(item, target, depth + 1)),
        Value::Object(object) => declared_carlini_location(object, target).or_else(|| {
            object
                .values()
                .find_map(|item| location_from_evidence_value_at_depth(item, target, depth + 1))
        }),
        _ => None,
    }
}

fn first_existing_file_line(text: &str, target: &Path) -> Option<(String, u32, Option<u32>)> {
    text.split(|character: char| character.is_whitespace() || "()[]{}<>\"'`,;".contains(character))
        .filter_map(file_line_candidate)
        .find_map(|(path, line)| {
            let normalized = normalize_file_path(target, path)?;
            is_target_file(target, &normalized).then(|| (normalized, line.unwrap_or(1), None))
        })
}

fn normalize_declared_file_path(target: &Path, file_path: &str) -> Option<String> {
    let normalized = normalize_file_path(target, file_path)?;
    let candidate = target.join(&normalized);
    (!candidate.exists() || is_target_file(target, &normalized)).then_some(normalized)
}

fn is_target_file(target: &Path, relative: &str) -> bool {
    let Ok(root) = target.canonicalize() else {
        return false;
    };
    let Ok(candidate) = target.join(relative).canonicalize() else {
        return false;
    };
    candidate.starts_with(root) && candidate.is_file()
}

fn file_line_candidate(token: &str) -> Option<(&str, Option<u32>)> {
    let token = token.trim_matches(|character| ".!?".contains(character));
    let (path, line) = match token.rsplit_once(':') {
        Some((path, digits)) => match digits.parse::<u32>() {
            Ok(line) if line > 0 => (path, Some(line)),
            _ => (token, None),
        },
        None => (token, None),
    };
    (path.contains('.') && path.len() > 2).then_some((path, line))
}

fn read_positive_line(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
        .filter(|value| *value > 0 && *value <= u32::MAX as u64)
}

fn compact_carlini_value(value: &Value) -> Option<String> {
    compact_carlini_value_at_depth(value, 0)
}

fn compact_carlini_value_at_depth(value: &Value, depth: usize) -> Option<String> {
    if depth >= 16 {
        return None;
    }
    let text = match value {
        Value::String(text) => text.trim().to_string(),
        Value::Array(items) => compact_carlini_values(items.iter(), depth + 1),
        Value::Object(object) => compact_carlini_values(object.values(), depth + 1),
        Value::Number(number) => number.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => String::new(),
    };
    let bounded = bounded_text(&text, 4096);
    (!bounded.is_empty()).then_some(bounded)
}

fn compact_carlini_values<'a>(values: impl Iterator<Item = &'a Value>, depth: usize) -> String {
    values
        .filter_map(|value| compact_carlini_value_at_depth(value, depth))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn carlini_message(object: &Map<String, Value>, rule_id: &str) -> String {
    let mut message =
        read_object_string(object, &["message"]).unwrap_or_else(|| rule_id.to_string());
    append_carlini_message_field(&mut message, object, "evidence", "\n\nEvidence: ");
    append_carlini_message_field(&mut message, object, "confidence", "\nConfidence: ");
    append_carlini_message_field(&mut message, object, "likelihood", "\nLikelihood: ");
    append_carlini_message_field(&mut message, object, "impact", "\nImpact: ");
    append_carlini_cwes(&mut message, object);
    message
}

fn append_carlini_message_field(
    message: &mut String,
    object: &Map<String, Value>,
    key: &str,
    prefix: &str,
) {
    if let Some(value) = read_object_string(object, &[key]) {
        message.push_str(prefix);
        message.push_str(&value);
    }
}

fn append_carlini_cwes(message: &mut String, object: &Map<String, Value>) {
    let cwe = read_object_string_array(object, &["cwe"]);
    if cwe.is_empty() {
        return;
    }
    message.push_str("\nCWE: ");
    message.push_str(&cwe.join(", "));
}

pub(crate) fn persist_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<CarliniThreatHuntPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = ctx.finding_run_id();
    crate::findings::commit_observed_findings(
        store,
        ctx.run_observation().as_ref(),
        &run_id,
        target,
        findings,
    )?;
    Ok(Some(CarliniThreatHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}
