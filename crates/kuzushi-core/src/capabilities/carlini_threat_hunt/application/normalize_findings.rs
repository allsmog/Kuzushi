use super::*;

/// Normalization outcome: what survived plus WHY each rejected entry was
/// dropped. Rejections are never silent — callers trace and count them.
pub(crate) struct NormalizedCarliniFindings {
    pub(crate) kept: Vec<Finding>,
    pub(crate) rejected: Vec<String>,
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
        rejected: Vec::new(),
    };
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            normalized
                .rejected
                .push("findings entry is not a JSON object".to_string());
            continue;
        };
        match carlini_finding_from_object(object, target, actor_fingerprint) {
            Ok(finding) => normalized.kept.push(finding),
            Err(reason) => normalized.rejected.push(reason),
        }
    }
    Ok(normalized)
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
    object: Map<String, Value>,
    target: &Path,
    actor_fingerprint: &str,
) -> Result<Finding, String> {
    let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
        .unwrap_or_else(|| "carlini-threat-hunt/finding".to_string());
    let Some((file_path, start_line, end_line)) = carlini_location(&object, target) else {
        return Err(rejected_finding_reason(&object));
    };
    let severity = carlini_severity(
        read_object_string(&object, &["severity"])
            .as_deref()
            .unwrap_or(""),
    );
    let message = carlini_message(&object, &rule_id);
    let mut finding = Finding::new_tool(
        MODULE_ID, rule_id, file_path, start_line, end_line, severity, message,
    );
    finding.actor_fingerprint = Some(actor_fingerprint.to_string());
    Ok(finding)
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
    let file_path = normalize_file_path(target, &file_path)?;
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
    ["location", "evidence", "source", "sink"]
        .iter()
        .filter_map(|key| read_object_string(object, &[key]))
        .find_map(|text| first_existing_file_line(&text, target))
}

fn first_existing_file_line(text: &str, target: &Path) -> Option<(String, u32, Option<u32>)> {
    text.split(|character: char| {
        character.is_whitespace() || "()[]{}<>\"'`,;".contains(character)
    })
    .filter_map(file_line_candidate)
    .find_map(|(path, line)| {
        let normalized = normalize_file_path(target, path)?;
        target
            .join(&normalized)
            .is_file()
            .then(|| (normalized, line.unwrap_or(1), None))
    })
}

fn file_line_candidate(token: &str) -> Option<(&str, Option<u32>)> {
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
    read_object_u64(object, keys).filter(|value| *value > 0)
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
    store.with_run_lifecycle(&run_id, target, || {
        for finding in findings {
            store.insert_finding(&run_id, finding)?;
        }
        Ok(((), findings.len()))
    })?;
    Ok(Some(CarliniThreatHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}
