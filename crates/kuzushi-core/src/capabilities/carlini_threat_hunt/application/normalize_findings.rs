use super::*;

pub(crate) fn normalize_findings(
    raw: Value,
    target: &Path,
    max_findings: usize,
    actor_fingerprint: &str,
) -> Result<Vec<Finding>> {
    let items = carlini_findings_items(raw)?;
    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        if let Some(finding) = carlini_finding_from_object(object, target, actor_fingerprint) {
            findings.push(finding);
        }
    }
    Ok(findings)
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
) -> Option<Finding> {
    let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
        .unwrap_or_else(|| "carlini-threat-hunt/finding".to_string());
    let (file_path, start_line, end_line) = carlini_location(&object, target)?;
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
    Some(finding)
}

fn carlini_location(
    object: &Map<String, Value>,
    target: &Path,
) -> Option<(String, u32, Option<u32>)> {
    let file_path = read_object_string(object, &["filePath", "file_path"])?;
    let file_path = normalize_file_path(target, &file_path)?;
    let start_line = read_positive_line(object, &["startLine", "start_line"]).unwrap_or(1) as u32;
    let end_line = read_positive_line(object, &["endLine", "end_line"]).map(|value| value as u32);
    Some((file_path, start_line, end_line))
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
