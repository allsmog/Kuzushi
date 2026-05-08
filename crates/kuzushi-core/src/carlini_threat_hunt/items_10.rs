use super::prelude::*;
use super::*;

pub(crate) fn normalize_findings(
    raw: Value,
    target: &Path,
    max_findings: usize,
    actor_fingerprint: &str,
) -> Result<Vec<Finding>> {
    let findings_value = match raw {
        Value::Object(object) => object
            .get("findings")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        Value::Array(items) => Value::Array(items),
        _ => {
            anyhow::bail!(
                "carlini-threat-hunt output parse failed: expected object or findings array"
            )
        }
    };
    let Value::Array(items) = findings_value else {
        anyhow::bail!("carlini-threat-hunt output parse failed: findings must be an array");
    };

    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
            .unwrap_or_else(|| "carlini-threat-hunt/finding".to_string());
        let Some(file_path) = read_object_string(&object, &["filePath", "file_path"]) else {
            continue;
        };
        let Some(file_path) = normalize_file_path(target, &file_path) else {
            continue;
        };
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .filter(|value| *value > 0)
            .unwrap_or(1) as u32;
        let end_line = read_object_u64(&object, &["endLine", "end_line"])
            .filter(|value| *value > 0)
            .map(|value| value as u32);
        let severity = carlini_severity(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or("WARNING"),
        );
        let mut message =
            read_object_string(&object, &["message"]).unwrap_or_else(|| rule_id.clone());
        if let Some(evidence) = read_object_string(&object, &["evidence"]) {
            message.push_str("\n\nEvidence: ");
            message.push_str(&evidence);
        }
        if let Some(confidence) = read_object_string(&object, &["confidence"]) {
            message.push_str("\nConfidence: ");
            message.push_str(&confidence);
        }
        if let Some(likelihood) = read_object_string(&object, &["likelihood"]) {
            message.push_str("\nLikelihood: ");
            message.push_str(&likelihood);
        }
        if let Some(impact) = read_object_string(&object, &["impact"]) {
            message.push_str("\nImpact: ");
            message.push_str(&impact);
        }
        let cwe = read_object_string_array(&object, &["cwe"]);
        if !cwe.is_empty() {
            message.push_str("\nCWE: ");
            message.push_str(&cwe.join(", "));
        }
        let mut finding = Finding::new_tool(
            MODULE_ID, rule_id, file_path, start_line, end_line, severity, message,
        );
        finding.actor_fingerprint = Some(actor_fingerprint.to_string());
        findings.push(finding);
    }
    Ok(findings)
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
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;
    Ok(Some(CarliniThreatHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}
