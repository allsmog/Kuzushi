use super::prelude::*;
use super::*;

pub(crate) fn normalize_deep_semantic_findings(
    raw: Value,
    target: &Path,
    artifact_root: &Path,
    max_findings: usize,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut artifacts = Vec::new();
    let Some(items) = raw.get("findings").and_then(Value::as_array) else {
        return Ok((findings, artifacts));
    };
    for item in items.iter().take(max_findings) {
        let Some(object) = item.as_object() else {
            continue;
        };
        let title = string_field(object.get("title"));
        let file_path = normalize_relative_path(string_field(object.get("filePath")));
        let message = string_field(object.get("message"));
        if title.is_empty() || file_path.is_empty() || message.is_empty() {
            continue;
        }
        let start_line = object
            .get("startLine")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1) as u32;
        let cwe = string_or_first_array(object.get("cwe")).unwrap_or_else(|| "unknown".to_string());
        let mut finding = Finding::new_tool(
            "deep-semantic-hunt",
            format!("deep-semantic/{}", sanitize_rule_segment(&cwe)),
            file_path.clone(),
            start_line,
            None,
            parse_severity(string_field(object.get("severity"))),
            format!(
                "[{cwe}] {title}: {message}\n\nReasoning: {}\nSystems hunt artifact: pending",
                string_field(object.get("reasoningChain"))
            ),
        );
        finding.title = title;
        let artifact = json!({
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "cwe": [cwe],
            "severity": finding.severity.as_str(),
            "filePath": file_path,
            "startLine": start_line,
            "reasoning": string_field(object.get("reasoningChain")),
            "analysisPath": object.get("analysisPath").cloned().unwrap_or_else(|| json!([])),
            "corroborationStatus": "deep-semantic",
        });
        let artifact_path = write_artifact(artifact_root, &finding.fingerprint, &artifact)?;
        let relative_artifact = path_relative_to(target, &artifact_path);
        finding.message = finding.message.replace(
            "Systems hunt artifact: pending",
            &format!("Systems hunt artifact: {relative_artifact}"),
        );
        artifacts.push(relative_artifact);
        findings.push(finding);
    }
    Ok((findings, artifacts))
}

pub(crate) fn persist_systems_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<SystemsHuntPersistedRun>> {
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

    Ok(Some(SystemsHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}
