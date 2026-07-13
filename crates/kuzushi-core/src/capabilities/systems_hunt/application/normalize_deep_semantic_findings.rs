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
        let Some((mut finding, artifact)) =
            item.as_object().and_then(normalized_deep_semantic_item)
        else {
            continue;
        };
        let artifact_path = write_artifact(target, artifact_root, &finding.fingerprint, &artifact)?;
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

struct DeepSemanticFields {
    title: String,
    file_path: String,
    message: String,
    start_line: u32,
    cwes: Vec<String>,
    evidence: Vec<String>,
    hardening_notes: Vec<String>,
    impact: Option<String>,
    reasoning: Option<String>,
}

fn normalized_deep_semantic_item(
    object: &serde_json::Map<String, Value>,
) -> Option<(Finding, Value)> {
    let fields = deep_semantic_fields(object)?;
    let cwe = fields
        .cwes
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let mut finding = deep_semantic_finding(object, &fields, &cwe);
    finding.title = fields.title.clone();
    let artifact = deep_semantic_artifact(object, &finding, fields);
    Some((finding, artifact))
}

fn deep_semantic_fields(object: &serde_json::Map<String, Value>) -> Option<DeepSemanticFields> {
    let title = first_string_field(object, &["title", "name"]);
    let file_path = normalize_relative_path(first_string_field(
        object,
        &["filePath", "file_path", "path", "file"],
    ));
    let message = collect_finding_body(object, &title);
    if title.is_empty() || file_path.is_empty() || message.is_empty() {
        return None;
    }
    Some(DeepSemanticFields {
        title,
        file_path,
        message,
        start_line: deep_semantic_start_line(object),
        cwes: first_string_array_field(object, &["cwe", "cwes"]),
        evidence: deep_semantic_evidence(object),
        hardening_notes: deep_semantic_hardening_notes(object),
        impact: deep_semantic_impact(object),
        reasoning: optional_string(first_string_field(
            object,
            &["reasoningChain", "reasoning", "rationale"],
        )),
    })
}

fn deep_semantic_start_line(object: &serde_json::Map<String, Value>) -> u32 {
    first_line_field(
        object,
        &[
            "startLine",
            "start_line",
            "line",
            "lines",
            "anchorLine",
            "line_start",
            "lineStart",
            "anchorLines",
            "lineRange",
            "line_range",
        ],
    )
    .max(1) as u32
}

fn deep_semantic_evidence(object: &serde_json::Map<String, Value>) -> Vec<String> {
    first_string_array_field(
        object,
        &["evidence", "evidenceAnchors", "supporting_evidence"],
    )
}

fn deep_semantic_hardening_notes(object: &serde_json::Map<String, Value>) -> Vec<String> {
    first_string_array_field(
        object,
        &[
            "hardeningNotes",
            "missingHardening",
            "missing_hardening",
            "recommendation",
            "recommendations",
            "fix",
        ],
    )
}

fn deep_semantic_impact(object: &serde_json::Map<String, Value>) -> Option<String> {
    optional_string(first_string_field(
        object,
        &[
            "impact",
            "exploitability",
            "exploitability_notes",
            "exploitabilityNotes",
        ],
    ))
}

fn deep_semantic_finding(
    object: &serde_json::Map<String, Value>,
    fields: &DeepSemanticFields,
    cwe: &str,
) -> Finding {
    Finding::new_tool(
        "deep-semantic-hunt",
        format!("deep-semantic/{}", sanitize_rule_segment(cwe)),
        fields.file_path.clone(),
        fields.start_line,
        None,
        parse_severity(string_field(object.get("severity"))),
        build_finding_message(
            &format!("[{cwe}] {}", fields.title),
            &fields.message,
            None,
            &fields.evidence,
            fields.impact.as_deref(),
            &fields.hardening_notes,
            fields.reasoning.as_deref(),
        ),
    )
}

fn deep_semantic_artifact(
    object: &serde_json::Map<String, Value>,
    finding: &Finding,
    fields: DeepSemanticFields,
) -> Value {
    json!({
        "fingerprint": finding.fingerprint,
        "title": fields.title,
        "cwe": fields.cwes,
        "severity": finding.severity.as_str(),
        "filePath": fields.file_path,
        "startLine": fields.start_line,
        "description": fields.message,
        "evidence": fields.evidence,
        "impact": fields.impact,
        "recommendation": fields.hardening_notes,
        "reasoning": fields.reasoning,
        "analysisPath": object.get("analysisPath").cloned().unwrap_or_else(|| json!([])),
        "corroborationStatus": "deep-semantic",
    })
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
    store.with_run_lifecycle(&run_id, target, || {
        for finding in findings {
            store.insert_finding(&run_id, finding)?;
        }
        Ok(((), findings.len()))
    })?;

    Ok(Some(SystemsHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}
