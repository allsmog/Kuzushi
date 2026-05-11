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
        let title = first_string_field(object, &["title", "name"]);
        let file_path = normalize_relative_path(first_string_field(
            object,
            &["filePath", "file_path", "path", "file"],
        ));
        let message = collect_finding_body(object, &title);
        if title.is_empty() || file_path.is_empty() || message.is_empty() {
            continue;
        }
        let start_line = first_line_field(
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
        .max(1) as u32;
        let cwe_list = first_string_array_field(object, &["cwe", "cwes"]);
        let cwe = cwe_list
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let evidence = first_string_array_field(
            object,
            &["evidence", "evidenceAnchors", "supporting_evidence"],
        );
        let hardening_notes = first_string_array_field(
            object,
            &[
                "hardeningNotes",
                "missingHardening",
                "missing_hardening",
                "recommendation",
                "recommendations",
                "fix",
            ],
        );
        let impact = optional_string(first_string_field(
            object,
            &[
                "impact",
                "exploitability",
                "exploitability_notes",
                "exploitabilityNotes",
            ],
        ));
        let reasoning = optional_string(first_string_field(
            object,
            &["reasoningChain", "reasoning", "rationale"],
        ));
        let message_title = format!("[{cwe}] {title}");
        let mut finding = Finding::new_tool(
            "deep-semantic-hunt",
            format!("deep-semantic/{}", sanitize_rule_segment(&cwe)),
            file_path.clone(),
            start_line,
            None,
            parse_severity(string_field(object.get("severity"))),
            build_finding_message(
                &message_title,
                &message,
                None,
                &evidence,
                impact.as_deref(),
                &hardening_notes,
                reasoning.as_deref(),
            ),
        );
        finding.title = title;
        let artifact = json!({
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "cwe": cwe_list,
            "severity": finding.severity.as_str(),
            "filePath": file_path,
            "startLine": start_line,
            "description": message,
            "evidence": evidence,
            "impact": impact,
            "recommendation": hardening_notes,
            "reasoning": reasoning,
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
