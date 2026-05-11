use super::*;

pub(crate) fn normalize_systems_hunt_findings(
    raw: Value,
    target: &Path,
    context: &SystemsContextOutput,
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
        let severity = parse_severity(string_field(object.get("severity")));
        let evidence = first_string_array_field(
            object,
            &["evidence", "evidenceAnchors", "supporting_evidence"],
        );
        let attacker_inputs = first_string_array_field(
            object,
            &[
                "attackerControlledFields",
                "attackerInputs",
                "attacker_inputs",
                "attacker_input",
            ],
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
        let function = optional_string(first_string_field(
            object,
            &["function", "functionName", "fn"],
        ));
        let domain = first_string_array_field(object, &["domains", "domain"]);
        let reasoning = optional_string(first_string_field(object, &["reasoning", "rationale"]));
        let cwe_list = first_string_array_field(object, &["cwe", "cwes"]);
        let cwe = cwe_list
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let rule_id = object
            .get("ruleId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("systems-hunt/{}", sanitize_rule_segment(&cwe)));
        let mut finding = Finding::new_tool(
            "systems-hunt",
            rule_id,
            file_path.clone(),
            start_line,
            None,
            severity,
            build_finding_message(
                &title,
                &message,
                function.as_deref(),
                &evidence,
                impact.as_deref(),
                &hardening_notes,
                reasoning.as_deref(),
            ),
        );
        finding.title = title;

        let surface = context
            .surfaces
            .iter()
            .find(|surface| surface.file_path == file_path)
            .or_else(|| context.surfaces.first());
        let artifact = json!({
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "cwe": cwe_list,
            "severity": severity.as_str(),
            "filePath": file_path,
            "startLine": start_line,
            "function": function,
            "domain": domain,
            "description": message,
            "evidence": evidence,
            "impact": impact,
            "recommendation": hardening_notes,
            "surfaceId": surface.map(|surface| surface.id.clone()).unwrap_or_default(),
            "surfaceKind": surface.map(|surface| surface.kind.clone()).unwrap_or_else(|| "unknown".to_string()),
            "lenses": string_array(object.get("lenses")),
            "violatedInvariantIds": string_array(object.get("violatedInvariantIds")),
            "violatedInvariant": string_field(object.get("violatedInvariant")),
            "triggerHypothesisIds": string_array(object.get("triggerHypothesisIds")),
            "triggerSequence": string_array(object.get("triggerSequence")),
            "stateMachine": string_array(object.get("stateMachine")),
            "boundaryAssignments": object.get("boundaryAssignments").cloned().unwrap_or_else(|| json!({})),
            "attackerControlledFields": attacker_inputs,
            "memoryPrimitive": string_field(object.get("memoryPrimitive")),
            "hardeningNotes": hardening_notes,
            "cheapVerifiable": object.get("cheapVerifiable").and_then(Value::as_bool).unwrap_or(false),
            "reasoning": reasoning,
            "analysisPath": object.get("analysisPath").cloned().unwrap_or_else(|| json!([])),
            "guardLocations": object.get("guardLocations").cloned().unwrap_or_else(|| json!([])),
            "counterexampleNotes": string_array(object.get("counterexampleNotes")),
            "relatedFiles": surface.map(|surface| vec![surface.file_path.clone()]).unwrap_or_default(),
            "corroborationStatus": string_field(object.get("corroborationStatus")),
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
