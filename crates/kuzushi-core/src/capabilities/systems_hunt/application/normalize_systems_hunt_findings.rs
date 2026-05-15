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
        let violated_invariant_ids = string_array(object.get("violatedInvariantIds"));
        let violated_invariant = string_field(object.get("violatedInvariant"));
        let trigger_hypothesis_ids = string_array(object.get("triggerHypothesisIds"));
        let trigger_sequence = string_array(object.get("triggerSequence"));
        let cheap_verifiable = object
            .get("cheapVerifiable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let corroboration_status = string_field(object.get("corroborationStatus"));
        if is_under_evidenced_systems_hunt_candidate(
            &evidence,
            &violated_invariant_ids,
            &violated_invariant,
            &trigger_hypothesis_ids,
            &trigger_sequence,
            cheap_verifiable,
            &corroboration_status,
        ) {
            let artifact_path = write_rejected_systems_candidate_artifact(artifact_root, object)?;
            artifacts.push(path_relative_to(target, &artifact_path));
            continue;
        }
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
            "violatedInvariantIds": violated_invariant_ids,
            "violatedInvariant": violated_invariant,
            "triggerHypothesisIds": trigger_hypothesis_ids,
            "triggerSequence": trigger_sequence,
            "stateMachine": string_array(object.get("stateMachine")),
            "boundaryAssignments": object.get("boundaryAssignments").cloned().unwrap_or_else(|| json!({})),
            "attackerControlledFields": attacker_inputs,
            "memoryPrimitive": string_field(object.get("memoryPrimitive")),
            "hardeningNotes": hardening_notes,
            "cheapVerifiable": cheap_verifiable,
            "reasoning": reasoning,
            "analysisPath": object.get("analysisPath").cloned().unwrap_or_else(|| json!([])),
            "guardLocations": object.get("guardLocations").cloned().unwrap_or_else(|| json!([])),
            "counterexampleNotes": string_array(object.get("counterexampleNotes")),
            "relatedFiles": surface.map(|surface| vec![surface.file_path.clone()]).unwrap_or_default(),
            "corroborationStatus": corroboration_status,
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

fn is_under_evidenced_systems_hunt_candidate(
    evidence: &[String],
    violated_invariant_ids: &[String],
    violated_invariant: &str,
    trigger_hypothesis_ids: &[String],
    trigger_sequence: &[String],
    cheap_verifiable: bool,
    corroboration_status: &str,
) -> bool {
    if cheap_verifiable || is_positive_corroboration_status(corroboration_status) {
        return false;
    }

    evidence.is_empty()
        && violated_invariant_ids.is_empty()
        && violated_invariant.trim().is_empty()
        && trigger_hypothesis_ids.is_empty()
        && trigger_sequence.is_empty()
}

fn is_positive_corroboration_status(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "confirmed" | "corroborated" | "validated" | "code-cited" | "code_cited"
    )
}

fn write_rejected_systems_candidate_artifact(
    artifact_root: &Path,
    object: &serde_json::Map<String, Value>,
) -> Result<PathBuf> {
    let fingerprint = rejected_candidate_fingerprint(object);
    let artifact = json!({
        "fingerprint": fingerprint,
        "rejected": true,
        "rejectionReason": "under-evidenced systems-hunt candidate: no evidence, invariant link, trigger link, cheap verification flag, or corroboration status",
        "candidate": object,
    });
    write_artifact(artifact_root, &fingerprint, &artifact)
}

fn rejected_candidate_fingerprint(object: &serde_json::Map<String, Value>) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    "systems-hunt-rejected-candidate".hash(&mut hasher);
    object
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .hash(&mut hasher);
    object
        .get("filePath")
        .or_else(|| object.get("file_path"))
        .or_else(|| object.get("path"))
        .or_else(|| object.get("file"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .hash(&mut hasher);
    object
        .get("startLine")
        .or_else(|| object.get("line"))
        .map(Value::to_string)
        .unwrap_or_default()
        .hash(&mut hasher);
    format!("systems-hunt-rejected-{:016x}", hasher.finish())
}
