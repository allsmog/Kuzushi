use super::prelude::*;
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
        let severity = parse_severity(string_field(object.get("severity")));
        let cwe = string_or_first_array(object.get("cwe")).unwrap_or_else(|| "unknown".to_string());
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
            format!(
                "{title}: {message}\n\nReasoning: {}\nTrigger: {}\nSystems hunt artifact: pending",
                string_field(object.get("reasoning")),
                string_array(object.get("triggerSequence")).join(" -> ")
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
            "cwe": string_array(object.get("cwe")),
            "severity": severity.as_str(),
            "filePath": file_path,
            "startLine": start_line,
            "surfaceId": surface.map(|surface| surface.id.clone()).unwrap_or_default(),
            "surfaceKind": surface.map(|surface| surface.kind.clone()).unwrap_or_else(|| "unknown".to_string()),
            "lenses": string_array(object.get("lenses")),
            "violatedInvariantIds": string_array(object.get("violatedInvariantIds")),
            "violatedInvariant": string_field(object.get("violatedInvariant")),
            "triggerHypothesisIds": string_array(object.get("triggerHypothesisIds")),
            "triggerSequence": string_array(object.get("triggerSequence")),
            "stateMachine": string_array(object.get("stateMachine")),
            "boundaryAssignments": object.get("boundaryAssignments").cloned().unwrap_or_else(|| json!({})),
            "attackerControlledFields": string_array(object.get("attackerControlledFields")),
            "memoryPrimitive": string_field(object.get("memoryPrimitive")),
            "hardeningNotes": string_array(object.get("hardeningNotes")),
            "cheapVerifiable": object.get("cheapVerifiable").and_then(Value::as_bool).unwrap_or(false),
            "reasoning": string_field(object.get("reasoning")),
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
