use super::*;

pub(crate) fn normalize_agentic_sast_findings(
    raw: Value,
    target: &Path,
    max_findings: usize,
    whitebox_static: bool,
) -> Result<Vec<Finding>> {
    let items = agentic_findings_items(raw)?;
    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        findings.push(agentic_finding_from_object(object, target, whitebox_static)?);
    }
    Ok(findings)
}

fn agentic_findings_items(raw: Value) -> Result<Vec<Value>> {
    match raw {
        Value::Object(object) => agentic_findings_items_from_object(object),
        Value::Array(items) => Ok(items),
        _ => anyhow::bail!("agentic-sast output parse failed: expected an object or findings array"),
    }
}

fn agentic_findings_items_from_object(object: Map<String, Value>) -> Result<Vec<Value>> {
    let Some(findings) = object.get("findings") else {
        anyhow::bail!("agentic-sast output parse failed: object missing findings array");
    };
    let Value::Array(items) = findings.clone() else {
        anyhow::bail!("agentic-sast output parse failed: findings must be an array");
    };
    Ok(items)
}

fn agentic_finding_from_object(
    object: Map<String, Value>,
    target: &Path,
    whitebox_static: bool,
) -> Result<Finding> {
    let raw_item = Value::Object(object.clone());
    let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
        .unwrap_or_else(|| "agentic-sast/finding".to_string());
    let (file_path, start_line, end_line) = agentic_location(&object, target);
    let severity = agentic_severity(
        read_object_string(&object, &["severity"])
            .as_deref()
            .unwrap_or(""),
    );
    let message = agentic_message(&object, &rule_id);
    let mut finding = Finding::new_tool(
        "agentic", rule_id, file_path, start_line, end_line, severity, message,
    );
    apply_agentic_enrichment(&mut finding, &object);
    apply_agentic_static_policy(&mut finding, target, &raw_item, whitebox_static)?;
    Ok(finding)
}

/// Producer-supplied enrichment (title/impact/category/exploit scenario/
/// preconditions/recommendation) rides the finding record so triage, chains,
/// and exports see it. The precondition severity ceiling is enforced in code
/// at this chokepoint, mirroring the ledger-import ingest contract.
fn apply_agentic_enrichment(finding: &mut Finding, object: &Map<String, Value>) {
    if let Some(title) = read_object_string(object, &["title"]).filter(|t| !t.trim().is_empty()) {
        finding.title = title.trim().to_string();
    }
    finding.impact = read_object_string(object, &["impact"]);
    finding.category = read_object_string(object, &["category"]);
    finding.exploit_scenario = read_object_string(object, &["exploitScenario", "exploit_scenario"]);
    if let Some(recommendation) =
        read_object_string(object, &["recommendation", "recommendedFix", "recommended_fix"])
    {
        finding.remediation = Some(recommendation);
    }
    finding.preconditions = agentic_preconditions(object);
    apply_precondition_ceiling(finding);
}

fn agentic_preconditions(object: &Map<String, Value>) -> Vec<String> {
    let Some(Value::Array(items)) = object.get("preconditions") else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

/// Mechanical ceiling from the closed precondition vocabulary; the cap is
/// recorded in the message, never silently applied.
fn apply_precondition_ceiling(finding: &mut Finding) {
    use crate::findings::ingest_contract::{enforce_severity_ceiling, Precondition};
    let mut capped_by: Option<Precondition> = None;
    let parsed: Vec<Precondition> = finding
        .preconditions
        .iter()
        .filter_map(|entry| Precondition::parse(entry))
        .collect();
    for precondition in parsed {
        let result = enforce_severity_ceiling(finding.severity, Some(precondition));
        if result.tier_capped {
            finding.severity = result.severity;
            capped_by = Some(precondition);
        }
    }
    if let Some(precondition) = capped_by {
        finding.message.push_str(&format!(
            "\nSeverity capped by precondition ceiling ({}).",
            precondition.as_str()
        ));
    }
}

fn agentic_location(object: &Map<String, Value>, target: &Path) -> (String, u32, Option<u32>) {
    let file_path = normalize_reported_file_path(resolve_agentic_schema_file_path(object), target);
    let start_line = agentic_line(object, &["startLine", "start_line"]).unwrap_or(1) as u32;
    let end_line = agentic_line(object, &["endLine", "end_line"]).map(|value| value as u32);
    (file_path, start_line, end_line)
}

fn agentic_line(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    read_object_u64(object, keys)
        .or_else(|| read_nested_object_u64(object, "source", keys))
        .or_else(|| first_citation_u64(object, keys))
        .filter(|value| *value > 0)
}

fn agentic_message(object: &Map<String, Value>, rule_id: &str) -> String {
    let mut message = read_object_string(object, &["message"])
        .or_else(|| read_object_string(object, &["title"]))
        .unwrap_or_else(|| rule_id.to_string());
    append_agentic_evidence(&mut message, object);
    append_agentic_schema_field(&mut message, object, "verdict", "Verdict");
    append_agentic_schema_field(&mut message, object, "staticProofState", "Static proof state");
    append_agentic_schema_object_summary(&mut message, object, "source", "Source");
    append_agentic_schema_object_summary(&mut message, object, "sink", "Sink");
    append_agentic_schema_object_summary(&mut message, object, "path", "Path");
    append_agentic_assessments(&mut message, object);
    append_agentic_schema_field(&mut message, object, "triggerNarrative", "Trigger narrative");
    append_agentic_schema_field(&mut message, object, "impactNarrative", "Impact narrative");
    append_agentic_schema_field(&mut message, object, "recommendedFix", "Recommended fix");
    append_agentic_confidence(&mut message, object);
    message
}

fn append_agentic_assessments(message: &mut String, object: &Map<String, Value>) {
    append_agentic_schema_object_summary(
        message,
        object,
        "sanitizerAssessment",
        "Sanitizer assessment",
    );
    append_agentic_schema_object_summary(message, object, "guardAssessment", "Guard assessment");
}

fn append_agentic_evidence(message: &mut String, object: &Map<String, Value>) {
    let Some(evidence) = read_object_string(object, &["evidence"]) else {
        return;
    };
    if evidence.trim().is_empty() {
        return;
    }
    message.push_str("\n\nEvidence: ");
    message.push_str(evidence.trim());
}

fn append_agentic_confidence(message: &mut String, object: &Map<String, Value>) {
    if let Some(confidence) = read_object_string(object, &["confidence"]) {
        message.push_str("\nConfidence: ");
        message.push_str(confidence.trim());
    }
}

fn apply_agentic_static_policy(
    finding: &mut Finding,
    target: &Path,
    raw_item: &Value,
    whitebox_static: bool,
) -> Result<()> {
    if whitebox_static {
        let validation = validate_agentic_whitebox_static_claim(target, raw_item)?;
        apply_agentic_static_validation(finding, &validation);
    } else if let Some(state) = whitebox_static_proof_state_from_input(raw_item)? {
        finding.set_static_proof_state(unvalidated_agentic_static_state(state));
    }
    Ok(())
}

fn unvalidated_agentic_static_state(state: StaticProofState) -> StaticProofState {
    match state {
        StaticProofState::SignalOnly => StaticProofState::SignalOnly,
        _ => StaticProofState::NeedsRuntimeEvidence,
    }
}

pub(crate) fn validate_agentic_whitebox_static_claim(
    target: &Path,
    raw_item: &Value,
) -> Result<StaticProofValidation> {
    let claim = static_proof_claim_from_whitebox_schema(raw_item)?;
    Ok(validate_static_proof_claim(target, &claim))
}
