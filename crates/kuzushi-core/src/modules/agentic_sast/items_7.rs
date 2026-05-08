use super::prelude::*;
use super::*;

pub(in crate::modules) fn normalize_agentic_sast_findings(
    raw: Value,
    target: &Path,
    max_findings: usize,
    whitebox_static: bool,
) -> Result<Vec<Finding>> {
    let findings_value = match raw {
        Value::Object(object) => object
            .get("findings")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        Value::Array(items) => Value::Array(items),
        _ => {
            anyhow::bail!("agentic-sast output parse failed: expected an object or findings array")
        }
    };
    let Value::Array(items) = findings_value else {
        anyhow::bail!("agentic-sast output parse failed: findings must be an array");
    };

    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        let raw_item = Value::Object(object.clone());
        let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
            .unwrap_or_else(|| "agentic-sast/finding".to_string());
        let file_path =
            normalize_reported_file_path(resolve_agentic_schema_file_path(&object), target);
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .or_else(|| read_nested_object_u64(&object, "source", &["startLine", "start_line"]))
            .or_else(|| first_citation_u64(&object, &["startLine", "start_line"]))
            .filter(|value| *value > 0)
            .unwrap_or(1) as u32;
        let end_line = read_object_u64(&object, &["endLine", "end_line"])
            .or_else(|| read_nested_object_u64(&object, "source", &["endLine", "end_line"]))
            .or_else(|| first_citation_u64(&object, &["endLine", "end_line"]))
            .filter(|value| *value > 0)
            .map(|value| value as u32);
        let severity = agentic_severity(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or("WARNING"),
        );
        let mut message = read_object_string(&object, &["message"])
            .or_else(|| read_object_string(&object, &["title"]))
            .unwrap_or_else(|| rule_id.clone());
        if let Some(evidence) = read_object_string(&object, &["evidence"]) {
            if !evidence.trim().is_empty() {
                message.push_str("\n\nEvidence: ");
                message.push_str(evidence.trim());
            }
        }
        append_agentic_schema_field(&mut message, &object, "verdict", "Verdict");
        append_agentic_schema_field(
            &mut message,
            &object,
            "staticProofState",
            "Static proof state",
        );
        append_agentic_schema_object_summary(&mut message, &object, "source", "Source");
        append_agentic_schema_object_summary(&mut message, &object, "sink", "Sink");
        append_agentic_schema_object_summary(&mut message, &object, "path", "Path");
        append_agentic_schema_object_summary(
            &mut message,
            &object,
            "sanitizerAssessment",
            "Sanitizer assessment",
        );
        append_agentic_schema_object_summary(
            &mut message,
            &object,
            "guardAssessment",
            "Guard assessment",
        );
        append_agentic_schema_field(
            &mut message,
            &object,
            "triggerNarrative",
            "Trigger narrative",
        );
        append_agentic_schema_field(&mut message, &object, "impactNarrative", "Impact narrative");
        append_agentic_schema_field(&mut message, &object, "recommendedFix", "Recommended fix");
        if let Some(confidence) = read_object_string(&object, &["confidence"]) {
            message.push_str("\nConfidence: ");
            message.push_str(confidence.trim());
        }
        let mut finding = Finding::new_tool(
            "agentic", rule_id, file_path, start_line, end_line, severity, message,
        );
        if whitebox_static {
            let validation = validate_agentic_whitebox_static_claim(target, &raw_item)?;
            apply_agentic_static_validation(&mut finding, &validation);
        } else if let Some(state) = whitebox_static_proof_state_from_input(&raw_item)? {
            finding.set_static_proof_state(state);
        }
        findings.push(finding);
    }
    Ok(findings)
}

pub(in crate::modules) fn validate_agentic_whitebox_static_claim(
    target: &Path,
    raw_item: &Value,
) -> Result<StaticProofValidation> {
    let claim = static_proof_claim_from_whitebox_schema(raw_item)?;
    Ok(validate_static_proof_claim(target, &claim))
}
