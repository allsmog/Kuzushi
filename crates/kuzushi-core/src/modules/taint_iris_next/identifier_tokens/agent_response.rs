use super::*;

pub(in crate::modules::taint_iris_next) fn parse_taint_iris_next_agent_response(
    response: AgentQueryResponse,
) -> Result<Value> {
    match response.structured {
        Some(value @ Value::Object(_)) => Ok(value),
        Some(_) => anyhow::bail!(
            "taint-iris-next:hunt expected structured output to be a JSON object"
        ),
        None => parse_json_object_from_agent_text(&response.text).with_context(|| {
            "taint-iris-next:hunt expected pi-agent-core to return JSON with selectedCwes, findings, triage, and notes"
        }),
    }
}

pub(in crate::modules::taint_iris_next) fn build_taint_iris_next_repair_prompt(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> String {
    [
        "Return only strict JSON matching this shape: {\"selectedCwes\":[],\"findings\":[],\"triage\":[],\"notes\":[]}.".to_string(),
        "No markdown, no prose outside JSON.".to_string(),
        format!("Minimum finding evidence level: {}", plan.caps.min_evidence_level),
        format!(
            "Backend: {}; evidence rows: {}; linked stories: {}",
            plan.backend.selected,
            evidence.evidence.len(),
            evidence.linked_story_count
        ),
        format!(
            "Catalog CWEs: {}",
            plan.catalog
                .iter()
                .map(|entry| entry.cwe.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ]
    .join("\n")
}
