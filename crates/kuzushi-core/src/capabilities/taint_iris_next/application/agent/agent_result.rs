use super::*;

pub(in crate::capabilities::taint_iris_next) fn normalized_taint_iris_next_agent_result(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    raw: Value,
    retry_count: usize,
    cost: RuntimeCostReport,
) -> Result<TaintIrisNextAgentResult> {
    let object = required_agent_object(&raw)?;
    let payload = normalize_valid_agent_payload(plan, evidence, object)?;
    Ok(payload.into_result(raw, retry_count, cost))
}

struct NormalizedAgentPayload {
    agent_status: String,
    selected_cwes: Vec<Value>,
    findings: Vec<Finding>,
    triage: Vec<Value>,
    outcome: String,
    warnings: Vec<String>,
}

impl NormalizedAgentPayload {
    fn into_result(
        self,
        raw: Value,
        retry_count: usize,
        cost: RuntimeCostReport,
    ) -> TaintIrisNextAgentResult {
        TaintIrisNextAgentResult {
            agent_status: self.agent_status,
            selected_cwes: self.selected_cwes,
            findings: self.findings,
            review_candidates: Vec::new(),
            triage_summary: summarize_taint_iris_next_triage(&self.triage),
            triage: self.triage,
            outcome: self.outcome,
            raw_output: raw,
            structured_output_valid: true,
            structured_output_retry_count: retry_count,
            parse_error: None,
            result_text_excerpt: None,
            warnings: self.warnings,
            cost_usd: cost.observed_usd(),
            cost_usd_exact: cost.is_complete(),
        }
    }
}

fn required_agent_object(raw: &Value) -> Result<&Map<String, Value>> {
    let Value::Object(object) = raw else {
        anyhow::bail!("taint-iris-next:hunt expected agent output to be a JSON object");
    };
    Ok(object)
}

fn normalize_valid_agent_payload(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    object: &Map<String, Value>,
) -> Result<NormalizedAgentPayload> {
    let selected_cwes =
        normalize_taint_iris_next_selections(required_agent_array(object, "selectedCwes")?, &plan.catalog)?;
    let (mut findings, mut warnings) =
        normalize_taint_iris_next_findings(required_agent_array(object, "findings")?, plan, evidence)?;
    let triage = normalize_taint_iris_next_triage(required_agent_array(object, "triage")?);
    let (agent_status, outcome) =
        agent_selection_status(&selected_cwes, evidence, &mut warnings);
    findings.truncate(plan.caps.max_agent_findings);
    Ok(NormalizedAgentPayload {
        agent_status,
        selected_cwes,
        findings,
        triage,
        outcome,
        warnings,
    })
}

fn agent_selection_status(
    selections: &[Value],
    evidence: &TaintIrisNextEvidenceResult,
    warnings: &mut Vec<String>,
) -> (String, String) {
    if !selections.is_empty() {
        return ("valid-json".to_string(), evidence.outcome.clone());
    }
    if !evidence.evidence.is_empty() {
        warnings.push(format!(
            "agent selected no CWEs from {} evidence row(s)",
            evidence.evidence.len()
        ));
        return ("no-selection".to_string(), "agent-no-selection".to_string());
    }
    ("no-selection".to_string(), evidence.outcome.clone())
}

fn required_agent_array(object: &Map<String, Value>, camel_key: &str) -> Result<Vec<Value>> {
    let snake_key = camel_to_snake(camel_key);
    let aliases = [camel_key, snake_key.as_str()];
    let value = read_object_value(object, &aliases).with_context(|| {
        format!("taint-iris-next:hunt agent output missing required `{camel_key}` array")
    })?;
    value
        .as_array()
        .cloned()
        .with_context(|| format!("taint-iris-next:hunt agent output `{camel_key}` must be an array"))
}

fn camel_to_snake(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_uppercase() {
            out.push('_');
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}
