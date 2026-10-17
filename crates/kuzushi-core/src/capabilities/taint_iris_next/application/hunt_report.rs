use super::*;

pub(crate) fn require_taint_iris_next_model(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        "taint-iris-next:hunt",
        optional_nonempty_string(input, "model")?,
        ctx.config.model.as_deref(),
    )
}

pub(crate) fn taint_iris_next_hunt_status(agent: &TaintIrisNextAgentResult) -> &'static str {
    if agent.outcome == "agent-output-invalid" && agent.findings.is_empty() {
        "agent-output-invalid"
    } else if agent.outcome == "agent-output-invalid" {
        "hunted-with-agent-output-invalid"
    } else {
        "hunted"
    }
}

pub(crate) fn taint_iris_next_hunt_data(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    status: &str,
    agent_prompt: &str,
    agent: &TaintIrisNextAgentResult,
) -> Value {
    let mut data = taint_iris_next_base_data(plan, evidence, status, agent_prompt);
    let Value::Object(object) = &mut data else {
        return data;
    };
    insert_agent_hunt_fields(object, agent);
    insert_agent_hunt_diagnostics(object, agent);
    object.insert("stats".to_string(), agent_hunt_stats(evidence, agent));
    data
}

fn insert_agent_hunt_fields(object: &mut Map<String, Value>, agent: &TaintIrisNextAgentResult) {
    object.insert("outcome".to_string(), json!(agent.outcome));
    object.insert("agentStatus".to_string(), json!(agent.agent_status));
    object.insert("selectedCwes".to_string(), json!(agent.selected_cwes));
    object.insert("findings".to_string(), json!(agent.findings));
    object.insert(
        "reviewCandidates".to_string(),
        json!(agent.review_candidates),
    );
    object.insert("triage".to_string(), json!(agent.triage));
    object.insert("triageSummary".to_string(), agent.triage_summary.clone());
    object.insert("warnings".to_string(), json!(agent.warnings));
    object.insert("rawAgentOutput".to_string(), agent.raw_output.clone());
}

fn insert_agent_hunt_diagnostics(
    object: &mut Map<String, Value>,
    agent: &TaintIrisNextAgentResult,
) {
    object.insert(
        "structuredOutputValid".to_string(),
        json!(agent.structured_output_valid),
    );
    object.insert(
        "structuredOutputRetryCount".to_string(),
        json!(agent.structured_output_retry_count),
    );
    if let Some(parse_error) = &agent.parse_error {
        object.insert("parseError".to_string(), json!(parse_error));
    }
    if let Some(excerpt) = &agent.result_text_excerpt {
        object.insert("resultTextExcerpt".to_string(), json!(excerpt));
    }
}

fn agent_hunt_stats(
    evidence: &TaintIrisNextEvidenceResult,
    agent: &TaintIrisNextAgentResult,
) -> Value {
    let mut stats = json!({
        "totalFindings": agent.findings.len().saturating_sub(agent.review_candidates.len()),
        "totalReviewCandidates": agent.review_candidates.len(),
        "totalCandidates": evidence.candidates.len(),
        "totalLinkedStories": evidence.linked_story_count,
        "backendPathCount": evidence.backend_path_count,
    });
    if agent.cost_usd_exact {
        stats["totalCostUsd"] = json!(agent.cost_usd);
    } else {
        stats["observedCostUsd"] = json!(agent.cost_usd);
        stats["providerSpendUnresolved"] = json!(true);
    }
    stats
}

pub(crate) fn taint_iris_next_hunt_report(
    plan: &TaintIrisNextPlan,
    agent: &TaintIrisNextAgentResult,
    status: &str,
    persisted: Option<TaintIrisNextPersistedRun>,
    output: String,
    data: Value,
) -> TaintIrisNextReport {
    TaintIrisNextReport {
        target: plan.target.display().to_string(),
        status: status.to_string(),
        mode: "hunt".to_string(),
        count: agent
            .findings
            .len()
            .saturating_sub(agent.review_candidates.len()),
        findings: agent.findings.clone(),
        review_candidates: agent.review_candidates.clone(),
        selected_cwes: agent.selected_cwes.clone(),
        persisted,
        cost_usd: agent.cost_usd,
        cost_usd_exact: agent.cost_usd_exact,
        ok: agent.structured_output_valid,
        output,
        data,
    }
}
