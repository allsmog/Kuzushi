use super::*;

pub(in crate::modules::taint_iris_next) fn run_taint_iris_next_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
    runtime: &dyn AgentRuntime,
    model: &str,
    agent_tool_policy: AgentToolPolicy,
) -> Result<TaintIrisNextAgentResult> {
    let (raw, retry_count, cost_usd) = match query_taint_iris_next_agent(
        plan,
        evidence,
        agent_prompt,
        runtime,
        model,
        agent_tool_policy,
    ) {
        Ok(parsed) => parsed,
        Err(QueryAgentError { error, cost_usd }) => {
            return Ok(invalid_taint_iris_next_agent_result(
                plan, evidence, error, 1, cost_usd,
            ))
        }
    };
    normalized_taint_iris_next_agent_result(plan, evidence, raw, retry_count, cost_usd)
}

/// Carries the partial cost incurred before a query failed so callers can
/// still report token spend that has already been billed.
pub(in crate::modules::taint_iris_next) struct QueryAgentError {
    pub(in crate::modules::taint_iris_next) error: anyhow::Error,
    pub(in crate::modules::taint_iris_next) cost_usd: f64,
}

pub(in crate::modules::taint_iris_next) fn query_taint_iris_next_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
    runtime: &dyn AgentRuntime,
    model: &str,
    agent_tool_policy: AgentToolPolicy,
) -> std::result::Result<(Value, usize, f64), QueryAgentError> {
    let response = run_taint_iris_next_agent_prompt(
        plan,
        runtime,
        model,
        agent_prompt.to_string(),
        agent_tool_policy.clone(),
    )
    .map_err(|error| QueryAgentError {
        error,
        cost_usd: 0.0,
    })?;
    let first_cost = response.cost_usd;
    match parse_taint_iris_next_agent_response(response) {
        Ok(raw) => Ok((raw, 0, first_cost)),
        Err(_) => {
            let repair = run_taint_iris_next_agent_prompt(
                plan,
                runtime,
                model,
                build_taint_iris_next_repair_prompt(plan, evidence),
                agent_tool_policy,
            )
            .map_err(|error| QueryAgentError {
                error,
                cost_usd: first_cost,
            })?;
            let repair_cost = repair.cost_usd;
            let total_cost = first_cost + repair_cost;
            parse_taint_iris_next_agent_response(repair)
                .map(|raw| (raw, 1, total_cost))
                .map_err(|error| QueryAgentError {
                    error,
                    cost_usd: total_cost,
                })
        }
    }
}

pub(in crate::modules::taint_iris_next) fn run_taint_iris_next_agent_prompt(
    plan: &TaintIrisNextPlan,
    runtime: &dyn AgentRuntime,
    model: &str,
    prompt: String,
    agent_tool_policy: AgentToolPolicy,
) -> Result<AgentQueryResponse> {
    runtime.query_blocking(
        AgentQueryRequest::new(
            model.to_string(),
            plan.repo_root.clone(),
            TAINT_IRIS_NEXT_SYSTEM_PROMPT.to_string(),
            prompt,
        )
        .with_tool_policy(agent_tool_policy),
    )
}

pub(in crate::modules::taint_iris_next) fn invalid_taint_iris_next_agent_result(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    error: anyhow::Error,
    retry_count: usize,
    cost_usd: f64,
) -> TaintIrisNextAgentResult {
    let (findings, selections, triage) = deterministic_taint_iris_next_fallback(plan, evidence);
    let warnings = vec![
        "agent returned no structured JSON output".to_string(),
        format!("parse error: {error}"),
        format!(
            "agent output invalid; returning {} deterministic linked finding candidate(s) for review",
            findings.len()
        ),
    ];
    TaintIrisNextAgentResult {
        agent_status: "invalid-json".to_string(),
        selected_cwes: selections,
        findings: findings.clone(),
        review_candidates: findings,
        triage,
        triage_summary: summarize_taint_iris_next_triage(&[]),
        outcome: "agent-output-invalid".to_string(),
        raw_output: Value::Null,
        structured_output_valid: false,
        structured_output_retry_count: retry_count,
        parse_error: Some(error.to_string()),
        result_text_excerpt: None,
        warnings,
        cost_usd,
    }
}
