use super::*;

pub(in crate::capabilities::taint_iris_next) fn run_taint_iris_next_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
    runtime: &dyn AgentRuntime,
    model: &str,
    agent_tool_policy: AgentToolPolicy,
) -> Result<TaintIrisNextAgentResult> {
    let (raw, retry_count) = match query_taint_iris_next_agent(
        plan,
        evidence,
        agent_prompt,
        runtime,
        model,
        agent_tool_policy,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Ok(invalid_taint_iris_next_agent_result(
                plan, evidence, error, 1,
            ))
        }
    };
    normalized_taint_iris_next_agent_result(plan, evidence, raw, retry_count)
}

pub(in crate::capabilities::taint_iris_next) fn query_taint_iris_next_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
    runtime: &dyn AgentRuntime,
    model: &str,
    agent_tool_policy: AgentToolPolicy,
) -> Result<(Value, usize)> {
    let response = run_taint_iris_next_agent_prompt(
        plan,
        runtime,
        model,
        agent_prompt.to_string(),
        agent_tool_policy.clone(),
    )?;
    match parse_taint_iris_next_agent_response(response) {
        Ok(raw) => Ok((raw, 0)),
        Err(_) => {
            let repair = run_taint_iris_next_agent_prompt(
                plan,
                runtime,
                model,
                build_taint_iris_next_repair_prompt(plan, evidence),
                agent_tool_policy,
            )?;
            parse_taint_iris_next_agent_response(repair).map(|raw| (raw, 1))
        }
    }
}

pub(in crate::capabilities::taint_iris_next) fn run_taint_iris_next_agent_prompt(
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

pub(in crate::capabilities::taint_iris_next) fn invalid_taint_iris_next_agent_result(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    error: anyhow::Error,
    retry_count: usize,
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
        cost_usd: 0.0,
    }
}
