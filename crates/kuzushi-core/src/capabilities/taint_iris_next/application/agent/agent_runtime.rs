use super::*;

pub(in crate::capabilities::taint_iris_next) fn run_taint_iris_next_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
    runtime: &dyn AgentRuntime,
    model: &str,
    agent_tool_policy: AgentToolPolicy,
    runtime_options: Option<AgentRuntimeOptions>,
) -> Result<TaintIrisNextAgentResult> {
    let (raw, retry_count, cost) = match query_taint_iris_next_agent(
        plan,
        evidence,
        agent_prompt,
        runtime,
        model,
        agent_tool_policy,
        runtime_options,
    ) {
        Ok(parsed) => parsed,
        Err(QueryAgentError {
            error,
            cost,
            raw_text,
            retry_count,
        }) => {
            return Ok(invalid_taint_iris_next_agent_result(
                plan,
                evidence,
                error,
                retry_count,
                cost,
                raw_text,
            ))
        }
    };
    normalized_taint_iris_next_agent_result(plan, evidence, raw, retry_count, cost)
}

#[derive(Debug)]
pub(in crate::capabilities::taint_iris_next) struct QueryAgentError {
    pub(in crate::capabilities::taint_iris_next) error: anyhow::Error,
    pub(in crate::capabilities::taint_iris_next) cost: RuntimeCostReport,
    pub(in crate::capabilities::taint_iris_next) raw_text: Option<String>,
    pub(in crate::capabilities::taint_iris_next) retry_count: usize,
}

impl QueryAgentError {
    fn new(
        error: anyhow::Error,
        cost: RuntimeCostReport,
        raw_text: Option<String>,
        retry_count: usize,
    ) -> Self {
        Self {
            error,
            cost,
            raw_text,
            retry_count,
        }
    }
}

pub(in crate::capabilities::taint_iris_next) fn query_taint_iris_next_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
    runtime: &dyn AgentRuntime,
    model: &str,
    agent_tool_policy: AgentToolPolicy,
    runtime_options: Option<AgentRuntimeOptions>,
) -> std::result::Result<(Value, usize, RuntimeCostReport), QueryAgentError> {
    let response = run_taint_iris_next_agent_prompt(
        plan,
        runtime,
        model,
        agent_prompt.to_string(),
        agent_tool_policy.clone(),
        runtime_options.clone(),
        plan.max_budget_usd,
    )
    .map_err(|error| QueryAgentError::new(error, RuntimeCostReport::INCOMPLETE_ZERO, None, 0))?;
    parse_or_repair_taint_agent(
        plan,
        evidence,
        runtime,
        model,
        agent_tool_policy,
        runtime_options,
        response,
    )
}

fn parse_or_repair_taint_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    runtime: &dyn AgentRuntime,
    model: &str,
    policy: AgentToolPolicy,
    options: Option<AgentRuntimeOptions>,
    response: AgentQueryResponse,
) -> std::result::Result<(Value, usize, RuntimeCostReport), QueryAgentError> {
    let first_cost = checked_taint_agent_cost(&response, RuntimeCostReport::INCOMPLETE_ZERO, 0)?;
    let first_text = response.text.clone();
    match parse_taint_iris_next_agent_response(response) {
        Ok(raw) => Ok((raw, 0, first_cost)),
        Err(_) => repair_taint_agent(
            plan, evidence, runtime, model, policy, options, first_cost, first_text,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn repair_taint_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    runtime: &dyn AgentRuntime,
    model: &str,
    policy: AgentToolPolicy,
    options: Option<AgentRuntimeOptions>,
    first_cost: RuntimeCostReport,
    first_text: String,
) -> std::result::Result<(Value, usize, RuntimeCostReport), QueryAgentError> {
    let remaining_spend =
        remaining_observed_spend(plan.max_budget_usd, first_cost, &first_text)?;
    let repair = run_taint_iris_next_agent_prompt(
        plan,
        runtime,
        model,
        build_taint_iris_next_repair_prompt(plan, evidence),
        policy,
        options,
        remaining_spend,
    )
    .map_err(|error| {
        QueryAgentError::new(error, first_cost.mark_incomplete(), Some(first_text), 1)
    })?;
    let repair_cost = checked_taint_agent_cost(&repair, first_cost.mark_incomplete(), 1)?;
    let total = first_cost
        .checked_add(repair_cost, "taint-iris-next initial plus repair cost")
        .map_err(|error| {
            QueryAgentError::new(
                error,
                first_cost.mark_incomplete(),
                Some(repair.text.clone()),
                1,
            )
        })?;
    parse_taint_agent_repair(repair, total)
}

fn checked_taint_agent_cost(
    response: &AgentQueryResponse,
    fallback: RuntimeCostReport,
    retry_count: usize,
) -> std::result::Result<RuntimeCostReport, QueryAgentError> {
    response
        .checked_cost_report()
        .map_err(|error| {
            QueryAgentError::new(error, fallback, Some(response.text.clone()), retry_count)
        })
}

fn remaining_observed_spend(
    stop_usd: Option<f64>,
    spent: RuntimeCostReport,
    raw_text: &str,
) -> std::result::Result<Option<f64>, QueryAgentError> {
    let Some(stop_usd) = stop_usd else {
        return Ok(None);
    };
    // Unmetered but priced spend counts at its labelled estimate; spend that
    // is neither metered nor priced cannot prove it is under the stop.
    let Some(spent_usd) = spent.estimated_total_usd() else {
        return Err(spend_stop_error(
            "observed spend receipt is incomplete and unpriced",
            spent,
            raw_text,
        ));
    };
    let remaining = stop_usd - spent_usd;
    if remaining <= 0.0 {
        return Err(spend_stop_error(
            "observed spend stop is exhausted",
            spent,
            raw_text,
        ));
    }
    Ok(Some(remaining))
}

fn spend_stop_error(reason: &str, cost: RuntimeCostReport, raw_text: &str) -> QueryAgentError {
    QueryAgentError::new(
        anyhow::anyhow!("repair skipped: {reason}"),
        cost,
        Some(raw_text.to_string()),
        0,
    )
}

fn parse_taint_agent_repair(
    response: AgentQueryResponse,
    cost: RuntimeCostReport,
) -> std::result::Result<(Value, usize, RuntimeCostReport), QueryAgentError> {
    let raw_text = response.text.clone();
    parse_taint_iris_next_agent_response(response)
        .map(|raw| (raw, 1, cost))
        .map_err(|error| QueryAgentError::new(error, cost, Some(raw_text), 1))
}

pub(in crate::capabilities::taint_iris_next) fn run_taint_iris_next_agent_prompt(
    plan: &TaintIrisNextPlan,
    runtime: &dyn AgentRuntime,
    model: &str,
    prompt: String,
    agent_tool_policy: AgentToolPolicy,
    runtime_options: Option<AgentRuntimeOptions>,
    observed_spend_stop_usd: Option<f64>,
) -> Result<AgentQueryResponse> {
    let mut request = AgentQueryRequest::new(
        model.to_string(),
        plan.repo_root.clone(),
        plan.system_prompt.clone(),
        prompt,
    )
    .with_tool_policy(agent_tool_policy);
    let runtime_options =
        runtime_options_with_spend_stop(runtime_options, observed_spend_stop_usd);
    if let Some(runtime_options) = runtime_options {
        request = request.with_runtime_options(runtime_options);
    }
    crate::runtime::query_blocking_checked(runtime, request)
}

fn runtime_options_with_spend_stop(
    runtime_options: Option<AgentRuntimeOptions>,
    observed_spend_stop_usd: Option<f64>,
) -> Option<AgentRuntimeOptions> {
    let mut options = runtime_options.unwrap_or_default();
    options.observed_spend_stop_usd = observed_spend_stop_usd;
    (!options.is_empty()).then_some(options)
}

pub(in crate::capabilities::taint_iris_next) fn invalid_taint_iris_next_agent_result(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    error: anyhow::Error,
    retry_count: usize,
    cost: RuntimeCostReport,
    raw_text: Option<String>,
) -> TaintIrisNextAgentResult {
    let text_excerpt = raw_text.as_deref().map(truncate_for_excerpt);
    let projection = invalid_agent_projection(plan, evidence);
    let warnings = vec![
        "agent returned no structured JSON output".to_string(),
        format!("parse error: {error}"),
        projection.warning,
    ];
    TaintIrisNextAgentResult {
        agent_status: "invalid-json".to_string(),
        selected_cwes: projection.selections,
        findings: projection.findings,
        review_candidates: projection.review_candidates,
        triage: projection.triage,
        triage_summary: summarize_taint_iris_next_triage(&[]),
        outcome: "agent-output-invalid".to_string(),
        raw_output: Value::Null,
        structured_output_valid: false,
        structured_output_retry_count: retry_count,
        parse_error: Some(error.to_string()),
        result_text_excerpt: text_excerpt,
        warnings,
        cost_usd: cost.observed_usd(),
        cost_usd_exact: cost.is_complete(),
    }
}

struct InvalidAgentProjection {
    selections: Vec<Value>,
    findings: Vec<Finding>,
    review_candidates: Vec<Finding>,
    triage: Vec<Value>,
    warning: String,
}

fn invalid_agent_projection(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> InvalidAgentProjection {
    if plan.allow_deterministic_fallback {
        let (findings, selections, triage) = deterministic_taint_iris_next_fallback(plan, evidence);
        return InvalidAgentProjection {
            warning: format!(
                "agent output invalid; allowDeterministicFallback=true returned {} deterministic linked finding candidate(s) for review",
                findings.len()
            ),
            review_candidates: findings.clone(),
            findings,
            selections,
            triage,
        };
    }
    InvalidAgentProjection {
        selections: Vec::new(),
        findings: Vec::new(),
        review_candidates: Vec::new(),
        triage: Vec::new(),
        warning: format!(
            "agent failed; emitting 0 findings ({} linked stories remain in structural evidence for review). Set allowDeterministicFallback=true to opt in to deterministic linked-story projection.",
            evidence.linked_story_count
        ),
    }
}

fn truncate_for_excerpt(text: &str) -> String {
    const MAX_LEN: usize = 4096;
    let trimmed = text.trim();
    if trimmed.len() <= MAX_LEN {
        return trimmed.to_string();
    }
    let mut end = MAX_LEN;
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}…[truncated {} bytes]",
        &trimmed[..end],
        trimmed.len() - end
    )
}

#[cfg(test)]
mod observed_spend_tests {
    use super::*;

    #[test]
    fn incomplete_or_exhausted_spend_refuses_repair() {
        let incomplete = RuntimeCostReport::INCOMPLETE_ZERO;
        let exhausted = RuntimeCostReport::known(
            RuntimeCost::from_usd(0.25, "test observed spend").unwrap(),
        );

        assert!(remaining_observed_spend(Some(1.0), incomplete, "raw")
            .unwrap_err()
            .error
            .to_string()
            .contains("incomplete"));
        assert!(remaining_observed_spend(Some(0.25), exhausted, "raw")
            .unwrap_err()
            .error
            .to_string()
            .contains("exhausted"));
    }

    #[test]
    fn priced_unmetered_spend_repairs_within_the_estimated_remainder() {
        let estimated = RuntimeCostReport::INCOMPLETE_ZERO.with_unmetered_estimate(Some(
            RuntimeCost::from_usd(0.40, "test estimated spend").unwrap(),
        ));

        let remaining = remaining_observed_spend(Some(1.0), estimated, "raw").unwrap();

        assert!((remaining.unwrap() - 0.60).abs() < 1e-9);
        assert!(remaining_observed_spend(Some(0.30), estimated, "raw")
            .unwrap_err()
            .error
            .to_string()
            .contains("exhausted"));
    }

    #[test]
    fn exact_spend_passes_only_the_remaining_stop_to_repair() {
        let spent = RuntimeCostReport::known(
            RuntimeCost::from_usd(0.10, "test observed spend").unwrap(),
        );

        let remaining = remaining_observed_spend(Some(0.25), spent, "raw").unwrap();

        assert!((remaining.unwrap() - 0.15).abs() < f64::EPSILON);
    }
}
