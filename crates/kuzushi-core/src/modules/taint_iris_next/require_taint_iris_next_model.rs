use super::*;

pub(in crate::modules) fn require_taint_iris_next_model(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    optional_nonempty_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context(
            "taint-iris-next:hunt requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
        )
}

pub(in crate::modules) fn taint_iris_next_hunt_status(
    agent: &TaintIrisNextAgentResult,
) -> &'static str {
    if agent.outcome == "agent-output-invalid" && agent.findings.is_empty() {
        "agent-output-invalid"
    } else if agent.outcome == "agent-output-invalid" {
        "hunted-with-agent-output-invalid"
    } else {
        "hunted"
    }
}

pub(in crate::modules) fn taint_iris_next_hunt_data(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    status: &str,
    agent_prompt: &str,
    agent: &TaintIrisNextAgentResult,
) -> Value {
    let mut data = taint_iris_next_base_data(plan, evidence, status, agent_prompt);
    if let Value::Object(object) = &mut data {
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
        object.insert(
            "stats".to_string(),
            json!({
                "totalFindings": agent.findings.len().saturating_sub(agent.review_candidates.len()),
                "totalReviewCandidates": agent.review_candidates.len(),
                "totalCandidates": evidence.candidates.len(),
                "totalLinkedStories": evidence.linked_story_count,
                "backendPathCount": evidence.backend_path_count,
                "totalCostUsd": agent.cost_usd,
            }),
        );
    }
    data
}

pub(in crate::modules) fn taint_iris_next_hunt_report(
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
        ok: status != "agent-output-invalid",
        output,
        data,
    }
}
