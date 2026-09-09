use super::run_carlini_threat_hunt::CarliniDebugArtifacts;
use super::*;
use crate::structured_output::{
    parse_or_repair_required_structured_json_with_cost, StructuredOutputError,
};

mod response_artifacts;

#[cfg(test)]
pub(crate) use response_artifacts::carlini_actor_response_artifact_payload;
pub(crate) use response_artifacts::extract_carlini_findings_response;
use response_artifacts::{
    write_carlini_actor_prompt_artifact, write_carlini_actor_repair_prompt_artifact,
    write_carlini_actor_response_artifact,
};

/// Output of a single carlini actor query. `cost_usd` accumulates every
/// LLM call we paid for to produce `value`: the initial response, any
/// max-output-tokens retry, and any repair pass. Returning it explicitly
/// keeps the cost from being dropped on the floor at the report layer
/// (previously hardcoded to 0.0).
pub(crate) struct CarliniActorQuery {
    pub(crate) value: Value,
    pub(crate) cost: RuntimeCostReport,
}

struct PreparedCarliniActorQuery {
    prompt: String,
    contract: StructuredJsonContract,
    request: AgentQueryRequest,
}

impl PreparedCarliniActorQuery {
    fn run(
        &self,
        runtime: &dyn AgentRuntime,
        debug_artifacts: Option<&CarliniDebugArtifacts>,
        actor_fingerprint: &str,
    ) -> Result<(AgentQueryResponse, RuntimeCostReport)> {
        write_carlini_actor_prompt_artifact(debug_artifacts, actor_fingerprint, &self.prompt);
        run_carlini_actor_with_retry(runtime, &self.request, debug_artifacts, actor_fingerprint)
    }
}

pub(crate) fn query_carlini_actor(
    runtime: &dyn AgentRuntime,
    input: &Value,
    target: &Path,
    options: &CarliniInput,
    model: &str,
    inventory_block: &str,
    actor_hunt: &ActorHunt,
    actor_fingerprint: &str,
    debug_artifacts: Option<&CarliniDebugArtifacts>,
) -> Result<CarliniActorQuery> {
    let prepared = prepare_carlini_actor_query(
        input,
        target,
        options,
        model,
        inventory_block,
        actor_hunt,
        actor_fingerprint,
    )?;
    let (response, accumulated_cost) = prepared.run(runtime, debug_artifacts, actor_fingerprint)?;
    if let Some(value) = extract_carlini_findings_response(&response) {
        return Ok(CarliniActorQuery {
            value,
            cost: accumulated_cost,
        });
    }
    repair_carlini_actor_findings(
        runtime,
        &prepared.request,
        response,
        prepared.contract,
        debug_artifacts,
        actor_fingerprint,
        accumulated_cost,
    )
}

fn prepare_carlini_actor_query(
    input: &Value,
    target: &Path,
    options: &CarliniInput,
    model: &str,
    inventory_block: &str,
    actor_hunt: &ActorHunt,
    actor_fingerprint: &str,
) -> Result<PreparedCarliniActorQuery> {
    let parts = build_actor_prompt_parts(
        target,
        actor_hunt,
        options,
        inventory_block,
        actor_fingerprint,
    );
    let contract = StructuredJsonContract::new(
        "carlini-threat-hunt:run",
        "CarliniThreatFindings",
        findings_schema(),
    );
    let request = carlini_actor_request(model, target, parts.prompt.clone(), input)?
        .with_cacheable_prompt_prefix(parts.cacheable_prefix)
        .with_structured_output(contract.runtime_contract());
    Ok(PreparedCarliniActorQuery {
        prompt: parts.prompt,
        contract,
        request,
    })
}

/// Run the initial actor query and, when the model truncated its output, one
/// higher-budget retry. Returns the chosen response plus the total cost paid
/// across both calls (the retry is dropped on error, keeping the initial).
fn run_carlini_actor_with_retry(
    runtime: &dyn AgentRuntime,
    request: &AgentQueryRequest,
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
) -> Result<(AgentQueryResponse, RuntimeCostReport)> {
    let initial =
        crate::runtime::query_blocking_checked(runtime, request.clone()).map_err(|error| {
            StructuredOutputError::from_source_and_cost(error, RuntimeCostReport::INCOMPLETE_ZERO)
        })?;
    write_carlini_actor_response_artifact(debug_artifacts, actor_fingerprint, "initial", &initial);
    let accumulated_cost = initial.checked_cost_report()?;
    if !initial.truncated {
        return Ok((initial, accumulated_cost));
    }
    match retry_carlini_with_higher_output_budget(runtime, request) {
        Ok(retry) => {
            write_carlini_actor_response_artifact(
                debug_artifacts,
                actor_fingerprint,
                "retry",
                &retry,
            );
            let total_cost = accumulated_cost.checked_add(
                retry.checked_cost_report()?,
                "Carlini initial plus truncation-retry cost",
            )?;
            Ok((retry, total_cost))
        }
        Err(_) => Ok((initial, accumulated_cost.mark_incomplete())),
    }
}

/// Structured-output was not present in `response`; parse-or-repair it into the
/// findings object. Adds only the repair-pass delta to `accumulated_cost` (the
/// caller already counted the response's own cost).
fn repair_carlini_actor_findings(
    runtime: &dyn AgentRuntime,
    request: &AgentQueryRequest,
    response: AgentQueryResponse,
    contract: StructuredJsonContract,
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    accumulated_cost: RuntimeCostReport,
) -> Result<CarliniActorQuery> {
    let response_cost = response.checked_cost_report()?;
    let costed = parse_or_repair_required_structured_json_with_cost(
        response,
        contract,
        require_json_object,
        |repair_prompt, output| {
            query_carlini_repair(
                runtime,
                request,
                debug_artifacts,
                actor_fingerprint,
                repair_prompt,
                output,
            )
        },
    )
    .map_err(|error| remap_carlini_structured_failure(error, accumulated_cost, response_cost))?;
    let structured_cost = costed.cost_report()?;
    let cost = carlini_cost_with_repair(accumulated_cost, response_cost, structured_cost)?;
    Ok(CarliniActorQuery {
        value: costed.value,
        cost,
    })
}

fn remap_carlini_structured_failure(
    error: anyhow::Error,
    accumulated_cost: RuntimeCostReport,
    response_cost: RuntimeCostReport,
) -> anyhow::Error {
    let Some(failure) = error.downcast_ref::<StructuredOutputError>() else {
        return error;
    };
    let helper_cost = failure.cost_report();
    match carlini_cost_with_repair(accumulated_cost, response_cost, helper_cost) {
        Ok(cost) => StructuredOutputError::from_source_and_cost(error, cost).into(),
        Err(cost_error) => StructuredOutputError::from_source_and_cost(
            error.context(format!(
                "Could not compose prior Carlini spend into structured-output failure: {cost_error:#}"
            )),
            accumulated_cost.mark_incomplete(),
        )
        .into(),
    }
}

fn query_carlini_repair(
    runtime: &dyn AgentRuntime,
    request: &AgentQueryRequest,
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    repair_prompt: String,
    output: crate::runtime::AgentStructuredOutput,
) -> Result<AgentQueryResponse> {
    write_carlini_actor_repair_prompt_artifact(debug_artifacts, actor_fingerprint, &repair_prompt);
    let repair_request = repair_request_from(request, repair_prompt, output);
    let response = crate::runtime::query_blocking_checked(runtime, repair_request)?;
    write_carlini_actor_response_artifact(debug_artifacts, actor_fingerprint, "repair", &response);
    Ok(response)
}

fn carlini_cost_with_repair(
    accumulated: RuntimeCostReport,
    response: RuntimeCostReport,
    structured: RuntimeCostReport,
) -> Result<RuntimeCostReport> {
    let repair_observed =
        RuntimeCost::from_usd(structured.observed_usd(), "Carlini structured-output cost")?
            .checked_sub(
                RuntimeCost::from_usd(response.observed_usd(), "Carlini response cost")?,
                "Carlini repair-only cost",
            )?;
    let repair = if structured.is_complete() && response.is_complete() {
        RuntimeCostReport::known(repair_observed)
    } else {
        RuntimeCostReport::incomplete(repair_observed)
    };
    accumulated.checked_add(repair, "Carlini accumulated plus repair cost")
}

fn carlini_actor_request(
    model: &str,
    target: &Path,
    prompt: String,
    input: &Value,
) -> Result<AgentQueryRequest> {
    let request = AgentQueryRequest::new(
        model.to_string(),
        target.to_path_buf(),
        carlini_system_prompt(),
        prompt,
    )
    .with_tool_policy(try_whitebox_static_policy_for_target(target)?)
    .with_thinking_level(agentic_hunter_thinking_level(input));

    Ok(match max_output_tokens_from_input(input) {
        Some(tokens) => request.with_max_output_tokens(tokens),
        None => request,
    })
}

pub(in crate::capabilities::carlini_threat_hunt) fn max_output_tokens_from_input(
    input: &Value,
) -> Option<u32> {
    ["maxOutputTokens", "max_output_tokens", "maxTokens"]
        .iter()
        .filter_map(|key| input.get(*key).and_then(Value::as_u64))
        .find(|tokens| *tokens > 0 && *tokens <= u32::MAX as u64)
        .map(|tokens| tokens as u32)
}

fn retry_carlini_with_higher_output_budget(
    runtime: &dyn AgentRuntime,
    request: &AgentQueryRequest,
) -> Result<AgentQueryResponse> {
    const RETRY_FLOOR: u32 = 16_000;
    const RETRY_CEILING: u32 = 65_535;
    let next_budget = match request.max_output_tokens {
        Some(cap) if cap >= RETRY_CEILING => cap,
        Some(cap) => cap.saturating_mul(2).clamp(RETRY_FLOOR, RETRY_CEILING),
        None => RETRY_FLOOR,
    };
    crate::runtime::query_blocking_checked(
        runtime,
        request.clone().with_max_output_tokens(next_budget),
    )
}

pub(crate) fn record_unique_carlini_findings(
    state: &mut CarliniActorRunState,
    findings: Vec<Finding>,
) {
    for finding in findings {
        let dedupe_key = carlini_dedupe_key(&finding);
        if state.seen.insert(dedupe_key) {
            state.findings.push(finding);
        }
    }
}

pub(crate) fn carlini_dedupe_key(finding: &Finding) -> String {
    format!(
        "{}|{}|{}",
        finding.rule_id, finding.file_path, finding.start_line
    )
}

pub(crate) fn finalize_carlini_findings(
    input: &Value,
    findings: &mut Vec<Finding>,
    max_findings: usize,
) -> Result<()> {
    findings.truncate(max_findings);
    apply_carlini_static_profile(input, findings)
}

pub(crate) fn apply_carlini_static_profile(
    input: &Value,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(findings, StaticProofState::CodeCited)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn carlini_threat_hunt_report(
    target: PathBuf,
    ctx: &ToolExecutionContext<'_>,
    options: CarliniInput,
    actors: usize,
    actor_runs: usize,
    prompt_inventory_files: usize,
    threat_focused_prompt_files: usize,
    findings: Vec<Finding>,
    rejected_count: usize,
    rejection_reasons: Vec<String>,
    cost_usd: f64,
    cost_usd_exact: bool,
) -> Result<CarliniThreatHuntReport> {
    let persisted = persist_findings(&target, &findings, ctx)?;
    Ok(CarliniThreatHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        actors,
        actor_runs,
        prompt_inventory_files,
        threat_focused_prompt_files,
        findings,
        rejected_count,
        rejection_reasons,
        persisted,
        kb_context: Some(options.kb_context),
        cost_usd,
        cost_usd_exact,
    })
}

#[cfg(test)]
mod cost_failure_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    enum RuntimeOutcome {
        Response(AgentQueryResponse),
        Failure(&'static str),
    }

    struct ScriptedRuntime {
        outcomes: Mutex<VecDeque<RuntimeOutcome>>,
    }

    impl ScriptedRuntime {
        fn new(outcomes: impl IntoIterator<Item = RuntimeOutcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into_iter().collect()),
            }
        }
    }

    impl AgentRuntime for ScriptedRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            match self.outcomes.lock().unwrap().pop_front().unwrap() {
                RuntimeOutcome::Response(response) => Ok(response),
                RuntimeOutcome::Failure(message) => anyhow::bail!(message),
            }
        }

        fn triage_finding_blocking(
            &self,
            _request: crate::runtime::TriageRequest,
        ) -> Result<crate::findings::TriageOutcome> {
            unreachable!("Carlini structured-output tests do not triage")
        }
    }

    #[test]
    fn truncated_retry_provider_failure_retains_initial_spend_on_parse_failure() {
        let runtime = ScriptedRuntime::new([
            RuntimeOutcome::Response(response("not json", true, 0.2)),
            RuntimeOutcome::Failure("retry provider failed"),
        ]);

        let report = run_to_structured_failure(&runtime);

        assert_cost_report(report, 0.2, false);
    }

    #[test]
    fn repair_provider_failure_retains_initial_and_retry_spend() {
        let runtime = ScriptedRuntime::new([
            RuntimeOutcome::Response(response("not json", true, 0.2)),
            RuntimeOutcome::Response(response("still not json", false, 0.3)),
            RuntimeOutcome::Failure("repair provider failed"),
        ]);

        let report = run_to_structured_failure(&runtime);

        assert_cost_report(report, 0.5, false);
    }

    #[test]
    fn oversized_repair_failure_retains_all_three_response_costs() {
        let oversized = "x".repeat(crate::structured_output::MAX_STRUCTURED_RESPONSE_BYTES + 1);
        let runtime = ScriptedRuntime::new([
            RuntimeOutcome::Response(response("not json", true, 0.2)),
            RuntimeOutcome::Response(response("still not json", false, 0.3)),
            RuntimeOutcome::Response(response(&oversized, false, 0.4)),
        ]);

        let report = run_to_structured_failure(&runtime);

        assert_cost_report(report, 0.9, true);
    }

    fn run_to_structured_failure(runtime: &ScriptedRuntime) -> RuntimeCostReport {
        let target = tempfile::tempdir().unwrap();
        let request = AgentQueryRequest::new("test:model", target.path(), "system", "prompt");
        let (response, accumulated_cost) =
            run_carlini_actor_with_retry(runtime, &request, None, "actor").unwrap();
        let contract = StructuredJsonContract::new(
            "carlini-threat-hunt:run",
            "CarliniThreatFindings",
            findings_schema(),
        );
        let error = repair_carlini_actor_findings(
            runtime,
            &request,
            response,
            contract,
            None,
            "actor",
            accumulated_cost,
        )
        .err()
        .expect("structured-output failure");
        error
            .downcast_ref::<StructuredOutputError>()
            .expect("costed structured-output failure")
            .cost_report()
    }

    fn response(text: &str, truncated: bool, cost_usd: f64) -> AgentQueryResponse {
        AgentQueryResponse {
            text: text.to_string(),
            truncated,
            cost_usd,
            cost_usd_reported: true,
            ..AgentQueryResponse::default()
        }
    }

    fn assert_cost_report(report: RuntimeCostReport, observed: f64, exact: bool) {
        assert!((report.observed_usd() - observed).abs() < 1e-9);
        assert_eq!(report.is_complete(), exact);
    }
}
