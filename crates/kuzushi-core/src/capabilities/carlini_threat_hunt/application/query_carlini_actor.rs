use super::run_carlini_threat_hunt::CarliniDebugArtifacts;
use super::*;
use crate::structured_output::{
    balanced_json_slices, parse_or_repair_required_structured_json_with_cost,
};

/// Output of a single carlini actor query. `cost_usd` accumulates every
/// LLM call we paid for to produce `value`: the initial response, any
/// max-output-tokens retry, and any repair pass. Returning it explicitly
/// keeps the cost from being dropped on the floor at the report layer
/// (previously hardcoded to 0.0).
pub(crate) struct CarliniActorQuery {
    pub(crate) value: Value,
    pub(crate) cost_usd: f64,
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
    let prompt = build_actor_prompt(target, actor_hunt, options, inventory_block, actor_fingerprint);
    write_carlini_actor_prompt_artifact(debug_artifacts, actor_fingerprint, &prompt);
    let contract = StructuredJsonContract::new(
        "carlini-threat-hunt:run",
        "CarliniThreatFindings",
        findings_schema(),
    );
    let request = carlini_actor_request(model, target, prompt, input)
        .with_structured_output(contract.runtime_contract());
    let (response, accumulated_cost) =
        run_carlini_actor_with_retry(runtime, &request, debug_artifacts, actor_fingerprint)?;
    if let Some(value) = extract_carlini_findings_response(&response) {
        return Ok(CarliniActorQuery {
            value,
            cost_usd: accumulated_cost,
        });
    }
    repair_carlini_actor_findings(
        runtime,
        &request,
        response,
        contract,
        debug_artifacts,
        actor_fingerprint,
        accumulated_cost,
    )
}

/// Run the initial actor query and, when the model truncated its output, one
/// higher-budget retry. Returns the chosen response plus the total cost paid
/// across both calls (the retry is dropped on error, keeping the initial).
fn run_carlini_actor_with_retry(
    runtime: &dyn AgentRuntime,
    request: &AgentQueryRequest,
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
) -> Result<(AgentQueryResponse, f64)> {
    let initial = runtime.query_blocking(request.clone())?;
    write_carlini_actor_response_artifact(debug_artifacts, actor_fingerprint, "initial", &initial);
    let accumulated_cost = initial.cost_usd;
    if !initial.truncated {
        return Ok((initial, accumulated_cost));
    }
    match retry_carlini_with_higher_output_budget(runtime, request) {
        Ok(retry) => {
            write_carlini_actor_response_artifact(debug_artifacts, actor_fingerprint, "retry", &retry);
            let total_cost = accumulated_cost + retry.cost_usd;
            Ok((retry, total_cost))
        }
        Err(_) => Ok((initial, accumulated_cost)),
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
    accumulated_cost: f64,
) -> Result<CarliniActorQuery> {
    let response_cost = response.cost_usd;
    let costed = parse_or_repair_required_structured_json_with_cost(
        response,
        contract,
        require_json_object,
        |repair_prompt, output| {
            write_carlini_actor_repair_prompt_artifact(
                debug_artifacts,
                actor_fingerprint,
                &repair_prompt,
            );
            let repair_request = repair_request_from(request, repair_prompt, output);
            let repair_response = runtime.query_blocking(repair_request);
            if let Ok(response) = &repair_response {
                write_carlini_actor_response_artifact(
                    debug_artifacts,
                    actor_fingerprint,
                    "repair",
                    response,
                );
            }
            repair_response
        },
    )?;
    let repair_only_cost = (costed.cost_usd - response_cost).max(0.0);
    Ok(CarliniActorQuery {
        value: costed.value,
        cost_usd: accumulated_cost + repair_only_cost,
    })
}

pub(crate) fn extract_carlini_findings_response(response: &AgentQueryResponse) -> Option<Value> {
    if let Some(structured) = response.structured.as_ref() {
        if is_carlini_findings_object(structured) {
            return Some(structured.clone());
        }
    }

    let mut candidates = balanced_json_slices(&response.text, '{', '}');
    candidates.reverse();
    candidates.into_iter().find_map(|candidate| {
        let value = serde_json::from_str::<Value>(candidate).ok()?;
        is_carlini_findings_object(&value).then_some(value)
    })
}

fn is_carlini_findings_object(value: &Value) -> bool {
    value
        .get("findings")
        .is_some_and(|findings| findings.is_array())
}

fn carlini_actor_request(
    model: &str,
    target: &Path,
    prompt: String,
    input: &Value,
) -> AgentQueryRequest {
    let request = AgentQueryRequest::new(
        model.to_string(),
        target.to_path_buf(),
        carlini_system_prompt(),
        prompt,
    )
    .with_tool_policy(whitebox_static_policy_for_target(target))
    .with_thinking_level(agentic_hunter_thinking_level(input));

    match max_output_tokens_from_input(input) {
        Some(tokens) => request.with_max_output_tokens(tokens),
        None => request,
    }
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
    runtime.query_blocking(request.clone().with_max_output_tokens(next_budget))
}

fn write_carlini_actor_prompt_artifact(
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    prompt: &str,
) {
    write_carlini_actor_artifact(
        debug_artifacts,
        actor_fingerprint,
        "prompt",
        &json!({ "actorFingerprint": actor_fingerprint, "prompt": prompt }),
    );
}

fn write_carlini_actor_repair_prompt_artifact(
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    prompt: &str,
) {
    write_carlini_actor_artifact(
        debug_artifacts,
        actor_fingerprint,
        "repair-prompt",
        &json!({ "actorFingerprint": actor_fingerprint, "prompt": prompt }),
    );
}

fn write_carlini_actor_response_artifact(
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    phase: &str,
    response: &AgentQueryResponse,
) {
    write_carlini_actor_artifact(
        debug_artifacts,
        actor_fingerprint,
        phase,
        &carlini_actor_response_artifact_payload(actor_fingerprint, phase, response),
    );
}

pub(crate) fn carlini_actor_response_artifact_payload(
    actor_fingerprint: &str,
    phase: &str,
    response: &AgentQueryResponse,
) -> Value {
    let ignored_tool_prelude = ignored_tool_prelude_summary(response);
    json!({
        "actorFingerprint": actor_fingerprint,
        "phase": phase,
        "text": response.text,
        "structured": response.structured,
        "ignoredToolPrelude": ignored_tool_prelude,
        "costUsd": response.cost_usd,
        "inputTokens": response.input_tokens,
        "outputTokens": response.output_tokens,
        "truncated": response.truncated,
        "stopReason": response.stop_reason,
    })
}

fn ignored_tool_prelude_summary(response: &AgentQueryResponse) -> Value {
    let preludes = ignored_tool_prelude_objects(&response.text);
    json!({
        "present": !preludes.is_empty(),
        "count": preludes.len(),
        "reason": "Carlini threat hunt is a prompt-only query path; tool-shaped JSON in model text was ignored and was not executed.",
        "objects": preludes,
    })
}

fn ignored_tool_prelude_objects(text: &str) -> Vec<Value> {
    let slices = balanced_json_slices(text, '{', '}');
    let findings_index = slices
        .iter()
        .rposition(|candidate| {
            serde_json::from_str::<Value>(candidate)
                .ok()
                .is_some_and(|value| is_carlini_findings_object(&value))
        })
        .unwrap_or(slices.len());

    slices
        .into_iter()
        .take(findings_index)
        .filter_map(|candidate| serde_json::from_str::<Value>(candidate).ok())
        .filter(is_tool_shaped_json)
        .collect()
}

fn is_tool_shaped_json(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.contains_key("cmd")
        || object.contains_key("tool")
        || object.contains_key("tool_call")
        || object.contains_key("toolCall")
        || (object.contains_key("name") && object.contains_key("arguments"))
}

fn write_carlini_actor_artifact(
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    phase: &str,
    value: &Value,
) {
    let Some(debug_artifacts) = debug_artifacts else {
        return;
    };
    let leaf = format!(
        "carlini-threat-hunt/{}-{}.json",
        sanitize_actor_artifact_leaf(actor_fingerprint),
        phase
    );
    let _ = crate::run_artifacts::write_run_artifact_json(
        &debug_artifacts.target,
        &debug_artifacts.run_id,
        &leaf,
        format!("carlini {phase}"),
        value,
    );
}

fn sanitize_actor_artifact_leaf(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
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

pub(crate) fn carlini_threat_hunt_report(
    target: PathBuf,
    ctx: &ToolExecutionContext<'_>,
    options: CarliniInput,
    actors: usize,
    actor_runs: usize,
    prompt_inventory_files: usize,
    threat_focused_prompt_files: usize,
    findings: Vec<Finding>,
    cost_usd: f64,
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
        persisted,
        kb_context: Some(options.kb_context),
        cost_usd,
    })
}
