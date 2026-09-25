use super::*;

pub(in crate::modules) fn run_taint_iris_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    run_taint_iris_next_tool(&taint_iris_legacy_input(input), ctx, runtime)
}

pub(in crate::modules) fn run_taint_iris_next_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_taint_iris_next_report(input, ctx, runtime)?.to_tool_json())
}

pub(in crate::modules) fn run_taint_iris_next_plan_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    Ok(
        run_taint_iris_next_report(&taint_iris_next_mode_input(input, "plan"), ctx, None)?
            .to_tool_json(),
    )
}

pub(in crate::modules) fn run_taint_iris_next_trace_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    Ok(
        run_taint_iris_next_report(&taint_iris_next_mode_input(input, "plan"), ctx, None)?
            .to_tool_json(),
    )
}

pub(in crate::modules) fn run_taint_iris_next_review_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(
        run_taint_iris_next_report(&taint_iris_next_mode_input(input, "hunt"), ctx, runtime)?
            .to_tool_json(),
    )
}

fn taint_iris_next_mode_input(input: &Value, mode: &str) -> Value {
    let mut normalized = input.clone();
    if let Value::Object(object) = &mut normalized {
        object.insert("mode".to_string(), json!(mode));
        return normalized;
    }
    json!({ "mode": mode })
}

fn taint_iris_legacy_input(input: &Value) -> Value {
    let mut normalized = taint_iris_next_mode_input(input, "hunt");
    let Value::Object(object) = &mut normalized else {
        return normalized;
    };
    forward_legacy_taint_prompt(object);
    if object.contains_key("cweFocus") || object.contains_key("cwe_focus") {
        return normalized;
    }
    if let Some(cwe) = object.get("cwe").cloned() {
        object.insert("cweFocus".to_string(), cwe);
    }
    normalized
}

fn forward_legacy_taint_prompt(object: &mut serde_json::Map<String, Value>) {
    if object.contains_key("TAINT_IRIS_NEXT_PROMPT") {
        return;
    }
    if let Some(prompt) = object.get("TAINT_IRIS_PROMPT").cloned() {
        object.insert("TAINT_IRIS_NEXT_PROMPT".to_string(), prompt);
    }
}

pub(in crate::modules) fn run_taint_iris_next_import_sinks_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    Ok(run_taint_iris_next_sink_import_report(input, ctx)?.to_tool_json())
}

pub(in crate::modules) fn run_taint_iris_next_catalog_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_taint_iris_next_catalog_report(input, ctx, runtime)?.to_tool_json())
}

pub(in crate::modules) fn run_taint_iris_next_codeql_db_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_codeql_build_report(input, ctx, runtime)?.to_tool_json())
}

pub(in crate::modules) fn dispatch_systems_hunt_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "systems-hunt:systems-context-gatherer"
        | "systems-hunt:systems-invariant-extract"
        | "systems-hunt:systems-trigger-synth"
        | "systems-hunt:systems-hunt"
        | "systems-hunt:deep-semantic-cwe-select"
        | "systems-hunt:deep-semantic-hunt" => {
            Some(execute_systems_hunt_tool(name, input.clone(), ctx, runtime))
        }
        _ => None,
    }
}

pub(in crate::modules) fn dispatch_uaf_hunt_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "uaf-hunt:hunt" => Some(execute_uaf_hunt_tool(name, input.clone(), ctx, runtime)),
        _ => None,
    }
}

impl ModuleRegistry {
    /// Threat-intel dispatch lives as a method (not a free function)
    /// because the apply path re-enters the registry to invoke
    /// sub-hunts. The closure passed to the capability is the
    /// canonical tool router; recursion is bounded because the
    /// `HuntKind` enum doesn't contain `threat-intel` as a valid
    /// hunt target.
    pub(in crate::modules) fn dispatch_threat_intel_tool(
        &self,
        name: &str,
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> ToolDispatchResult {
        use crate::capabilities::threat_intel::execute_threat_intel_tool;
        if name == "threat-intel:discover" {
            return Some(run_threat_intel_discover(input, ctx));
        }
        if name == "threat-intel:research" {
            return Some(self.run_threat_intel_research_tool(input, ctx, runtime));
        }
        if !matches!(
            name,
            "threat-intel:list" | "threat-intel:apply" | "threat-intel:harvest"
        ) {
            return None;
        }
        let result = execute_threat_intel_tool(
            name,
            input.clone(),
            ctx,
            runtime,
            |inner_name, inner_input, inner_ctx, inner_runtime| {
                self.dispatch_delegated_tool_with_runtime(
                    inner_name,
                    inner_input,
                    inner_ctx,
                    inner_runtime,
                )
            },
        );
        Some(result)
    }

    fn run_threat_intel_research_tool(
        &self,
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        run_threat_intel_research(
            input,
            ctx,
            runtime,
            |inner_name, inner_input, inner_ctx, inner_runtime| {
                self.dispatch_delegated_tool_with_runtime(
                    inner_name,
                    inner_input,
                    inner_ctx,
                    inner_runtime,
                )
            },
        )
    }
}

pub(in crate::modules) fn dispatch_runtime_analysis_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "full-mode:hunt" => Some(run_full_mode_hunt_tool(input.clone(), ctx, runtime)),
        "classifier-gate:score" => Some(run_classifier_score_tool(input.clone(), ctx, runtime)),
        "deep-audit:run" => Some(run_deep_audit_tool(input.clone(), ctx, runtime)),
        "threat-model:build"
        | "threat-model:read"
        | "threat-model:verify"
        | "threat-model:import"
        | "threat-model:models"
        | "threat-model:activate"
        | "threat-model:revisions"
        | "threat-model:diff"
        | "threat-model:restore"
        | "threat-model:adopt"
        | "threat-model:methodologies"
        | "randori:pasta"
        | "randori:threat-model" => {
            Some(execute_threat_model_tool(name, input.clone(), ctx, runtime))
        }
        "x-ray:run" | "x-ray:read" | "x-ray:x-ray" => {
            Some(execute_x_ray_tool(name, input.clone(), ctx, runtime))
        }
        "threat-leads:build" | "threat-leads:read" => {
            Some(execute_threat_leads_tool(name, input.clone(), ctx))
        }
        _ => None,
    }
}

pub(in crate::modules) fn dispatch_finding_action_tool(
    registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "triage:run" if triage_strategy(input, "deep") && deep_triage_target(input) => {
            Some(run_deep_audit_tool(deep_triage_input(input), ctx, runtime))
        }
        "triage:run" if triage_strategy(input, "gate-deep") => Some(run_classifier_score_tool(
            deep_triage_input(input),
            ctx,
            runtime,
        )),
        "triage:run" => Some(run_triage_with_optional_dedupe(input, ctx, runtime)),
        "triage:chain-hunt" => Some(crate::capabilities::chain_hunt::execute_triage_chain_hunt(
            input.clone(),
            ctx,
            runtime,
        )),
        "triage:dedupe" => Some(crate::capabilities::corpus_dedupe::execute_triage_dedupe(
            input.clone(),
            ctx,
            runtime,
        )),
        "verify:finding" if crate::modules::verification_is_empirical(input) => {
            Some(dispatch_empirical_verification(registry, input, ctx))
        }
        "verify:finding" => Some(run_verify_finding(input.clone(), ctx, runtime)),
        "verify:exploit" => Some(run_verify_exploit(input.clone(), ctx)),
        "trace:expand" => Some(run_trace_expand(input.clone(), ctx, runtime)),
        "patch:finding" => Some(run_patch_finding(input.clone(), ctx, runtime)),
        _ => None,
    }
}

fn dispatch_empirical_verification(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    registry.dispatch_delegated_tool_with_runtime(
        "verify:exploit",
        json!({"fingerprint": input.get("fingerprint")}),
        ctx,
        None,
    )
}

/// Opt-in `dedupe=true` runs the model-driven corpus dedupe BEFORE bulk
/// triage, so settled duplicates drop out of finding selection instead of
/// burning independent triage spend. The dedupe payload rides the triage
/// result under `data.dedupe` and both spends fold into one envelope cost.
fn run_triage_with_optional_dedupe(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let legacy_dedupe = input
        .get("dedupe")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let dedupe_enabled =
        legacy_dedupe || input.get("modelDedupe").and_then(Value::as_str) == Some("auto");
    let effective_input = effective_model_dedupe_input(input, legacy_dedupe);
    if !dedupe_enabled {
        return run_triage(effective_input, ctx, runtime);
    }
    let dedupe = crate::capabilities::corpus_dedupe::execute_triage_dedupe(
        dedupe_prepass_input(&effective_input),
        ctx,
        runtime,
    )?;
    let mut result = run_triage(effective_input, ctx, runtime)?;
    merge_dedupe_into_triage_result(&mut result, dedupe)?;
    Ok(result)
}

fn effective_model_dedupe_input(input: &Value, legacy_dedupe: bool) -> Value {
    let mut effective = input.clone();
    if legacy_dedupe {
        effective["modelDedupe"] = json!("auto");
    }
    effective
}

fn dedupe_prepass_input(input: &Value) -> Value {
    match input.get("model") {
        Some(model) => json!({ "model": model }),
        None => json!({}),
    }
}

fn merge_dedupe_into_triage_result(result: &mut Value, dedupe: Value) -> Result<()> {
    let combined = envelope_cost_report(result)?.checked_add(
        envelope_cost_report(&dedupe)?,
        "triage:run dedupe pre-pass cost",
    )?;
    if let Some(data) = result.get_mut("data").and_then(Value::as_object_mut) {
        data.insert(
            "dedupe".to_string(),
            dedupe.get("data").cloned().unwrap_or(dedupe),
        );
    }
    crate::module_result::apply_runtime_cost_report(result, combined);
    Ok(())
}

/// Read a result envelope's monetary claim back into a checked report so two
/// envelopes can fold without inventing exactness.
fn envelope_cost_report(value: &Value) -> Result<crate::runtime::RuntimeCostReport> {
    use crate::runtime::{RuntimeCost, RuntimeCostReport};
    if let Some(exact) = value.get("costUsd").and_then(Value::as_f64) {
        return Ok(RuntimeCostReport::known(RuntimeCost::from_usd(
            exact,
            "result envelope cost",
        )?));
    }
    if let Some(observed) = value.get("observedCostUsd").and_then(Value::as_f64) {
        return Ok(RuntimeCostReport::incomplete(RuntimeCost::from_usd(
            observed,
            "result envelope cost",
        )?));
    }
    Ok(RuntimeCostReport::UNAVAILABLE)
}

/// The single-finding deep-audit tool needs an explicit fingerprint; a
/// `strategy=deep` run without one falls through to `run_triage`, which
/// classifies every selected finding through the deep auditor.
fn deep_triage_target(input: &Value) -> bool {
    ["findingFingerprint", "fingerprint"].iter().any(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|v| !v.trim().is_empty())
    })
}

fn triage_strategy(input: &Value, expected: &str) -> bool {
    input
        .get("strategy")
        .and_then(Value::as_str)
        .is_some_and(|strategy| strategy.trim().eq_ignore_ascii_case(expected))
}

fn deep_triage_input(input: &Value) -> Value {
    let mut normalized = input.clone();
    let Value::Object(object) = &mut normalized else {
        return normalized;
    };
    if object.contains_key("findingFingerprint") {
        return normalized;
    }
    if let Some(fingerprint) = object.get("fingerprint").cloned() {
        object.insert("findingFingerprint".to_string(), fingerprint);
    }
    normalized
}

pub(in crate::modules) fn dispatch_recon_assessment_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "recon:nmap" | "recon:subdomain" | "recon:http-fingerprint" | "recon:import" => {
            Some(execute_recon_tool(name, input.clone(), ctx))
        }
        "vendor-assessment:attach"
        | "vendor-assessment:scope"
        | "vendor-assessment:prompts"
        | "vendor-assessment:assess" => Some(vendor_assessment::execute_tool(
            name,
            input.clone(),
            ctx,
            runtime,
        )),
        "chrome-rce:scan" | "chrome-rce:review-trigger" => {
            Some(chrome_rce::execute_tool(name, input.clone(), ctx))
        }
        _ => None,
    }
}
