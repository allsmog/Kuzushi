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
                self.execute_tool_with_runtime(inner_name, inner_input, inner_ctx, inner_runtime)
            },
        );
        Some(result)
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
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "triage:run" if triage_strategy(input, "deep") => {
            Some(run_deep_audit_tool(deep_triage_input(input), ctx, runtime))
        }
        "triage:run" if triage_strategy(input, "gate-deep") => Some(run_classifier_score_tool(
            deep_triage_input(input),
            ctx,
            runtime,
        )),
        "triage:run" => Some(run_triage(input.clone(), ctx, runtime)),
        "verify:finding" if verify_empirical_mode(input) => {
            Some(run_verify_exploit(input.clone(), ctx))
        }
        "verify:finding" => Some(run_verify_finding(input.clone(), ctx, runtime)),
        "verify:exploit" => Some(run_verify_exploit(input.clone(), ctx)),
        "trace:expand" => Some(run_trace_expand(input.clone(), ctx, runtime)),
        "patch:finding" => Some(run_patch_finding(input.clone(), ctx, runtime)),
        _ => None,
    }
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

fn verify_empirical_mode(input: &Value) -> bool {
    input
        .get("mode")
        .and_then(Value::as_str)
        .is_some_and(|mode| mode.trim().eq_ignore_ascii_case("empirical"))
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
