use super::*;

pub(crate) fn run_taint_iris_next_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<TaintIrisNextReport> {
    let target = taint_iris_next_target(input, ctx)?;
    let options = TaintIrisNextInput::from_tool_input(input)?;
    let plan = build_taint_iris_next_plan(&target, options)?;

    if !taint_iris_next_has_required_context(&plan) {
        return Ok(taint_iris_next_missing_context_report(&plan));
    }

    let evidence = extract_taint_iris_next_evidence(&plan)?;
    let agent_prompt = build_taint_iris_next_agent_prompt(&plan, &evidence);

    if plan.mode == TaintIrisNextMode::Plan {
        return Ok(taint_iris_next_planned_report(
            &plan,
            &evidence,
            &agent_prompt,
        ));
    }

    run_taint_iris_next_hunt(
        input,
        ctx,
        runtime,
        &target,
        &plan,
        &evidence,
        &agent_prompt,
    )
}

pub(crate) fn taint_iris_next_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    let target = resolve_tool_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "taint-iris-next:hunt target is not a directory: {}",
            target.display()
        );
    }
    Ok(target)
}

pub(crate) fn run_taint_iris_next_hunt(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    target: &Path,
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
) -> Result<TaintIrisNextReport> {
    let runtime = require_taint_iris_next_runtime(runtime)?;
    let model = require_taint_iris_next_model(input, ctx)?;
    apply_taint_iris_next_mcp_options(input);
    apply_taint_iris_next_joern_timeout_default(input, &plan.backend.selected);
    let mcps_enabled = read_bool_option(input, "mcps").unwrap_or(true);
    let agent_tool_policy = agent_tool_policy_for_input(input)?.with_mcps(mcps_enabled);
    let mut agent = run_taint_iris_next_agent(
        &plan,
        &evidence,
        &agent_prompt,
        runtime,
        &model,
        agent_tool_policy,
    )?;
    let mut findings = agent.findings.clone();
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SourceSinkLinked)?;
        agent.findings = findings;
    }
    let persisted = persist_taint_iris_next_findings(&target, &agent.findings, ctx)?;
    let output = render_taint_iris_next_output(&plan, &evidence, Some(&agent));
    let status = taint_iris_next_hunt_status(&agent);
    let data = taint_iris_next_hunt_data(&plan, &evidence, status, &agent_prompt, &agent);

    Ok(taint_iris_next_hunt_report(
        &plan, &agent, status, persisted, output, data,
    ))
}

pub(crate) fn taint_iris_next_missing_context_report(
    plan: &TaintIrisNextPlan,
) -> TaintIrisNextReport {
    let output = render_taint_iris_next_missing_context(plan);
    TaintIrisNextReport {
        target: plan.target.display().to_string(),
        status: "missing-context".to_string(),
        mode: plan.mode.as_str().to_string(),
        count: 0,
        findings: Vec::new(),
        review_candidates: Vec::new(),
        selected_cwes: Vec::new(),
        persisted: None,
        cost_usd: 0.0,
        ok: false,
        output: output.clone(),
        data: json!({
            "status": "missing-context",
            "target": plan.target.display().to_string(),
            "contextStatus": plan.context_status,
            "threatModelStatus": plan.threat_model_status,
            "missing": {
                "context": !plan.context_status.ok,
                "threatModel": !plan.threat_model_status.ok,
            },
        }),
    }
}

pub(crate) fn taint_iris_next_planned_report(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
) -> TaintIrisNextReport {
    TaintIrisNextReport {
        target: plan.target.display().to_string(),
        status: "planned".to_string(),
        mode: "plan".to_string(),
        count: 0,
        findings: Vec::new(),
        review_candidates: Vec::new(),
        selected_cwes: Vec::new(),
        persisted: None,
        cost_usd: 0.0,
        ok: true,
        output: render_taint_iris_next_output(plan, evidence, None),
        data: taint_iris_next_base_data(plan, evidence, "planned", agent_prompt),
    }
}

pub(crate) fn require_taint_iris_next_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.context(
        "taint-iris-next:hunt requires the pi-agent-core runtime in hunt mode. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

pub(in crate::capabilities::taint_iris_next) fn apply_taint_iris_next_mcp_options(input: &Value) {
    apply_path_option_env(input, "joernCpg", "KUZUSHI_JOERN_CPG");
    apply_path_option_env(input, "joern_cpg", "KUZUSHI_JOERN_CPG");
    apply_int_option_env(
        input,
        "joernPerCweTimeoutMs",
        "KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS",
    );
    apply_int_option_env(
        input,
        "joern_per_cwe_timeout_ms",
        "KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS",
    );
    apply_bool_option_env(input, "codeqlPrewarm", "KUZUSHI_CODEQL_PREWARM");
    apply_bool_option_env(input, "codeql_prewarm", "KUZUSHI_CODEQL_PREWARM");
    apply_path_option_env(input, "codeqlCacheDir", "KUZUSHI_CODEQL_CACHE_DIR");
    apply_path_option_env(input, "codeql_cache_dir", "KUZUSHI_CODEQL_CACHE_DIR");
    apply_int_option_env(input, "mcpToolTimeoutMs", "KUZUSHI_MCP_TOOL_TIMEOUT_MS");
    apply_int_option_env(input, "mcp_tool_timeout_ms", "KUZUSHI_MCP_TOOL_TIMEOUT_MS");
    apply_bool_option_env(input, "bridgeVerbose", "KUZUSHI_BRIDGE_VERBOSE");
    apply_bool_option_env(input, "bridge_verbose", "KUZUSHI_BRIDGE_VERBOSE");
    apply_path_option_env(input, "bridgeLogPath", "KUZUSHI_BRIDGE_LOG");
    apply_path_option_env(input, "bridge_log_path", "KUZUSHI_BRIDGE_LOG");
}

const JOERN_DEFAULT_MCP_TOOL_TIMEOUT_MS: &str = "180000";

pub(in crate::capabilities::taint_iris_next) fn apply_taint_iris_next_joern_timeout_default(
    input: &Value,
    selected_backend: &str,
) {
    if !joern_reachable_from_agent(input, selected_backend) {
        return;
    }
    if std::env::var_os("KUZUSHI_MCP_TOOL_TIMEOUT_MS").is_some() {
        return;
    }
    if input.get("mcpToolTimeoutMs").is_some() || input.get("mcp_tool_timeout_ms").is_some() {
        return;
    }
    std::env::set_var(
        "KUZUSHI_MCP_TOOL_TIMEOUT_MS",
        JOERN_DEFAULT_MCP_TOOL_TIMEOUT_MS,
    );
}

fn joern_reachable_from_agent(input: &Value, selected_backend: &str) -> bool {
    if selected_backend == "joern" {
        return true;
    }
    if input.get("joernCpg").and_then(Value::as_str).is_some()
        || input.get("joern_cpg").and_then(Value::as_str).is_some()
    {
        return true;
    }
    std::env::var_os("KUZUSHI_JOERN_CPG").is_some()
}

fn apply_bool_option_env(input: &Value, key: &str, env: &str) {
    if std::env::var_os(env).is_some() {
        return;
    }
    if let Some(value) = read_bool_option(input, key) {
        std::env::set_var(env, if value { "1" } else { "0" });
    }
}

fn apply_int_option_env(input: &Value, key: &str, env: &str) {
    if std::env::var_os(env).is_some() {
        return;
    }
    if let Some(value) = input.get(key).and_then(Value::as_i64) {
        std::env::set_var(env, value.to_string());
    } else if let Some(value) = input.get(key).and_then(Value::as_str) {
        let value = value.trim();
        if !value.is_empty() {
            std::env::set_var(env, value);
        }
    }
}

fn apply_path_option_env(input: &Value, key: &str, env: &str) {
    if std::env::var_os(env).is_some() {
        return;
    }
    if let Some(value) = input.get(key).and_then(Value::as_str) {
        let value = value.trim();
        if !value.is_empty() {
            std::env::set_var(env, value);
        }
    }
}
