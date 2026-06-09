use super::*;

pub(crate) fn run_taint_iris_next_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<TaintIrisNextReport> {
    let target = taint_iris_next_target(input, ctx)?;
    let options = TaintIrisNextInput::from_tool_input(input)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "hunt",
                format!("taint-iris-next:hunt start · target={}", target.display()),
            )
            .emit();
    }
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
    let runtime_options = taint_iris_next_runtime_options(input, &plan.backend.selected);
    let agent_tool_policy = build_taint_iris_next_tool_policy(input, target)?;
    let _trace_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                "hunt",
                "source-discovery · sink-discovery · taint-trace",
            )
            .emit();
        trace.parent_scope(phase)
    });
    let mut agent = run_taint_iris_next_agent(
        plan,
        evidence,
        agent_prompt,
        runtime,
        &model,
        agent_tool_policy,
        runtime_options,
    )?;
    drop(_trace_scope);
    let mut findings = agent.findings.clone();
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SourceSinkLinked)?;
        agent.findings = findings;
    }
    let persisted = persist_taint_iris_next_findings(target, &agent.findings, ctx)?;
    let output = render_taint_iris_next_output(plan, evidence, Some(&agent));
    let status = taint_iris_next_hunt_status(&agent);
    let data = taint_iris_next_hunt_data(plan, evidence, status, agent_prompt, &agent);
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "hunt",
                format!(
                    "taint-iris-next:hunt complete · {} findings",
                    agent.findings.len()
                ),
            )
            .emit();
    }

    Ok(taint_iris_next_hunt_report(
        plan, &agent, status, persisted, output, data,
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

pub(crate) fn require_taint_iris_next_runtime(
    runtime: Option<&dyn AgentRuntime>,
) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "taint-iris-next:hunt requires the LangGraph runtime in hunt mode. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )
}

/// Build the tool policy for a taint-iris-next hunt, gating MCP
/// attachment on artifact existence and refusing to dispatch when the
/// CPG / CodeQL DB are missing. Honors the legacy `mcps: false` input
/// for callers that explicitly want to suppress MCP attachment (used
/// by `dataflow-plan` and other planning verbs).
pub(in crate::capabilities::taint_iris_next) fn build_taint_iris_next_tool_policy(
    input: &Value,
    target: &Path,
) -> Result<AgentToolPolicy> {
    let mcps_enabled = read_bool_option(input, "mcps").unwrap_or(true);
    let policy = agent_tool_policy_for_input(input)?;
    if !mcps_enabled {
        return Ok(policy);
    }
    let policy = policy.with_mcps_for_target(target);
    ensure_required_mcps(&policy, target, &["joern", "codeql"])?;
    Ok(policy)
}

fn ensure_required_mcps(
    policy: &AgentToolPolicy,
    target: &Path,
    required: &[&str],
) -> Result<()> {
    let mut missing = Vec::new();
    for name in required {
        if !crate::runtime::plan_contains(&policy.mcps_attached, name) {
            missing.push(*name);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let hints = missing
        .iter()
        .map(|name| missing_mcp_hint(name, target))
        .collect::<Vec<_>>()
        .join("\n  ");
    anyhow::bail!(
        "taint-iris-next:hunt requires MCP servers whose artifacts are missing on {}:\n  {}\nRun `/planning` (or set `mcps: false` to suppress MCP attachment).",
        target.display(),
        hints
    );
}

fn missing_mcp_hint(name: &str, target: &Path) -> String {
    match name {
        "joern" => format!(
            "- joern (.kuzushi/cpg.bin)              missing -> run `cpg:build` on {}",
            target.display()
        ),
        "codeql" => format!(
            "- codeql (.kuzushi/codeql-db/)          missing -> run `codeql:create-db` on {}",
            target.display()
        ),
        other => format!("- {other:>17} missing"),
    }
}

const JOERN_DEFAULT_MCP_TOOL_TIMEOUT_MS: &str = "180000";

pub(in crate::capabilities::taint_iris_next) fn taint_iris_next_runtime_options(
    input: &Value,
    selected_backend: &str,
) -> Option<AgentRuntimeOptions> {
    let mut options = AgentRuntimeOptions::default();
    insert_path_option(
        &mut options.mcp_environment,
        input,
        &["joernCpg", "joern_cpg"],
        "KUZUSHI_JOERN_CPG",
    );
    insert_int_option(
        &mut options.mcp_environment,
        input,
        &["joernPerCweTimeoutMs", "joern_per_cwe_timeout_ms"],
        "KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS",
    );
    insert_bool_option(
        &mut options.mcp_environment,
        input,
        &["codeqlPrewarm", "codeql_prewarm"],
        "KUZUSHI_CODEQL_PREWARM",
    );
    insert_path_option(
        &mut options.mcp_environment,
        input,
        &["codeqlCacheDir", "codeql_cache_dir"],
        "KUZUSHI_CODEQL_CACHE_DIR",
    );
    options.mcp_tool_timeout_ms =
        read_u64_option(input, &["mcpToolTimeoutMs", "mcp_tool_timeout_ms"]);
    if options.mcp_tool_timeout_ms.is_none() && joern_reachable_from_agent(input, selected_backend)
    {
        options.mcp_tool_timeout_ms = JOERN_DEFAULT_MCP_TOOL_TIMEOUT_MS.parse::<u64>().ok();
    }
    options.bridge_verbose = read_bool_alias(input, &["bridgeVerbose", "bridge_verbose"]);
    options.bridge_log_path = read_string_option(input, &["bridgeLogPath", "bridge_log_path"]);
    (!options.is_empty()).then_some(options)
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
    false
}

fn insert_bool_option(
    values: &mut BTreeMap<String, String>,
    input: &Value,
    aliases: &[&str],
    env_key: &str,
) {
    if let Some(value) = read_bool_alias(input, aliases) {
        values.insert(
            env_key.to_string(),
            if value { "1" } else { "0" }.to_string(),
        );
    }
}

fn insert_int_option(
    values: &mut BTreeMap<String, String>,
    input: &Value,
    aliases: &[&str],
    env_key: &str,
) {
    if let Some(value) = read_u64_option(input, aliases) {
        values.insert(env_key.to_string(), value.to_string());
    }
}

fn insert_path_option(
    values: &mut BTreeMap<String, String>,
    input: &Value,
    aliases: &[&str],
    env_key: &str,
) {
    if let Some(value) = read_string_option(input, aliases) {
        values.insert(env_key.to_string(), value);
    }
}

fn read_u64_option(input: &Value, aliases: &[&str]) -> Option<u64> {
    aliases.iter().find_map(|key| match input.get(*key) {
        Some(Value::Number(value)) => value.as_u64(),
        Some(Value::String(value)) => value.trim().parse::<u64>().ok(),
        _ => None,
    })
}

fn read_bool_alias(input: &Value, aliases: &[&str]) -> Option<bool> {
    aliases.iter().find_map(|key| read_bool_option(input, key))
}

fn read_string_option(input: &Value, aliases: &[&str]) -> Option<String> {
    aliases.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}
