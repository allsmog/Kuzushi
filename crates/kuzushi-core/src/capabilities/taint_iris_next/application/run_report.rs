use super::*;

pub(crate) fn run_taint_iris_next_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<TaintIrisNextReport> {
    let target = taint_iris_next_target(input, ctx)?;
    let options = TaintIrisNextInput::from_tool_input(input)?;
    let parent_step = emit_taint_iris_next_start(ctx, &target);
    let plan = traced_taint_iris_next_plan(ctx, parent_step, &target, options)?;

    if !taint_iris_next_has_required_context(&plan) {
        emit_taint_iris_next_child(
            ctx,
            parent_step,
            "refused",
            "missing context or threat-model artifact",
        );
        return Ok(taint_iris_next_missing_context_report(&plan));
    }

    let evidence = traced_taint_iris_next_evidence(ctx, parent_step, &plan)?;
    emit_taint_iris_next_progress(ctx, parent_step, "agent · compose prompt");
    let agent_prompt = build_taint_iris_next_agent_prompt(&plan, &evidence);

    if plan.mode == TaintIrisNextMode::Plan {
        return Ok(planned_taint_iris_next_report(
            ctx,
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
        parent_step,
    )
}

fn traced_taint_iris_next_plan(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    target: &Path,
    options: TaintIrisNextInput,
) -> Result<TaintIrisNextPlan> {
    emit_taint_iris_next_progress(ctx, parent_step, "plan · load context/catalog/discovery");
    let plan = build_taint_iris_next_plan(target, options)?;
    emit_taint_iris_next_progress(ctx, parent_step, taint_iris_next_plan_trace_label(&plan));
    Ok(plan)
}

fn traced_taint_iris_next_evidence(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    plan: &TaintIrisNextPlan,
) -> Result<TaintIrisNextEvidenceResult> {
    emit_taint_iris_next_progress(ctx, parent_step, "evidence · collect source/sink candidates");
    let evidence = extract_taint_iris_next_evidence(plan)?;
    emit_taint_iris_next_progress(
        ctx,
        parent_step,
        taint_iris_next_evidence_trace_label(&evidence),
    );
    Ok(evidence)
}

fn planned_taint_iris_next_report(
    ctx: &ToolExecutionContext<'_>,
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
) -> TaintIrisNextReport {
    emit_taint_iris_next_done(
        ctx,
        format!(
            "taint-iris-next:hunt planned · {} candidates",
            evidence.candidates.len()
        ),
    );
    taint_iris_next_planned_report(plan, evidence, agent_prompt)
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
    parent_step: Option<usize>,
) -> Result<TaintIrisNextReport> {
    let execution =
        prepare_taint_iris_next_agent_execution(input, ctx, runtime, target, plan, parent_step)?;
    let _trace_scope = begin_taint_iris_next_agent_scope(ctx, parent_step);
    let mut agent = run_taint_iris_next_agent(
        &plan,
        &evidence,
        &agent_prompt,
        execution.runtime,
        &execution.model,
        execution.agent_tool_policy,
        execution.runtime_options,
    )?;
    drop(_trace_scope);
    apply_taint_iris_next_whitebox_profile(input, &mut agent)?;
    let persisted = persist_taint_iris_next_findings(&target, &agent.findings, ctx)?;
    let output = render_taint_iris_next_output(&plan, &evidence, Some(&agent));
    let status = taint_iris_next_hunt_status(&agent);
    let data = taint_iris_next_hunt_data(&plan, &evidence, status, &agent_prompt, &agent);
    emit_taint_iris_next_done(
        ctx,
        format!(
            "taint-iris-next:hunt complete · {} findings",
            agent.findings.len()
        ),
    );

    Ok(taint_iris_next_hunt_report(
        &plan, &agent, status, persisted, output, data,
    ))
}

struct TaintIrisNextAgentExecution<'a> {
    runtime: &'a dyn AgentRuntime,
    model: String,
    agent_tool_policy: AgentToolPolicy,
    runtime_options: Option<AgentRuntimeOptions>,
}

fn prepare_taint_iris_next_agent_execution<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
    target: &Path,
    plan: &TaintIrisNextPlan,
    parent_step: Option<usize>,
) -> Result<TaintIrisNextAgentExecution<'a>> {
    let runtime = require_taint_iris_next_runtime(runtime)?;
    let model = require_taint_iris_next_model(input, ctx)?;
    emit_taint_iris_next_progress(ctx, parent_step, "agent · resolve runtime/model");
    let runtime_options = taint_iris_next_runtime_options(input, &plan.backend.selected);
    emit_taint_iris_next_progress(ctx, parent_step, "agent · configure runtime options");
    let agent_tool_policy = build_taint_iris_next_tool_policy(input, target)?;
    emit_taint_iris_next_progress(ctx, parent_step, "agent · attach analysis tools");
    Ok(TaintIrisNextAgentExecution {
        runtime,
        model,
        agent_tool_policy,
        runtime_options,
    })
}

fn apply_taint_iris_next_whitebox_profile(
    input: &Value,
    agent: &mut TaintIrisNextAgentResult,
) -> Result<()> {
    if !whitebox_static_profile_requested(input)? {
        return Ok(());
    }
    mark_whitebox_static_findings(&mut agent.findings, StaticProofState::SourceSinkLinked)
}

fn emit_taint_iris_next_start(ctx: &ToolExecutionContext<'_>, target: &Path) -> Option<usize> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "hunt",
                format!("taint-iris-next:hunt start · target={}", target.display()),
            )
            .emit()
    })
}

fn emit_taint_iris_next_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    label: impl Into<String>,
) {
    emit_taint_iris_next_child(ctx, parent_step, "tool-progress", label);
}

fn emit_taint_iris_next_child(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    kind: &str,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };
    let _ = trace.child(parent).step(kind, "hunt", label.into()).emit();
}

fn begin_taint_iris_next_agent_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };
    let phase = trace
        .child(parent)
        .step("reasoning", "hunt", "source-discovery · sink-discovery · taint-trace")
        .emit();
    Some(trace.parent_scope(phase))
}

fn emit_taint_iris_next_done(ctx: &ToolExecutionContext<'_>, label: String) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "hunt", label).emit();
    }
}

fn taint_iris_next_plan_trace_label(plan: &TaintIrisNextPlan) -> String {
    format!(
        "plan · {} languages · {} catalog entries · {} structural queries · backend {}",
        plan.languages.len(),
        plan.catalog.len(),
        plan.structural_queries.len(),
        plan.backend.selected
    )
}

fn taint_iris_next_evidence_trace_label(evidence: &TaintIrisNextEvidenceResult) -> String {
    format!(
        "evidence · {} candidates · {} linked stories · {} backend paths",
        evidence.candidates.len(),
        evidence.linked_story_count,
        evidence.backend_path_count
    )
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
        cost_usd_exact: true,
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
        cost_usd_exact: true,
        ok: true,
        output: render_taint_iris_next_output(plan, evidence, None),
        data: taint_iris_next_base_data(plan, evidence, "planned", agent_prompt),
    }
}

pub(crate) fn require_taint_iris_next_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
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
    let policy = policy.try_with_mcps_for_target(target)?;
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
            "- codeql (.kuzushi/v3/codeql-db/)       missing -> run `codeql:create-db` on {}",
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
