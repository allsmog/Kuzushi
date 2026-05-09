use super::*;

pub(in crate::modules) const TAINT_IRIS_NEXT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Taint IRIS Next agent.
Return only strict JSON matching:
{"selectedCwes":[{"cwe":"CWE-89","reason":"why","catalogSignals":["sink: query"],"sourceSpec":"source","sinkSpec":"sink","sanitizerSpec":"","customCweRationale":""}],"findings":[{"title":"short title","cwe":"CWE-89","severity":"critical|high|medium|low|info","confidence":"high|medium|low","evidenceLevel":"path|linked|candidate","filePath":"relative/path","startLine":1,"message":"detail","sourceSinkTrace":"source -> sink","catalogSignals":["source: req.query","sink: query"],"customCweRationale":"","taintPath":[{"filePath":"relative/path","line":1,"message":"source|step|sink","snippet":"code"}]}],"triage":[{"status":"finding|candidate|rejected","cwe":"CWE-89","evidenceLevel":"path|linked|candidate","rationale":"why","filePath":"relative/path","line":1,"catalogSignals":["sink: query"]}],"notes":[]}.
Select CWE themes from the bounded catalog unless customCweRationale is present. Report only concrete evidence-backed findings.

Tool usage: when MCP tools are available you should triangulate before calling a candidate a finding. Prefer at least two independent confirmations:
- `tree_sitter_node_at` / `tree_sitter_callers` to verify the candidate is real code (not in a comment, not in a test fixture) and to identify the surrounding function and callers.
- `codeql_flows_for_cwe` to look for source-to-sink flows with the same CWE label that touch the candidate file.
- `joern_taint_paths` (with sourceQuery / sinkQuery on relevant kuzushi catalog regexes) to ask the CPG for an interprocedural flow that lands at the candidate.
- `joern_callers_of` / `joern_callees_of` for context expansion when callers aren't obvious from rg output.

Treat the deterministic plan + evidence bundle as a starting point, not gospel: if a CodeQL flow or Joern taint path contradicts a candidate's CWE labelling, change the CWE and rationalise it via `customCweRationale`."#;

pub(in crate::modules) fn run_taint_iris_next_report(
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

pub(in crate::modules) fn taint_iris_next_target(
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

pub(in crate::modules) fn run_taint_iris_next_hunt(
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
    // Apply the shell-tunable MCP knobs: read each option from the input
    // (operators set them via `set taint-iris-next:hunt <key> <value>`)
    // and translate to the env vars the bridge + MCP servers honour.
    // env mutation is process-local so it only affects this kuzushi run.
    apply_taint_iris_next_mcp_options(input);
    // taint-iris-next opts the policy into the kuzushi MCP-as-agent
    // surface (tree-sitter / joern / codeql) by default. Operators can
    // turn it off per-run with `set taint-iris-next:hunt mcps false`,
    // or off globally with `setg`. The bridge still honours
    // KUZUSHI_AGENT_MCPS=1 as an env override for ad-hoc runs of other
    // modules.
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

pub(in crate::modules) fn taint_iris_next_missing_context_report(
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

pub(in crate::modules) fn taint_iris_next_planned_report(
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

pub(in crate::modules) fn require_taint_iris_next_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.context(
        "taint-iris-next:hunt requires the pi-agent-core runtime in hunt mode. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

/// Translate the taint-iris-next:hunt module options that mirror env
/// vars (joern CPG path, per-CWE timeout, codeql cache, bridge
/// verbosity, etc.) into actual environment variables on the current
/// process so the bridge + MCP child processes pick them up. Process
/// env mutation is local to this kuzushi invocation, so it doesn't
/// leak between hunts. Already-set env vars take precedence: an
/// operator who exports `KUZUSHI_BRIDGE_VERBOSE=1` in their shell
/// can rely on that without it being clobbered by an unset `set` value.
pub(in crate::modules) fn apply_taint_iris_next_mcp_options(input: &Value) {
    apply_path_option_env(input, "joernCpg", "KUZUSHI_JOERN_CPG");
    apply_int_option_env(input, "joernPerCweTimeoutMs", "KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS");
    apply_bool_option_env(input, "codeqlPrewarm", "KUZUSHI_CODEQL_PREWARM");
    apply_path_option_env(input, "codeqlCacheDir", "KUZUSHI_CODEQL_CACHE_DIR");
    apply_int_option_env(input, "mcpToolTimeoutMs", "KUZUSHI_MCP_TOOL_TIMEOUT_MS");
    apply_bool_option_env(input, "bridgeVerbose", "KUZUSHI_BRIDGE_VERBOSE");
    apply_path_option_env(input, "bridgeLogPath", "KUZUSHI_BRIDGE_LOG");
}

pub(in crate::modules) fn read_bool_option(input: &Value, key: &str) -> Option<bool> {
    let raw = input.get(key)?;
    if let Some(b) = raw.as_bool() {
        return Some(b);
    }
    if let Some(s) = raw.as_str() {
        match s.trim().to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => return Some(true),
            "false" | "0" | "no" | "off" => return Some(false),
            _ => {}
        }
    }
    if let Some(n) = raw.as_i64() {
        return Some(n != 0);
    }
    None
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
    if let Some(n) = input.get(key).and_then(Value::as_i64) {
        std::env::set_var(env, n.to_string());
    } else if let Some(s) = input.get(key).and_then(Value::as_str) {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            std::env::set_var(env, trimmed);
        }
    }
}

fn apply_path_option_env(input: &Value, key: &str, env: &str) {
    if std::env::var_os(env).is_some() {
        return;
    }
    if let Some(s) = input.get(key).and_then(Value::as_str) {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            std::env::set_var(env, trimmed);
        }
    }
}
