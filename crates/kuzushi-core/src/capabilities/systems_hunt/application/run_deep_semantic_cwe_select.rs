use super::*;

pub(crate) fn run_deep_semantic_cwe_select(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<DeepSemanticCweOutput> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let runtime = runtime.context(
        "systems-hunt:deep-semantic-cwe-select requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model(
        "systems-hunt:deep-semantic-cwe-select",
        input,
        ctx,
        &options,
    )?;
    let inventory = collect_inventory(&target, 80, 2048)?;
    let _llm_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "deep-semantic-cwe-select", "cwe-select")
            .emit();
        trace.parent_scope(phase)
    });
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.clone(),
            DEEP_SEMANTIC_CWE_SYSTEM_PROMPT.to_string(),
            format!(
            "Select relevant native-code CWE classes for this repository. Return JSON with cwes[].\n\n{}",
            format_inventory(&inventory)
        ),
        )
        .with_tool_policy(whitebox_static_policy_for_target(&target))
        .with_thinking_level(agentic_hunter_thinking_level(input)),
        StructuredJsonContract::new(
            "systems-hunt:deep-semantic-cwe-select",
            "DeepSemanticCweSelection",
            cwes_schema(),
        ),
        require_json_object,
    )?;
    drop(_llm_scope);
    Ok(DeepSemanticCweOutput {
        cwes: parse_cwe_selections(&raw)
            .into_iter()
            .take(options.max_cwe_classes)
            .collect(),
    })
}

pub(crate) fn run_deep_semantic_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsHuntReport> {
    let run = prepare_deep_semantic_hunt(input, ctx, runtime)?;
    let cwes = selected_deep_semantic_cwes(input, ctx, run.runtime, &run.options)?;
    ensure_deep_semantic_cwes_selected(&run, &cwes)?;
    finish_deep_semantic_hunt(input, ctx, &run, &cwes)
}

struct DeepSemanticHuntRun<'a> {
    target: PathBuf,
    options: SystemsHuntInput,
    runtime: &'a dyn AgentRuntime,
    model: String,
}

fn prepare_deep_semantic_hunt<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<DeepSemanticHuntRun<'a>> {
    let target = resolve_target(input, ctx)?;
    let execution = resolve_deep_semantic_execution(input, ctx, runtime)?;
    Ok(DeepSemanticHuntRun {
        target,
        options: execution.options,
        runtime: execution.runtime,
        model: execution.model,
    })
}

struct DeepSemanticExecution<'a> {
    options: SystemsHuntInput,
    runtime: &'a dyn AgentRuntime,
    model: String,
}

fn resolve_deep_semantic_execution<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<DeepSemanticExecution<'a>> {
    let options = SystemsHuntInput::from_tool_input(input)?;
    let runtime = runtime.context(
        "systems-hunt:deep-semantic-hunt requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model("systems-hunt:deep-semantic-hunt", input, ctx, &options)?;
    Ok(DeepSemanticExecution {
        options,
        runtime,
        model,
    })
}

fn ensure_deep_semantic_cwes_selected(
    run: &DeepSemanticHuntRun<'_>,
    cwes: &[DeepSemanticCweSelection],
) -> Result<()> {
    if cwes.is_empty() {
        // Was a silent `Ok(empty_report)` — the operator had no way to
        // tell whether (a) the model legitimately found no CWEs worth
        // hunting, (b) the cwe-select agent returned malformed JSON and
        // the inner Result got `.unwrap_or_default()`-ed, or (c) the
        // runtime errored and the fallback path swallowed it. Bail
        // loudly with the resolved options so the operator can see
        // what cap was in effect.
        anyhow::bail!(
            "systems-hunt:deep-semantic-hunt: CWE selection returned 0 \
             classes for target {}. The deep-semantic agent either \
             produced no candidates or its response failed to parse. \
             Re-run with an explicit `cwes` input (array of CWE strings) \
             to bypass selection, or raise `maxCweClasses` (currently {}).",
            run.target.display(),
            run.options.max_cwe_classes,
        );
    }
    Ok(())
}

fn finish_deep_semantic_hunt(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &DeepSemanticHuntRun<'_>,
    cwes: &[DeepSemanticCweSelection],
) -> Result<SystemsHuntReport> {
    let (findings, artifacts) = collect_deep_semantic_hunt_findings(input, ctx, run, cwes)?;
    let persisted = persist_systems_findings(&run.target, &findings, ctx)?;
    Ok(deep_semantic_report(run, findings, persisted, artifacts))
}

fn collect_deep_semantic_hunt_findings(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &DeepSemanticHuntRun<'_>,
    cwes: &[DeepSemanticCweSelection],
) -> Result<(Vec<Finding>, Vec<String>)> {
    let raw = query_deep_semantic_with_scope(input, ctx, run, cwes)?;
    normalized_deep_semantic_hunt(input, run, raw)
}

fn deep_semantic_report(
    run: &DeepSemanticHuntRun<'_>,
    findings: Vec<Finding>,
    persisted: Option<SystemsHuntPersistedRun>,
    artifacts: Vec<String>,
) -> SystemsHuntReport {
    SystemsHuntReport {
        target: run.target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        artifacts,
        cost_usd: 0.0,
    }
}

fn query_deep_semantic_with_scope(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &DeepSemanticHuntRun<'_>,
    cwes: &[DeepSemanticCweSelection],
) -> Result<Value> {
    let _llm_scope = begin_deep_semantic_scope(ctx);
    let raw =
        query_deep_semantic_findings(run.runtime, run.model.clone(), input, &run.target, cwes)?;
    drop(_llm_scope);
    Ok(raw)
}

fn begin_deep_semantic_scope(
    ctx: &ToolExecutionContext<'_>,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "deep-semantic-hunt", "deep-semantic-hunt")
            .emit();
        trace.parent_scope(phase)
    })
}

fn normalized_deep_semantic_hunt(
    input: &Value,
    run: &DeepSemanticHuntRun<'_>,
    raw: Value,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let artifact_root = artifact_root(&run.target, &run.options.artifact_dir)?;
    let (mut findings, artifacts) = normalize_deep_semantic_findings(
        raw,
        &run.target,
        &artifact_root,
        run.options.max_findings,
    )?;
    apply_deep_semantic_whitebox_profile(input, &mut findings)?;
    Ok((findings, artifacts))
}

pub(crate) fn selected_deep_semantic_cwes(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    options: &SystemsHuntInput,
) -> Result<Vec<DeepSemanticCweSelection>> {
    let cwes = match cwes_from_input(input) {
        Some(cwes) => cwes,
        None => fallback_deep_semantic_cwes(input, ctx, runtime)?,
    };
    Ok(cwes.into_iter().take(options.max_cwe_classes).collect())
}

pub(crate) fn fallback_deep_semantic_cwes(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
) -> Result<Vec<DeepSemanticCweSelection>> {
    // Used to be `.unwrap_or_default()` — any failure inside
    // `run_deep_semantic_cwe_select` (bridge crash, structured-JSON
    // contract failure, model 429, parse error) silently produced an
    // empty Vec, which the caller turned into a 0-finding success.
    // Surface the underlying cause so the operator can fix it instead
    // of staring at "0 findings, ok: true".
    let output = run_deep_semantic_cwe_select(input, ctx, Some(runtime))
        .context("systems-hunt:deep-semantic-cwe-select failed; cannot fall back to empty CWE list because that hides agent/bridge errors")?;
    Ok(output.cwes)
}
