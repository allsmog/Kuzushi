use super::*;

pub(crate) fn run_deep_semantic_cwe_select(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<DeepSemanticCweOutput> {
    let run = prepare_deep_semantic_cwe_select(input, ctx, runtime)?;
    let raw = query_deep_semantic_cwe_select(input, ctx, &run)?;
    Ok(deep_semantic_cwe_output(ctx, &run, raw))
}

struct DeepSemanticCweSelectRun<'a> {
    target: PathBuf,
    options: SystemsHuntInput,
    runtime: &'a dyn AgentRuntime,
    model: String,
    inventory: Vec<(String, String)>,
    parent_step: Option<usize>,
}

fn prepare_deep_semantic_cwe_select<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<DeepSemanticCweSelectRun<'a>> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let parent_step = emit_deep_semantic_start(
        ctx,
        "deep-semantic-cwe-select",
        format!("target={}", target.display()),
    );
    let runtime = deep_semantic_cwe_runtime(runtime)?;
    let model = resolve_model(
        "systems-hunt:deep-semantic-cwe-select",
        input,
        ctx,
        &options,
    )?;
    let inventory = collect_deep_semantic_cwe_inventory(ctx, parent_step, &target)?;
    Ok(DeepSemanticCweSelectRun {
        target,
        options,
        runtime,
        model,
        inventory,
        parent_step,
    })
}

fn deep_semantic_cwe_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "systems-hunt:deep-semantic-cwe-select requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )
}

fn collect_deep_semantic_cwe_inventory(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    target: &Path,
) -> Result<Vec<(String, String)>> {
    emit_deep_semantic_progress(
        ctx,
        parent_step,
        "deep-semantic-cwe-select",
        "inventory · collect native-code snippets",
    );
    let inventory = collect_inventory(&target, 80, 2048)?;
    emit_deep_semantic_progress(
        ctx,
        parent_step,
        "deep-semantic-cwe-select",
        format!("inventory · {} snippets loaded", inventory.len()),
    );
    Ok(inventory)
}

fn query_deep_semantic_cwe_select(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &DeepSemanticCweSelectRun<'_>,
) -> Result<CostedStructuredJson<Value>> {
    let _llm_scope =
        begin_deep_semantic_child_scope(ctx, run.parent_step, "cwe-select", "cwe-select");
    let raw = query_required_structured_json_with_cost(
        run.runtime,
        AgentQueryRequest::new(
            run.model.clone(),
            run.target.clone(),
            run.options.deep_semantic_cwe_system_prompt.clone(),
            format!(
            "Select relevant native-code CWE classes for this repository. Return JSON with cwes[].\n\n{}",
            format_inventory(&run.inventory)
        ),
        )
        .with_tool_policy(whitebox_static_policy_for_target(&run.target))
        .with_thinking_level(agentic_hunter_thinking_level(input)),
        StructuredJsonContract::new(
            "systems-hunt:deep-semantic-cwe-select",
            "DeepSemanticCweSelection",
            cwes_schema(),
        ),
        require_json_object,
    )?;
    drop(_llm_scope);
    Ok(raw)
}

fn deep_semantic_cwe_output(
    ctx: &ToolExecutionContext<'_>,
    run: &DeepSemanticCweSelectRun<'_>,
    raw: CostedStructuredJson<Value>,
) -> DeepSemanticCweOutput {
    let output = DeepSemanticCweOutput {
        cwes: parse_cwe_selections(&raw.value)
            .into_iter()
            .take(run.options.max_cwe_classes)
            .collect(),
        cost_usd: raw.cost_usd,
        cost_usd_exact: raw.cost_usd_exact,
    };
    emit_deep_semantic_done(
        ctx,
        "deep-semantic-cwe-select",
        format!("{} CWE classes", output.cwes.len()),
    );
    output
}

pub(crate) fn run_deep_semantic_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsHuntReport> {
    let run = prepare_deep_semantic_hunt(input, ctx, runtime)?;
    let cwes = selected_deep_semantic_cwes(input, ctx, run.runtime, &run.options)?;
    ensure_deep_semantic_cwes_selected(&run, &cwes.value)?;
    finish_deep_semantic_hunt(input, ctx, &run, cwes)
}

struct DeepSemanticHuntRun<'a> {
    target: PathBuf,
    parent_step: Option<usize>,
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
    let parent_step = emit_deep_semantic_start(
        ctx,
        "deep-semantic-hunt",
        format!("target={}", target.display()),
    );
    let execution = resolve_deep_semantic_execution(input, ctx, runtime)?;
    artifact_root(&target, &execution.options.artifact_dir)?;
    Ok(DeepSemanticHuntRun {
        target,
        parent_step,
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
    cwes: CostedStructuredJson<Vec<DeepSemanticCweSelection>>,
) -> Result<SystemsHuntReport> {
    emit_deep_semantic_progress(
        ctx,
        run.parent_step,
        "deep-semantic-hunt",
        "cwe-select · choose classes",
    );
    let findings = collect_deep_semantic_hunt_findings(input, ctx, run, &cwes.value)?;
    let persisted = persist_systems_findings(&run.target, &findings.value.0, ctx)?;
    let total_cost = cwes.cost_report()?.checked_add(
        findings.cost_report()?,
        "deep-semantic selection plus hunt cost",
    )?;
    let report = deep_semantic_report(
        run,
        findings.value.0,
        persisted,
        findings.value.1,
        total_cost.observed_usd(),
        total_cost.is_complete(),
    );
    emit_deep_semantic_done(
        ctx,
        "deep-semantic-hunt",
        format!("{} findings", report.count),
    );
    Ok(report)
}

fn collect_deep_semantic_hunt_findings(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &DeepSemanticHuntRun<'_>,
    cwes: &[DeepSemanticCweSelection],
) -> Result<CostedStructuredJson<(Vec<Finding>, Vec<String>)>> {
    let raw = query_deep_semantic_with_scope(input, ctx, run, cwes)?;
    Ok(CostedStructuredJson {
        value: normalized_deep_semantic_hunt(input, run, raw.value)?,
        cost_usd: raw.cost_usd,
        cost_usd_exact: raw.cost_usd_exact,
    })
}

fn deep_semantic_report(
    run: &DeepSemanticHuntRun<'_>,
    findings: Vec<Finding>,
    persisted: Option<SystemsHuntPersistedRun>,
    artifacts: Vec<String>,
    cost_usd: f64,
    cost_usd_exact: bool,
) -> SystemsHuntReport {
    SystemsHuntReport {
        target: run.target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        artifacts,
        cost_usd,
        cost_usd_exact,
    }
}

fn query_deep_semantic_with_scope(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &DeepSemanticHuntRun<'_>,
    cwes: &[DeepSemanticCweSelection],
) -> Result<CostedStructuredJson<Value>> {
    let _llm_scope = begin_deep_semantic_child_scope(
        ctx,
        run.parent_step,
        "deep-semantic-hunt",
        "deep-semantic-hunt",
    );
    let raw = query_deep_semantic_findings(
        run.runtime,
        run.model.clone(),
        input,
        &run.target,
        cwes,
        &run.options.deep_semantic_hunt_system_prompt,
    )?;
    drop(_llm_scope);
    Ok(raw)
}

fn emit_deep_semantic_start(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    label: impl Into<String>,
) -> Option<usize> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                verb,
                format!("systems-hunt:{verb} start · {}", label.into()),
            )
            .emit()
    })
}

fn emit_deep_semantic_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    verb: &str,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };
    let _ = trace
        .child(parent)
        .step("tool-progress", verb, label.into())
        .emit();
}

fn begin_deep_semantic_child_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    verb: &str,
    label: &str,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };
    let phase = trace.child(parent).step("reasoning", verb, label).emit();
    Some(trace.parent_scope(phase))
}

fn emit_deep_semantic_done(ctx: &ToolExecutionContext<'_>, verb: &str, summary: String) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                verb,
                format!("systems-hunt:{verb} complete · {summary}"),
            )
            .emit();
    }
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
) -> Result<CostedStructuredJson<Vec<DeepSemanticCweSelection>>> {
    let cwes = match cwes_from_input(input) {
        Some(cwes) => CostedStructuredJson {
            value: cwes,
            cost_usd: 0.0,
            cost_usd_exact: true,
        },
        None => fallback_deep_semantic_cwes(input, ctx, runtime)?,
    };
    Ok(CostedStructuredJson {
        value: cwes
            .value
            .into_iter()
            .take(options.max_cwe_classes)
            .collect(),
        cost_usd: cwes.cost_usd,
        cost_usd_exact: cwes.cost_usd_exact,
    })
}

pub(crate) fn fallback_deep_semantic_cwes(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
) -> Result<CostedStructuredJson<Vec<DeepSemanticCweSelection>>> {
    // Used to be `.unwrap_or_default()` — any failure inside
    // `run_deep_semantic_cwe_select` (bridge crash, structured-JSON
    // contract failure, model 429, parse error) silently produced an
    // empty Vec, which the caller turned into a 0-finding success.
    // Surface the underlying cause so the operator can fix it instead
    // of staring at "0 findings, ok: true".
    let output = run_deep_semantic_cwe_select(input, ctx, Some(runtime))
        .context("systems-hunt:deep-semantic-cwe-select failed; cannot fall back to empty CWE list because that hides agent/bridge errors")?;
    Ok(CostedStructuredJson {
        value: output.cwes,
        cost_usd: output.cost_usd,
        cost_usd_exact: output.cost_usd_exact,
    })
}
