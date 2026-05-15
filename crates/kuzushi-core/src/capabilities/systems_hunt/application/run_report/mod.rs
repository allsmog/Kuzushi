use super::*;

mod invariant_extract;
pub(crate) use invariant_extract::run_systems_invariant_extract;

pub fn run_systems_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsHuntReport> {
    let run = prepare_systems_hunt_run(input, ctx, runtime)?;
    let raw = query_systems_hunt_with_scope(&run, ctx)?;
    let report = finalize_systems_hunt_report(raw, ctx, &run)?;
    emit_systems_hunt_done(ctx, report.count);
    Ok(report)
}

struct SystemsHuntRun<'a> {
    target: PathBuf,
    options: SystemsHuntInput,
    context: SystemsContextOutput,
    runtime: &'a dyn AgentRuntime,
    model: String,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: String,
    whitebox_static: bool,
}

fn prepare_systems_hunt_run<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<SystemsHuntRun<'a>> {
    let target = systems_hunt_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    emit_systems_hunt_start(ctx, &target);
    let context = gather_systems_context(&target, &options)?;
    ensure_systems_hunt_surfaces(ctx, &target, &options, &context)?;
    let execution = resolve_systems_hunt_execution(input, ctx, &options, runtime)?;
    Ok(SystemsHuntRun {
        target,
        options,
        context,
        runtime: execution.runtime,
        model: execution.model,
        agent_tool_policy: execution.agent_tool_policy,
        thinking_level: execution.thinking_level,
        whitebox_static: execution.whitebox_static,
    })
}

struct SystemsHuntExecution<'a> {
    runtime: &'a dyn AgentRuntime,
    model: String,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: String,
    whitebox_static: bool,
}

fn resolve_systems_hunt_execution<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    options: &SystemsHuntInput,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<SystemsHuntExecution<'a>> {
    let runtime = required_systems_runtime(runtime, "systems-hunt")?;
    let model = resolve_model("systems-hunt", input, ctx, options)?;
    let whitebox_static = whitebox_static_profile_requested(input)?;
    Ok(SystemsHuntExecution {
        runtime,
        model,
        agent_tool_policy: default_whitebox_static_agent_tool_policy(),
        thinking_level: agentic_hunter_thinking_level(input),
        whitebox_static,
    })
}

fn systems_hunt_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let target = resolve_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "systems-hunt: target is not a directory: {}",
            target.display()
        );
    }
    Ok(target)
}

struct CostedSystemsHuntRaw {
    raw: Value,
    cost_usd: f64,
}

fn ensure_systems_hunt_surfaces(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    options: &SystemsHuntInput,
    context: &SystemsContextOutput,
) -> Result<()> {
    if !context.surfaces.is_empty() {
        return Ok(());
    }
    emit_systems_hunt_refused(ctx);
    anyhow::bail!(
        "systems-hunt: no memory-safety surfaces detected under {}. \
         gather_systems_context yielded 0 surfaces from max_files={} \
         head_bytes={} max_surfaces={}. Likely causes: target has no \
         C/C++/Rust source, or `maxFiles`/`headBytes` is too restrictive, \
         or the joern/codeql augmentation backend errored silently. \
         Re-run with larger inventory caps, or scope to a directory \
         that contains systems-level code.",
        target.display(),
        options.max_files,
        options.head_bytes,
        options.max_surfaces,
    );
}

fn query_systems_hunt_with_scope(
    run: &SystemsHuntRun<'_>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CostedSystemsHuntRaw> {
    let _llm_scope = begin_systems_hunt_scope(ctx);
    emit_selected_systems_surfaces(ctx, &run.context);
    let raw = query_systems_hunt_findings(
        run.runtime,
        &run.model,
        &run.target,
        &run.context,
        &run.options,
        run.agent_tool_policy.clone(),
        &run.thinking_level,
    )?;
    drop(_llm_scope);
    Ok(raw)
}

fn begin_systems_hunt_scope(
    ctx: &ToolExecutionContext<'_>,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "systems-hunt", "invariants · triggers · hunt")
            .emit();
        trace.parent_scope(phase)
    })
}

fn finalize_systems_hunt_report(
    raw: CostedSystemsHuntRaw,
    ctx: &ToolExecutionContext<'_>,
    run: &SystemsHuntRun<'_>,
) -> Result<SystemsHuntReport> {
    let artifact_root = artifact_root(&run.target, &run.options.artifact_dir)?;
    let (mut findings, artifacts) = normalize_systems_hunt_findings(
        raw.raw,
        &run.target,
        &run.context,
        &artifact_root,
        run.options.max_findings,
    )?;
    apply_systems_hunt_whitebox_profile(run, &mut findings)?;
    let persisted = persist_systems_findings(&run.target, &findings, ctx)?;

    Ok(SystemsHuntReport {
        target: run.target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        artifacts,
        cost_usd: raw.cost_usd,
    })
}

fn apply_systems_hunt_whitebox_profile(
    run: &SystemsHuntRun<'_>,
    findings: &mut [Finding],
) -> Result<()> {
    if run.whitebox_static {
        mark_whitebox_static_findings(findings, StaticProofState::CodeCited)?;
    }
    Ok(())
}

fn emit_systems_hunt_start(ctx: &ToolExecutionContext<'_>, target: &Path) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "systems-hunt",
                format!("systems-hunt start · target={}", target.display()),
            )
            .emit();
    }
}

fn emit_systems_hunt_refused(ctx: &ToolExecutionContext<'_>) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "refused",
                "systems-hunt",
                "systems-hunt refused · no native surfaces detected",
            )
            .emit();
    }
}

fn emit_systems_hunt_done(ctx: &ToolExecutionContext<'_>, finding_count: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "systems-hunt",
                format!("systems-hunt complete · {finding_count} findings"),
            )
            .emit();
    }
}

fn emit_selected_systems_surfaces(ctx: &ToolExecutionContext<'_>, context: &SystemsContextOutput) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "systems-hunt",
                selected_surfaces_trace_label(context),
            )
            .emit();
    }
}

fn selected_surfaces_trace_label(context: &SystemsContextOutput) -> String {
    let surfaces = context
        .surfaces
        .iter()
        .map(|surface| {
            format!(
                "{}:{} ({})",
                surface.file_path, surface.start_line, surface.kind
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("systems-hunt selected surfaces · {surfaces}")
}

fn query_systems_hunt_findings(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: &str,
) -> Result<CostedSystemsHuntRaw> {
    let invariants = query_systems_invariants_with_cost(
        runtime,
        model,
        target,
        context,
        options,
        agent_tool_policy.clone(),
        thinking_level,
    )?;
    let triggers = query_systems_triggers_with_cost(
        runtime,
        model,
        target,
        context,
        &invariants.value,
        options,
        agent_tool_policy.clone(),
        thinking_level,
    )?;
    let findings = query_required_structured_json_with_cost(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            SYSTEMS_HUNT_SYSTEM_PROMPT.to_string(),
            build_systems_hunt_prompt(
                target,
                context,
                &invariants.value,
                &triggers.value,
                options,
            )?,
        )
        .with_tool_policy(agent_tool_policy)
        .with_thinking_level(thinking_level.to_string()),
        StructuredJsonContract::new(
            "systems-hunt:systems-hunt",
            "SystemsHuntFindings",
            findings_schema(),
        ),
        require_json_object,
    )?;
    Ok(CostedSystemsHuntRaw {
        raw: findings.value,
        cost_usd: invariants.cost_usd + triggers.cost_usd + findings.cost_usd,
    })
}
