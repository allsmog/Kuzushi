use super::*;

mod invariant_extract;
pub(crate) use invariant_extract::run_systems_invariant_extract;

pub fn run_systems_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsHuntReport> {
    let target = systems_hunt_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "systems-hunt",
                format!("systems-hunt start · target={}", target.display()),
            )
            .emit();
    }
    let context = gather_systems_context(&target, &options)?;
    if context.surfaces.is_empty() {
        if let Some(trace) = ctx.trace {
            let _ = trace
                .step(
                    "refused",
                    "systems-hunt",
                    "systems-hunt refused · no native surfaces detected",
                )
                .emit();
        }
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

    let runtime = required_systems_runtime(runtime, "systems-hunt")?;
    let model = resolve_model("systems-hunt", input, ctx, &options)?;
    let agent_tool_policy = default_whitebox_static_agent_tool_policy();
    let thinking_level = agentic_hunter_thinking_level(input);
    let _llm_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "systems-hunt", "invariants · triggers · hunt")
            .emit();
        trace.parent_scope(phase)
    });
    let raw = query_systems_hunt_findings(
        runtime,
        &model,
        &target,
        &context,
        &options,
        agent_tool_policy,
        &thinking_level,
    )?;
    drop(_llm_scope);
    let report = finalize_systems_hunt_report(raw, input, ctx, &target, &context, &options)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "systems-hunt",
                format!("systems-hunt complete · {} findings", report.count),
            )
            .emit();
    }
    Ok(report)
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

fn finalize_systems_hunt_report(
    raw: Value,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    context: &SystemsContextOutput,
    options: &SystemsHuntInput,
) -> Result<SystemsHuntReport> {
    let artifact_root = artifact_root(target, &options.artifact_dir)?;
    let (mut findings, artifacts) = normalize_systems_hunt_findings(
        raw,
        target,
        context,
        &artifact_root,
        options.max_findings,
    )?;
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::CodeCited)?;
    }
    let persisted = persist_systems_findings(target, &findings, ctx)?;

    Ok(SystemsHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        artifacts,
        cost_usd: 0.0,
    })
}

fn query_systems_hunt_findings(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: &str,
) -> Result<Value> {
    let invariants = query_systems_invariants(
        runtime,
        model,
        target,
        context,
        options,
        agent_tool_policy.clone(),
        thinking_level,
    )?;
    let triggers = query_systems_triggers(
        runtime,
        model,
        target,
        context,
        &invariants,
        options,
        agent_tool_policy.clone(),
        thinking_level,
    )?;
    query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            SYSTEMS_HUNT_SYSTEM_PROMPT.to_string(),
            build_systems_hunt_prompt(target, context, &invariants, &triggers, options)?,
        )
        .with_tool_policy(agent_tool_policy)
        .with_thinking_level(thinking_level.to_string()),
        StructuredJsonContract::new(
            "systems-hunt:systems-hunt",
            "SystemsHuntFindings",
            findings_schema(),
        ),
        require_json_object,
    )
}
