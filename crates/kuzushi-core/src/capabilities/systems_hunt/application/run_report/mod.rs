use super::*;

#[cfg(test)]
mod invariant_extract;
#[cfg(test)]
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
    parent_step: Option<crate::run_lifecycle::RunItemId>,
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
    artifact_root(&target, &options.artifact_dir)?;
    let parent_step = emit_systems_hunt_start(ctx, &target);
    emit_systems_hunt_progress(ctx, parent_step, "context · gather systems surfaces");
    let context = gather_systems_context(&target, &options)?;
    ensure_systems_hunt_surfaces(ctx, &target, &options, &context)?;
    emit_systems_hunt_progress(
        ctx,
        parent_step,
        format!("context · {} surfaces selected", context.surfaces.len()),
    );
    let execution = resolve_systems_hunt_execution(input, ctx, &options, runtime, &target)?;
    emit_systems_hunt_progress(ctx, parent_step, "agent · runtime/model resolved");
    Ok(SystemsHuntRun {
        target,
        parent_step,
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
    target: &Path,
) -> Result<SystemsHuntExecution<'a>> {
    let runtime = required_systems_runtime(runtime, "systems-hunt")?;
    let model = resolve_model("systems-hunt", input, ctx, options)?;
    let whitebox_static = whitebox_static_profile_requested(input)?;
    Ok(SystemsHuntExecution {
        runtime,
        model,
        agent_tool_policy: selected_whitebox_static_policy_for_target(target, input)?,
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
    cost_usd_exact: bool,
}

/// The target has no production C/C++/Rust/Go/Zig source, so a
/// memory-safety hunt does not apply. The tool reports this as `skipped`
/// rather than failing a scan that simply selected every engine.
#[derive(Debug)]
pub(crate) struct SystemsHuntNotApplicable {
    pub(crate) target: String,
}

impl std::fmt::Display for SystemsHuntNotApplicable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "systems-hunt does not apply: no C/C++/Rust/Go/Zig production source under {}",
            self.target
        )
    }
}

impl std::error::Error for SystemsHuntNotApplicable {}

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
    if context.metadata.systems_source_files == 0 {
        return Err(SystemsHuntNotApplicable {
            target: target.display().to_string(),
        }
        .into());
    }
    anyhow::bail!(
        "systems-hunt: no memory-safety surfaces detected under {}. \
         gather_systems_context yielded 0 surfaces from max_files={} \
         head_bytes={} max_surfaces={}. Likely causes: target has no \
         C/C++/Rust source, or `maxFiles`/`headBytes` is too restrictive, \
         or the cpg/codeql augmentation backend errored silently. \
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
    let _llm_scope = begin_systems_hunt_scope(ctx, run.parent_step);
    emit_selected_systems_surfaces(ctx, run.parent_step, &run.context);
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
    parent_step: Option<crate::run_lifecycle::RunItemId>,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };
    let phase = trace
        .child(parent)
        .step("reasoning", "systems-hunt", "invariants · triggers · hunt")
        .emit();
    Some(trace.parent_scope(phase))
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
        cost_usd_exact: raw.cost_usd_exact,
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

fn emit_systems_hunt_start(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
) -> Option<crate::run_lifecycle::RunItemId> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "systems-hunt",
                format!("systems-hunt start · target={}", target.display()),
            )
            .emit()
    })
}

fn emit_systems_hunt_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };
    let _ = trace
        .child(parent)
        .step("tool-progress", "systems-hunt", label.into())
        .emit();
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

fn emit_selected_systems_surfaces(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    context: &SystemsContextOutput,
) {
    emit_systems_hunt_progress(ctx, parent_step, selected_surfaces_trace_label(context));
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
    SystemsHuntQuery {
        runtime,
        model,
        target,
        context,
        options,
        agent_tool_policy,
        thinking_level,
    }
    .execute()
}

struct SystemsHuntQuery<'a> {
    runtime: &'a dyn AgentRuntime,
    model: &'a str,
    target: &'a Path,
    context: &'a SystemsContextOutput,
    options: &'a SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: &'a str,
}

impl SystemsHuntQuery<'_> {
    fn execute(&self) -> Result<CostedSystemsHuntRaw> {
        let invariants = self.query_invariants()?;
        let triggers = self.query_triggers(&invariants.value)?;
        let findings = query_final_systems_findings(
            self.runtime,
            self.model,
            self.target,
            self.context,
            self.options,
            self.agent_tool_policy.clone(),
            self.thinking_level,
            &invariants.value,
            &triggers.value,
        )?;
        merge_systems_hunt_costs(&invariants, &triggers, findings)
    }

    fn query_invariants(&self) -> Result<CostedStructuredJson<SystemsInvariantOutput>> {
        query_systems_invariants_with_cost(
            self.runtime,
            self.model,
            self.target,
            self.context,
            self.options,
            self.agent_tool_policy.clone(),
            self.thinking_level,
        )
    }

    fn query_triggers(
        &self,
        invariants: &SystemsInvariantOutput,
    ) -> Result<CostedStructuredJson<SystemsTriggerOutput>> {
        query_systems_triggers_with_cost(
            self.runtime,
            self.model,
            self.target,
            self.context,
            invariants,
            self.options,
            self.agent_tool_policy.clone(),
            self.thinking_level,
        )
    }
}

fn merge_systems_hunt_costs(
    invariants: &CostedStructuredJson<SystemsInvariantOutput>,
    triggers: &CostedStructuredJson<SystemsTriggerOutput>,
    findings: CostedStructuredJson<Value>,
) -> Result<CostedSystemsHuntRaw> {
    let total_cost = invariants
        .cost_report()?
        .checked_add(
            triggers.cost_report()?,
            "systems-hunt invariant and trigger cost",
        )?
        .checked_add(
            findings.cost_report()?,
            "systems-hunt invariant, trigger, and finding cost",
        )?;
    Ok(CostedSystemsHuntRaw {
        raw: findings.value,
        cost_usd: total_cost.observed_usd(),
        cost_usd_exact: total_cost.is_complete(),
    })
}

#[allow(clippy::too_many_arguments)]
fn query_final_systems_findings(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: &str,
    invariants: &SystemsInvariantOutput,
    triggers: &SystemsTriggerOutput,
) -> Result<CostedStructuredJson<Value>> {
    let prompt = build_systems_hunt_prompt(target, context, invariants, triggers, options)?;
    let request = AgentQueryRequest::new(
        model.to_string(),
        target.to_path_buf(),
        options.hunt_system_prompt.clone(),
        prompt,
    )
    .with_tool_policy(agent_tool_policy)
    .with_thinking_level(thinking_level.to_string());
    query_required_structured_json_with_cost(
        runtime,
        request,
        StructuredJsonContract::new(
            "systems-hunt:systems-hunt",
            "SystemsHuntFindings",
            findings_schema(),
        ),
        require_json_object,
    )
}
