use super::*;

pub(crate) fn run_taint_iris_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<TaintIrisReport> {
    let run = prepare_taint_iris_hunt_run(input, ctx, runtime)?;
    let cwes = select_taint_iris_cwes(input, ctx, &run)?;
    if cwes.is_empty() {
        return finish_empty_taint_iris_hunt(ctx, &run.target, cwes);
    }
    finish_taint_iris_hunt(input, ctx, run, cwes)
}

struct TaintIrisHuntRun<'a> {
    target: PathBuf,
    options: TaintIrisInput,
    runtime: &'a dyn AgentRuntime,
    model: String,
    parent_step: Option<usize>,
}

struct TaintIrisExecution<'a> {
    options: TaintIrisInput,
    runtime: &'a dyn AgentRuntime,
    model: String,
}

fn prepare_taint_iris_hunt_run<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<TaintIrisHuntRun<'a>> {
    let target = resolve_taint_iris_target(input, ctx)?;
    let execution = resolve_taint_iris_execution(input, ctx, runtime, &target)?;
    let parent_step = emit_taint_iris_start(ctx, &target);

    Ok(TaintIrisHuntRun {
        target,
        options: execution.options,
        runtime: execution.runtime,
        model: execution.model,
        parent_step,
    })
}

fn resolve_taint_iris_execution<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
    target: &Path,
) -> Result<TaintIrisExecution<'a>> {
    let options = TaintIrisInput::from_tool_input(input, target)?;
    let runtime = require_taint_iris_runtime(runtime)?;
    let model = require_taint_iris_model(input, ctx)?;
    Ok(TaintIrisExecution {
        options,
        runtime,
        model,
    })
}

fn emit_taint_iris_start(ctx: &ToolExecutionContext<'_>, target: &Path) -> Option<usize> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "hunt",
                format!("taint-iris:hunt start · target={}", target.display()),
            )
            .emit()
    })
}

fn select_taint_iris_cwes(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &TaintIrisHuntRun<'_>,
) -> Result<Vec<TaintCweSelection>> {
    // Phase scope so the cwe-select LLM call lands as a child of the
    // tool's start row in the feed.
    let _cwe_scope = begin_taint_iris_phase_scope(ctx, run.parent_step, "cwe-select".to_string());
    let cwes = selected_taint_iris_cwes(
        input,
        &run.target,
        run.runtime,
        &run.model,
        run.options.max_cwes,
    )?;
    drop(_cwe_scope);
    emit_taint_iris_reasoning(
        ctx,
        run.parent_step,
        format!("cwe-select · {} CWE classes selected", cwes.len()),
    );
    Ok(cwes)
}

fn begin_taint_iris_phase_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    label: String,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };

    let phase = trace.child(parent).step("reasoning", "hunt", label).emit();
    Some(trace.parent_scope(phase))
}

fn emit_taint_iris_reasoning(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    label: String,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };

    let _ = trace.child(parent).step("reasoning", "hunt", label).emit();
}

fn finish_empty_taint_iris_hunt(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    cwes: Vec<TaintCweSelection>,
) -> Result<TaintIrisReport> {
    emit_taint_iris_done(
        ctx,
        "taint-iris:hunt complete · no CWEs selected".to_string(),
    );
    empty_taint_iris_report(target, cwes, ctx)
}

fn finish_taint_iris_hunt(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: TaintIrisHuntRun<'_>,
    cwes: Vec<TaintCweSelection>,
) -> Result<TaintIrisReport> {
    let completed = completed_taint_iris_hunt(input, ctx, &run, cwes)?;
    emit_taint_iris_done(
        ctx,
        format!(
            "taint-iris:hunt complete · {} findings",
            completed.finding_count
        ),
    );

    Ok(completed.report)
}

struct CompletedTaintIrisHunt {
    report: TaintIrisReport,
    finding_count: usize,
}

fn completed_taint_iris_hunt(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &TaintIrisHuntRun<'_>,
    cwes: Vec<TaintCweSelection>,
) -> Result<CompletedTaintIrisHunt> {
    let findings = collect_taint_iris_findings(input, ctx, run, &cwes)?;
    let finding_count = findings.len();
    let persisted = persist_taint_iris_findings(&run.target, &findings, ctx)?;
    Ok(CompletedTaintIrisHunt {
        report: taint_iris_report(&run.target, cwes, findings, persisted, None),
        finding_count,
    })
}

fn collect_taint_iris_findings(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &TaintIrisHuntRun<'_>,
    cwes: &[TaintCweSelection],
) -> Result<Vec<Finding>> {
    let raw = query_taint_iris_with_scope(input, ctx, run, cwes)?;
    normalized_taint_iris_findings(input, raw, run)
}

fn query_taint_iris_with_scope(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    run: &TaintIrisHuntRun<'_>,
    cwes: &[TaintCweSelection],
) -> Result<Value> {
    // Phase scope so the agent's taint-trace round-trips appear under
    // taint-trace in the feed.
    let _trace_scope = begin_taint_iris_phase_scope(
        ctx,
        run.parent_step,
        format!("taint-trace · {} CWE classes", cwes.len()),
    );
    let raw = query_taint_iris_agent(
        input,
        &run.target,
        ctx,
        run.runtime,
        &run.model,
        cwes,
        &run.options,
    )?;
    drop(_trace_scope);
    Ok(raw)
}

fn normalized_taint_iris_findings(
    input: &Value,
    raw: Value,
    run: &TaintIrisHuntRun<'_>,
) -> Result<Vec<Finding>> {
    let mut findings = normalize_taint_iris_findings(raw, &run.target, run.options.max_findings)?;
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SourceSinkLinked)?;
    }
    Ok(findings)
}

fn emit_taint_iris_done(ctx: &ToolExecutionContext<'_>, label: String) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "hunt", label).emit();
    }
}

fn resolve_taint_iris_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let target = resolve_tool_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "taint-iris:hunt target is not a directory: {}",
            target.display()
        );
    }
    Ok(target)
}

pub(crate) fn require_taint_iris_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.context(
        "taint-iris:hunt requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )
}

pub(crate) fn require_taint_iris_model(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        "taint-iris:hunt",
        optional_nonempty_string(input, "model")?,
        ctx.config.model.as_deref(),
    )
}

pub(crate) fn selected_taint_iris_cwes(
    input: &Value,
    target: &Path,
    runtime: &dyn AgentRuntime,
    model: &str,
    max_cwes: Option<usize>,
) -> Result<Vec<TaintCweSelection>> {
    let mut cwes = run_taint_cwe_select_value(input, target, Some(runtime), Some(model))?;
    if let Some(max_cwes) = max_cwes {
        cwes.truncate(max_cwes);
    }
    Ok(cwes)
}

pub(crate) fn empty_taint_iris_report(
    target: &Path,
    cwes: Vec<TaintCweSelection>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<TaintIrisReport> {
    let findings = Vec::new();
    let persisted = persist_taint_iris_findings(target, &findings, ctx)?;
    Ok(taint_iris_report(
        target,
        cwes,
        findings,
        persisted,
        Some(json!({
            "type": "legacy-inconclusive",
            "reason": "no-cwes-selected",
            "message": "No CWE classes were selected, so the IRIS taint agent did not run; treat as inconclusive, not clean.",
        })),
    ))
}

pub(crate) fn query_taint_iris_agent(
    input: &Value,
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    model: &str,
    cwes: &[TaintCweSelection],
    options: &TaintIrisInput,
) -> Result<Value> {
    let inventory = collect_agentic_repo_inventory(target, 80, 2048)?;
    let codeql_db = resolve_taint_codeql_db_path(target, ctx.workspace.map(WorkspaceTarget::root));
    query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            TAINT_IRIS_SYSTEM_PROMPT.to_string(),
            build_taint_iris_prompt(target, cwes, &inventory, codeql_db.as_deref(), options),
        )
        .with_tool_policy(agent_tool_policy_for_input_and_target(input, target)?),
        StructuredJsonContract::new(
            "taint-iris:hunt",
            "TaintIrisFindings",
            findings_array_schema(),
        ),
        require_json_object,
    )
}
