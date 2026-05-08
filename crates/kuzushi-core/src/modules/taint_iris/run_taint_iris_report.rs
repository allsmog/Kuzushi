use super::*;

pub(in crate::modules) fn run_taint_iris_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<TaintIrisReport> {
    let target = resolve_taint_iris_target(input, ctx)?;
    let options = TaintIrisInput::from_tool_input(input, &target)?;
    let runtime = require_taint_iris_runtime(runtime)?;
    let model = require_taint_iris_model(input, ctx)?;
    let parent_step = ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "hunt",
                format!("taint-iris:hunt start · target={}", target.display()),
            )
            .emit()
    });

    let cwes = selected_taint_iris_cwes(input, &target, runtime, &model, options.max_cwes)?;
    if let (Some(trace), Some(parent)) = (ctx.trace, parent_step) {
        let _ = trace
            .child(parent)
            .step(
                "reasoning",
                "hunt",
                format!("cwe-select · {} CWE classes selected", cwes.len()),
            )
            .emit();
    }

    if cwes.is_empty() {
        if let Some(trace) = ctx.trace {
            let _ = trace
                .step("done", "hunt", "taint-iris:hunt complete · no CWEs selected")
                .emit();
        }
        return empty_taint_iris_report(&target, cwes, ctx);
    }

    let raw = query_taint_iris_agent(input, &target, ctx, runtime, &model, &cwes, &options)?;
    let mut findings = normalize_taint_iris_findings(raw, &target, options.max_findings)?;
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SourceSinkLinked)?;
    }
    let persisted = persist_taint_iris_findings(&target, &findings, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "hunt",
                format!("taint-iris:hunt complete · {} findings", findings.len()),
            )
            .emit();
    }

    Ok(taint_iris_report(&target, cwes, findings, persisted, None))
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

pub(in crate::modules) fn require_taint_iris_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.context(
        "taint-iris:hunt requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

pub(in crate::modules) fn require_taint_iris_model(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    optional_nonempty_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context(
            "taint-iris:hunt requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
        )
}

pub(in crate::modules) fn selected_taint_iris_cwes(
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

pub(in crate::modules) fn empty_taint_iris_report(
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

pub(in crate::modules) fn query_taint_iris_agent(
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
        .with_tool_policy(agent_tool_policy_for_input(input)?),
        StructuredJsonContract::new(
            "taint-iris:hunt",
            "TaintIrisFindings",
            findings_array_schema(),
        ),
        require_json_object,
    )
}
