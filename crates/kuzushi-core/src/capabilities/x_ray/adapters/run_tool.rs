use super::*;

pub(crate) fn run_x_ray(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let runtime = runtime.context(
        "x-ray:run requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let input = parse_run_input(&input, ctx)?;
    let parent_step = emit_x_ray_start(ctx, &input);
    emit_x_ray_progress(ctx, parent_step, "prompt · build repository x-ray request");
    let prompt = build_x_ray_prompt(&input);
    let _agent_scope = begin_x_ray_agent_scope(ctx, parent_step);
    // The x-ray prompt embeds the whole inventory it reasons over, so an
    // unchanged repository replays the understanding pass for free.
    let cache = crate::semantic_cache::SemanticCache::open_for_target(&input.target);
    let content = crate::structured_output::query_cached_structured_json_with_cost(
        cache.as_ref(),
        runtime,
        x_ray_agent_request(&input, prompt),
        StructuredJsonContract::new("x-ray:run", "XRayArtifactContent", x_ray_artifact_schema()),
        XRayArtifactContent::from_value_owned,
    )?
    .costed;
    drop(_agent_scope);
    let cost = content.cost_report()?;
    finish_x_ray_run(&input, ctx, parent_step, content.value, cost)
}

fn x_ray_agent_request(input: &XRayRunInput, prompt: String) -> AgentQueryRequest {
    let request = AgentQueryRequest::new(
        input.model.clone(),
        input.target.clone(),
        input.system_prompt.clone(),
        prompt,
    );
    let Some(stop_usd) = input.max_budget_usd else {
        return request;
    };
    request.with_runtime_options(crate::runtime::AgentRuntimeOptions {
        observed_spend_stop_usd: Some(stop_usd),
        ..Default::default()
    })
}

pub(crate) fn read_x_ray(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_target(&input, ctx)?;
    let repo_name = repo_name(&target);
    let data = read_x_ray_report_artifacts(&target, Some(&repo_name), "rust", 0.0)?;
    x_ray_response(
        render_x_ray_read_summary(&data),
        json!(data),
        &data,
        crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
    )
}

fn x_ray_response(
    output: String,
    data: Value,
    report: &XRayReportData,
    cost: crate::runtime::RuntimeCostReport,
) -> Result<Value> {
    let mut result =
        crate::module_result::completed_output_result(output.clone(), output, data);
    result["artifacts"] = json!([
        { "label": "x-ray", "path": report.artifact_paths.x_ray },
        { "label": "entry points", "path": report.artifact_paths.entry_points },
        { "label": "invariants", "path": report.artifact_paths.invariants },
        { "label": "architecture", "path": report.artifact_paths.architecture_svg },
    ]);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

fn finish_x_ray_run(
    input: &XRayRunInput,
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    content: XRayArtifactContent,
    cost: crate::runtime::RuntimeCostReport,
) -> Result<Value> {
    emit_x_ray_progress(ctx, parent_step, "artifacts · write x-ray report");
    write_x_ray_artifacts(&input.target, content)?;
    let data = read_x_ray_report_artifacts(
        &input.target,
        Some(&input.repo_name),
        "LangGraph",
        cost.observed_usd(),
    )?;
    let mut data = data;
    data.cost_usd_exact = cost.is_complete();
    data.estimated_cost_usd = cost
        .is_estimated()
        .then(|| cost.estimated_total_usd())
        .flatten();
    emit_x_ray_done(ctx);
    let mut data_json = json!(data);
    data_json["kbContext"] = json!(&input.kb_context);
    x_ray_response(render_x_ray_run_summary(&data), data_json, &data, cost)
}

fn emit_x_ray_start(ctx: &ToolExecutionContext<'_>, input: &XRayRunInput) -> Option<crate::run_lifecycle::RunItemId> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "run",
                format!("x-ray:run start · target={}", input.target.display()),
            )
            .emit()
    })
}

fn emit_x_ray_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };
    let _ = trace.child(parent).step("tool-progress", "run", label.into()).emit();
}

fn begin_x_ray_agent_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };
    let phase = trace
        .child(parent)
        .step("reasoning", "run", "inventory · agent-pass")
        .emit();
    Some(trace.parent_scope(phase))
}

fn emit_x_ray_done(ctx: &ToolExecutionContext<'_>) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "run", "x-ray:run complete").emit();
    }
}
