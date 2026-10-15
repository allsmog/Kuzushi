use super::*;

pub(crate) fn run_x_ray(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let runtime = runtime.context(
        "x-ray:run requires the selected agent runtime. Review runtime and model configuration before starting generation.",
    )?;
    let input = parse_run_input(&input, ctx)?;
    let parent_step = emit_x_ray_start(ctx, &input);
    emit_x_ray_progress(ctx, parent_step, "prompt · build repository x-ray request");
    let prompt = build_x_ray_prompt(&input);
    let _agent_scope = begin_x_ray_agent_scope(ctx, parent_step);
    // The shared cache decides whether a prior structured response can be reused.
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
    ctx.ensure_active()?;
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
    let request = match input.effort.as_deref() {
        Some(effort) => request.with_thinking_level(effort),
        None => request,
    };
    let Some(stop_usd) = input.max_budget_usd else {
        return request;
    };
    request.with_runtime_options(crate::runtime::AgentRuntimeOptions {
        observed_spend_stop_usd: Some(stop_usd),
        ..Default::default()
    })
}

pub(super) fn x_ray_response(
    output: String,
    data: Value,
    report: &XRayReportData,
    cost: crate::runtime::RuntimeCostReport,
) -> Result<Value> {
    let mut result = crate::module_result::completed_output_result(output.clone(), output, data);
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
        "agent-runtime",
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
    let mut output = x_ray_response(render_x_ray_run_summary(&data), data_json, &data, cost)?;
    output["warnings"] = json!(["Experimental report generation. Source coverage and report claims are unverified. These reports do not accept Map or establish finding decisions."]);
    Ok(output)
}

fn emit_x_ray_start(
    ctx: &ToolExecutionContext<'_>,
    input: &XRayRunInput,
) -> Option<crate::run_lifecycle::RunItemId> {
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
    let _ = trace
        .child(parent)
        .step("tool-progress", "run", label.into())
        .emit();
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
