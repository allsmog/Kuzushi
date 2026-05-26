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
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "run",
                format!("x-ray:run start · target={}", input.target.display()),
            )
            .emit();
    }
    let prompt = build_x_ray_prompt(&input);
    let _agent_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "run", "inventory · agent-pass")
            .emit();
        trace.parent_scope(phase)
    });
    let content = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            input.model.clone(),
            input.target.clone(),
            X_RAY_SYSTEM_PROMPT.to_string(),
            prompt,
        ),
        StructuredJsonContract::new("x-ray:run", "XRayArtifactContent", x_ray_artifact_schema()),
        XRayArtifactContent::from_value_owned,
    )?;
    drop(_agent_scope);
    finish_x_ray_run(&input, ctx, content)
}

pub(crate) fn read_x_ray(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_target(&input, ctx)?;
    let repo_name = repo_name(&target);
    let data = read_x_ray_report_artifacts(&target, Some(&repo_name), "rust", 0.0)?;
    Ok(x_ray_response(
        render_x_ray_read_summary(&data),
        json!(data),
        &data,
    ))
}

fn x_ray_response(output: String, data: Value, report: &XRayReportData) -> Value {
    let mut result =
        crate::module_result::completed_output_result(output.clone(), output, data);
    result["artifacts"] = json!([
        { "label": "x-ray", "path": report.artifact_paths.x_ray },
        { "label": "entry points", "path": report.artifact_paths.entry_points },
        { "label": "invariants", "path": report.artifact_paths.invariants },
        { "label": "architecture", "path": report.artifact_paths.architecture_svg },
    ]);
    result["costUsd"] = json!(report.cost_usd);
    result
}

fn finish_x_ray_run(
    input: &XRayRunInput,
    ctx: &ToolExecutionContext<'_>,
    content: XRayArtifactContent,
) -> Result<Value> {
    write_x_ray_artifacts(&input.target, content)?;
    let data =
        read_x_ray_report_artifacts(&input.target, Some(&input.repo_name), "LangGraph", 0.0)?;
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "run", "x-ray:run complete").emit();
    }
    let mut data_json = json!(data);
    data_json["kbContext"] = json!(&input.kb_context);
    Ok(x_ray_response(render_x_ray_run_summary(&data), data_json, &data))
}
