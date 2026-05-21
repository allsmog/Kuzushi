use super::*;

pub fn run_ndiff_fetch_cve(input: Value) -> Result<Value> {
    let Some(id) = ndiff_fetch_id(&input) else {
        return Ok(missing_ndiff_fetch_id_response());
    };
    match fetch_cve_or_advisory(&id, &input) {
        Ok(Some(record)) => Ok(ndiff_fetch_success_response(record)),
        Ok(None) => Ok(missing_ndiff_advisory_response(&id, &input)),
        Err(error) => Ok(ndiff_fetch_error_response(&id, error)),
    }
}

fn ndiff_fetch_id(input: &Value) -> Option<String> {
    input
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn missing_ndiff_fetch_id_response() -> Value {
    crate::module_result::failed_output_result(
        "ndiff:fetch-cve rejected input",
        "ndiff:fetch-cve requires an `id`.",
        json!({ "reason": "missing-id" }),
    )
}

fn ndiff_fetch_success_response(record: CveRecord) -> Value {
    let primary_patch_url = choose_primary_patch_url(&record);
    let output = format_cve_summary(&record);
    let data = json!({
        "record": record,
        "primaryPatchUrl": primary_patch_url,
    });
    crate::module_result::completed_output_result(output.clone(), output, data)
}

fn missing_ndiff_advisory_response(id: &str, input: &Value) -> Value {
    let output = format!(
        "No advisory found for \"{}\" (offline={}).",
        id,
        input.get("offline").and_then(Value::as_bool).unwrap_or(false)
    );
    crate::module_result::failed_output_result(
        "ndiff:fetch-cve advisory not found",
        output,
        json!({ "id": id, "reason": "not-found" }),
    )
}

fn ndiff_fetch_error_response(id: &str, error: anyhow::Error) -> Value {
    let output = format!("ndiff:fetch-cve error: {error:#}");
    crate::module_result::failed_output_result(
        "ndiff:fetch-cve failed",
        output,
        json!({ "id": id, "reason": "fetch-error" }),
    )
}

pub fn run_ndiff_extract_fix_pattern(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    emit_ndiff_extract_step(ctx, "tool", "ndiff:extract-fix-pattern start");
    let source = match resolve_ndiff_fix_pattern_source(&input)? {
        NdiffFixPatternSourceResolution::Ready(source) => source,
        NdiffFixPatternSourceResolution::Rejected(response) => return Ok(response),
    };
    let pattern = query_ndiff_fix_pattern(&input, ctx, runtime, &source)?;
    let response = ndiff_fix_pattern_response(source, pattern);
    emit_ndiff_extract_step(ctx, "done", "ndiff:extract-fix-pattern complete");
    response
}

fn query_ndiff_fix_pattern(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    source: &NdiffFixPatternSource,
) -> Result<Value> {
    let runtime = require_runtime("ndiff:extract-fix-pattern", runtime)?;
    let model = require_model("ndiff:extract-fix-pattern", input, ctx)?;
    let target = resolve_tool_target(input, ctx)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let thinking_level = agentic_hunter_thinking_level(input);
    let prompt = build_ndiff_fix_pattern_prompt(source.record.as_ref(), &source.patch_text);
    let _llm_scope = begin_ndiff_extract_scope(ctx);
    query_required_structured_json(
        runtime,
        ndiff_fix_pattern_request(model, target, prompt, thinking_level),
        StructuredJsonContract::new(
            "ndiff:extract-fix-pattern",
            "NdiffFixPattern",
            object_schema(),
        ),
        require_json_object,
    )
}

fn ndiff_fix_pattern_request(
    model: String,
    target: PathBuf,
    prompt: String,
    thinking_level: String,
) -> AgentQueryRequest {
    AgentQueryRequest::new(
        model,
        target,
        NDIFF_FIX_PATTERN_SYSTEM_PROMPT.to_string(),
        prompt,
    )
    .with_tool_policy(default_whitebox_static_agent_tool_policy())
    .with_thinking_level(thinking_level)
}

fn begin_ndiff_extract_scope(
    ctx: &ToolExecutionContext<'_>,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "extract-fix-pattern", "extract-fix-pattern")
            .emit();
        trace.parent_scope(phase)
    })
}

fn emit_ndiff_extract_step(ctx: &ToolExecutionContext<'_>, kind: &str, label: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(kind, "extract-fix-pattern", label.to_string())
            .emit();
    }
}
