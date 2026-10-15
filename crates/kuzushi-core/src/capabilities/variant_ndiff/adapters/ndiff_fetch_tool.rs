use super::*;

pub fn run_ndiff_fetch_cve(input: Value) -> Result<Value> {
    let Some(id) = ndiff_fetch_id(&input) else {
        return Ok(missing_ndiff_fetch_id_response());
    };
    match fetch_cve_or_advisory(&id, &input) {
        Ok(Some(record)) => Ok(ndiff_fetch_success_response(
            record,
            &id,
            advisory_retrieval_mode(&id, &input),
        )),
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

fn ndiff_fetch_success_response(record: CveRecord, requested_id: &str, mode: &str) -> Value {
    let primary_patch_url = choose_primary_patch_url(&record);
    let supplied = mode != "network";
    let output = if supplied {
        format!(
            "Supplied metadata; source not verified.\n{}",
            format_cve_summary(&record)
        )
    } else {
        format_cve_summary(&record)
    };
    let summary = format!(
        "{} · {}",
        if supplied {
            "Unverified supplied metadata"
        } else {
            "Retrieved advisory metadata"
        },
        record.id
    );
    let data = json!({
        "record": record,
        "primaryPatchUrl": primary_patch_url,
        "retrieval": {"requestedId":requested_id,"mode":mode,"sourceVerified":false,"metadataOnly":true},
    });
    crate::module_result::completed_output_result(summary, output, data)
}

fn missing_ndiff_advisory_response(id: &str, input: &Value) -> Value {
    let output = format!(
        "No advisory found for \"{}\" (offline={}).",
        id,
        input
            .get("offline")
            .and_then(Value::as_bool)
            .unwrap_or(false)
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
    ctx.ensure_active()?;
    emit_ndiff_extract_step(ctx, "tool", "ndiff:extract-fix-pattern start");
    let target = resolve_tool_target(&input, ctx)?;
    let source = match resolve_ndiff_source_for_target(&input, &target)? {
        NdiffFixPatternSourceResolution::Ready(source) => source,
        NdiffFixPatternSourceResolution::Rejected(response) => return Ok(response),
    };
    ctx.ensure_active()?;
    let pattern = query_ndiff_fix_pattern(&input, ctx, runtime, &source)?;
    ctx.ensure_active()?;
    let cost = pattern.cost_report()?;
    let response = ndiff_fix_pattern_response(source, pattern.value, cost);
    emit_ndiff_extract_step(ctx, "done", "ndiff:extract-fix-pattern complete");
    response
}

fn query_ndiff_fix_pattern(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    source: &NdiffFixPatternSource,
) -> Result<CostedStructuredJson<Value>> {
    let runtime = require_runtime("ndiff:extract-fix-pattern", runtime)?;
    let model = require_model("ndiff:extract-fix-pattern", input, ctx)?;
    let target = resolve_tool_target(input, ctx)?;
    let thinking_level = optional_variant_reasoning(input);
    let prompt = build_ndiff_fix_pattern_prompt(
        source.record.as_ref(),
        &source.patch_text,
        source.max_source_bytes,
    );
    let limit = ndiff_query_limit(input, "maxContextBytes", 65536, 1024..=512 * 1024)?;
    anyhow::ensure!(prompt.len() <= limit, "Advisory-pattern prompt exceeds maxContextBytes; narrow inputs or approve a larger declared bound");
    let _llm_scope = begin_ndiff_extract_scope(ctx);
    query_required_structured_json_with_cost(
        runtime,
        ndiff_fix_pattern_request(model, target, prompt, thinking_level.as_deref(), input)?,
        StructuredJsonContract::new(
            "ndiff:extract-fix-pattern",
            "NdiffFixPattern",
            ndiff_pattern_schema(),
        ),
        validate_ndiff_pattern_output,
    )
}

fn ndiff_fix_pattern_request(
    model: String,
    target: PathBuf,
    prompt: String,
    thinking_level: Option<&str>,
    input: &Value,
) -> Result<AgentQueryRequest> {
    let request = AgentQueryRequest::new(
        model,
        target,
        NDIFF_FIX_PATTERN_SYSTEM_PROMPT.to_string(),
        prompt,
    )
    .with_tool_policy(crate::runtime::AgentToolPolicy::new(
        "advisory-pattern-draft",
        std::iter::empty::<&str>(),
    ))
    .with_max_output_tokens(u32::try_from(ndiff_query_limit(
        input,
        "maxOutputTokens",
        4096,
        256..=32768,
    )?)?)
    .with_max_model_turns(Some(u32::try_from(ndiff_query_limit(
        input,
        "maxModelTurns",
        1,
        1..=4,
    )?)?));
    Ok(match thinking_level {
        Some(level) => request.with_thinking_level(level),
        None => request,
    })
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
