use super::*;

pub fn run_ndiff_fetch_cve(input: Value) -> Result<Value> {
    let id = match input.get("id").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            return Ok(json!({
                "ok": false,
                "output": "ndiff:fetch-cve requires an `id`.",
            }))
        }
    };
    match fetch_cve_or_advisory(&id, &input) {
        Ok(Some(record)) => {
            let primary_patch_url = choose_primary_patch_url(&record);
            Ok(json!({
                "ok": true,
                "output": format_cve_summary(&record),
                "data": {
                    "record": record,
                    "primaryPatchUrl": primary_patch_url,
                },
            }))
        }
        Ok(None) => Ok(json!({
            "ok": false,
            "output": format!(
                "No advisory found for \"{}\" (offline={}).",
                id,
                input.get("offline").and_then(Value::as_bool).unwrap_or(false)
            ),
        })),
        Err(error) => Ok(json!({
            "ok": false,
            "output": format!("ndiff:fetch-cve error: {error:#}"),
        })),
    }
}

pub fn run_ndiff_extract_fix_pattern(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let source = match resolve_ndiff_fix_pattern_source(&input)? {
        NdiffFixPatternSourceResolution::Ready(source) => source,
        NdiffFixPatternSourceResolution::Rejected(response) => return Ok(response),
    };
    let runtime = require_runtime("ndiff:extract-fix-pattern", runtime)?;
    let model = require_model("ndiff:extract-fix-pattern", &input, ctx)?;
    let target = resolve_tool_target(&input, ctx)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let prompt = build_ndiff_fix_pattern_prompt(source.record.as_ref(), &source.patch_text);
    let pattern = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target,
            NDIFF_FIX_PATTERN_SYSTEM_PROMPT.to_string(),
            prompt,
        ),
        StructuredJsonContract::new(
            "ndiff:extract-fix-pattern",
            "NdiffFixPattern",
            object_schema(),
        ),
        require_json_object,
    )?;
    ndiff_fix_pattern_response(source, pattern)
}
