use super::*;

pub(crate) fn ndiff_fix_pattern_output(object: &Map<String, Value>) -> String {
    [
        format!(
            "Fix shape:         {}",
            read_object_string(object, &["fixShape", "fix_shape"]).unwrap_or_default()
        ),
        format!(
            "Vulnerable shape:  {}",
            read_object_string(object, &["vulnerableShape", "vulnerable_shape"])
                .unwrap_or_default()
        ),
        format!(
            "CWEs:              {}",
            read_object_string_array(object, &["cwe", "cwes"]).join(", ")
        ),
        format!(
            "Languages:         {}",
            read_object_string_array(object, &["languages"]).join(", ")
        ),
        format!(
            "Keywords:          {}",
            read_object_string_array(object, &["keywords"]).join(", ")
        ),
        format!(
            "Detection query:   {}",
            read_object_string(object, &["detectionQuery", "detection_query"]).unwrap_or_default()
        ),
        format!(
            "Confidence:        {}",
            read_object_string(object, &["confidence"]).unwrap_or_default()
        ),
        String::new(),
        read_object_string(object, &["description"]).unwrap_or_default(),
    ]
    .join("\n")
}

pub fn run_ndiff_hunt_variants(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step("tool", "hunt-variants", "ndiff:hunt-variants start")
            .emit();
    }
    let pattern = match input.get("pattern").and_then(Value::as_object) {
        Some(pattern) => pattern.clone(),
        None => {
            return Ok(json!({
                "ok": false,
                "output": "ndiff:hunt-variants requires a pattern object.",
            }))
        }
    };
    let target = resolve_tool_target(&input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "ndiff:hunt-variants target is not a directory: {}",
            target.display()
        );
    }
    let runtime = require_runtime("ndiff:hunt-variants", runtime)?;
    let model = require_model("ndiff:hunt-variants", &input, ctx)?;
    let max_findings = positive_usize_input(&input, "maxFindings", 15, 100);
    let thinking_level = agentic_hunter_thinking_level(&input);
    let include_vendored = input
        .get("includeVendored")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let advisory_id = input
        .get("advisoryId")
        .or_else(|| input.get("advisory_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let prompt = build_ndiff_hunt_prompt(&pattern, &advisory_id, include_vendored);
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.clone(),
            NDIFF_HUNT_SYSTEM_PROMPT.to_string(),
            prompt,
        )
        .with_tool_policy(default_whitebox_static_agent_tool_policy())
        .with_thinking_level(thinking_level),
        StructuredJsonContract::new(
            "ndiff:hunt-variants",
            "NdiffVariantFindings",
            findings_schema(),
        ),
        require_json_object,
    )?;
    let repo_name = repo_name(&target);
    let findings = normalize_ndiff_findings(raw, &repo_name, &advisory_id, &pattern, max_findings)?;
    let persisted = persist_findings(&target, &findings, ctx)?;
    let output =
        render_ndiff_hunt_output(&advisory_id, findings.len(), include_vendored, &findings);
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "hunt-variants",
                format!("ndiff:hunt-variants complete · {} variants", findings.len()),
            )
            .emit();
    }

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "advisoryId": advisory_id,
            "pattern": pattern,
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}
