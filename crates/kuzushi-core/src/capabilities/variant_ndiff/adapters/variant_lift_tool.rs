use super::*;

pub fn run_variant_lift_pattern(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let fingerprint = match input.get("fingerprint").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            return Ok(json!({
                "ok": false,
                "output": "variant:lift-pattern requires a fingerprint.",
            }))
        }
    };
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "lift-pattern",
                format!("variant:lift-pattern start · fp={fingerprint}"),
            )
            .emit();
    }
    let workspace = ctx.workspace.context(
        "variant:lift-pattern needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("variant:lift-pattern requires the active workspace findings store")?;
    let Some(finding) = store.get_finding_by_reference(&fingerprint)? else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "No finding with fingerprint \"{}\" in {}.",
                fingerprint,
                workspace.findings_db_path().display()
            ),
        }));
    };
    let runtime = require_runtime("variant:lift-pattern", runtime)?;
    let model = require_model("variant:lift-pattern", &input, ctx)?;
    let thinking_level = agentic_hunter_thinking_level(&input);
    let prompt = build_variant_lift_prompt(&finding);
    // Phase scope so the LLM call indents under `lift-pattern` in the feed.
    let _llm_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "lift-pattern", "lift-pattern")
            .emit();
        trace.parent_scope(phase)
    });
    let signature = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            workspace.root().to_path_buf(),
            VARIANT_SIGNATURE_SYSTEM_PROMPT.to_string(),
            prompt,
        )
        .with_tool_policy(default_whitebox_static_agent_tool_policy())
        .with_thinking_level(thinking_level),
        StructuredJsonContract::new("variant:lift-pattern", "VariantSignature", object_schema()),
        require_json_object,
    )?;
    drop(_llm_scope);
    let object = signature
        .as_object()
        .context("variant:lift-pattern output parse failed: expected a JSON object")?;
    let output = [
        format!(
            "Variant signature for {} ({}:{}):",
            finding.rule_id, finding.file_path, finding.start_line
        ),
        format!(
            "  Source:        {}",
            read_object_string(object, &["source"]).unwrap_or_default()
        ),
        format!(
            "  Sink:          {}",
            read_object_string(object, &["sink"]).unwrap_or_default()
        ),
        format!(
            "  Missing guard: {}",
            read_object_string(object, &["missingGuard", "missing_guard"]).unwrap_or_default()
        ),
        format!(
            "  Languages:     {}",
            read_object_string_array(object, &["languages"]).join(", ")
        ),
        format!(
            "  Keywords:      {}",
            read_object_string_array(object, &["keywords"]).join(", ")
        ),
        String::new(),
        read_object_string(object, &["description"]).unwrap_or_default(),
    ]
    .join("\n");

    if let Some(trace) = ctx.trace {
        let _ = trace
            .step("done", "lift-pattern", "variant:lift-pattern complete")
            .emit();
    }
    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "fingerprint": fingerprint,
            "signature": signature,
            "finding": finding,
        },
        "costUsd": 0.0,
    }))
}
