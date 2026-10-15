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
    ctx.ensure_active()?;
    emit_ndiff_hunt_step(ctx, "tool", "ndiff:hunt-variants start", None);
    let prepared = match prepare_ndiff_hunt(&input, ctx, runtime)? {
        Some(prepared) => prepared,
        None => return Ok(missing_ndiff_hunt_pattern_response()),
    };
    crate::workspace::source_snapshot::run_source_bound_tool(
        ctx,
        "ndiff:hunt-variants",
        &prepared.target,
        || execute_ndiff_hunt(&prepared, ctx),
    )
}

fn execute_ndiff_hunt(
    prepared: &NdiffHuntRun<'_>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let raw = query_ndiff_hunt_json(prepared)?;
    let cost = raw.cost_report()?;
    let repo_name = repo_name(&prepared.target);
    let findings = normalize_ndiff_findings(
        raw.value,
        &repo_name,
        &prepared.advisory_id,
        &prepared.pattern,
        prepared.max_findings,
    )?;
    ctx.ensure_active()?;
    let persisted = persist_findings(&prepared.target, &findings, ctx)?;
    emit_ndiff_hunt_step(
        ctx,
        "done",
        "ndiff:hunt-variants complete",
        Some(findings.len()),
    );
    Ok(ndiff_hunt_response(prepared, findings, persisted, cost))
}

struct NdiffHuntRun<'a> {
    pattern: Map<String, Value>,
    target: PathBuf,
    runtime: &'a dyn AgentRuntime,
    model: String,
    max_findings: usize,
    thinking_level: Option<String>,
    max_output_tokens: u32,
    max_model_turns: u32,
    include_vendored: bool,
    advisory_id: String,
}

fn prepare_ndiff_hunt<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<Option<NdiffHuntRun<'a>>> {
    let Some(pattern) = input.get("pattern").and_then(Value::as_object) else {
        return Ok(None);
    };
    validate_ndiff_pattern(pattern)?;
    let target = checked_ndiff_hunt_target(input, ctx)?;
    Ok(Some(NdiffHuntRun {
        pattern: pattern.clone(),
        target,
        runtime: require_runtime("ndiff:hunt-variants", runtime)?,
        model: require_model("ndiff:hunt-variants", input, ctx)?,
        max_findings: ndiff_query_limit(input, "maxFindings", 15, 1..=100)?,
        thinking_level: optional_variant_reasoning(input),
        max_output_tokens: u32::try_from(ndiff_query_limit(
            input,
            "maxOutputTokens",
            4096,
            256..=32768,
        )?)?,
        max_model_turns: u32::try_from(ndiff_query_limit(input, "maxModelTurns", 4, 1..=16)?)?,
        include_vendored: ndiff_hunt_include_vendored(input),
        advisory_id: ndiff_hunt_advisory_id(input),
    }))
}

fn missing_ndiff_hunt_pattern_response() -> Value {
    crate::module_result::failed_output_result(
        "ndiff:hunt-variants rejected input",
        "ndiff:hunt-variants requires a pattern object.",
        json!({ "reason": "missing-pattern" }),
    )
}

fn checked_ndiff_hunt_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let target = resolve_tool_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "ndiff:hunt-variants target is not a directory: {}",
            target.display()
        );
    }
    Ok(target)
}

fn ndiff_hunt_include_vendored(input: &Value) -> bool {
    input
        .get("includeVendored")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

fn ndiff_hunt_advisory_id(input: &Value) -> String {
    input
        .get("advisoryId")
        .or_else(|| input.get("advisory_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn query_ndiff_hunt_json(run: &NdiffHuntRun<'_>) -> Result<CostedStructuredJson<Value>> {
    let prompt = build_ndiff_hunt_prompt(&run.pattern, &run.advisory_id, run.include_vendored);
    query_required_structured_json_with_cost(
        run.runtime,
        ndiff_hunt_request(run, prompt)?,
        StructuredJsonContract::new(
            "ndiff:hunt-variants",
            "NdiffVariantFindings",
            findings_schema(),
        ),
        validate_variant_observations,
    )
}

fn ndiff_hunt_request(run: &NdiffHuntRun<'_>, prompt: String) -> Result<AgentQueryRequest> {
    let request = AgentQueryRequest::new(
        run.model.clone(),
        run.target.clone(),
        NDIFF_HUNT_SYSTEM_PROMPT.to_string(),
        prompt,
    )
    .with_tool_policy(try_whitebox_static_policy_for_target(&run.target)?)
    .with_max_output_tokens(run.max_output_tokens)
    .with_max_model_turns(Some(run.max_model_turns));
    Ok(match &run.thinking_level {
        Some(level) => request.with_thinking_level(level),
        None => request,
    })
}

fn ndiff_hunt_response(
    run: &NdiffHuntRun<'_>,
    findings: Vec<Finding>,
    persisted: Option<PersistedRun>,
    cost: crate::runtime::RuntimeCostReport,
) -> Value {
    let output = render_ndiff_hunt_output(
        &run.advisory_id,
        findings.len(),
        run.include_vendored,
        &findings,
        cost,
    );
    let summary = format!(
        "Advisory-guided observations: {} finding{}; partial coverage, independent review required.",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );
    let data = json!({
        "advisoryId": run.advisory_id,
        "pattern": run.pattern,
        "findings": findings,
        "persisted": persisted,
        "coverage": {"complete":false},
        "observationsVerified": false,
        "candidateLocationsVerified": false,
        "patternAccepted": false,
    });
    let mut result = crate::module_result::partial_output_result(
        summary,
        output,
        vec![
            json!({"code":"partial-advisory-observations","message":"Advisory and source-location claims require independent review. Pattern and vendor guidance do not establish enforced discovery scope or complete coverage. An empty response does not resolve existing findings."}),
        ],
        data,
    );
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    result
}

fn emit_ndiff_hunt_step(
    ctx: &ToolExecutionContext<'_>,
    kind: &str,
    label: &str,
    findings: Option<usize>,
) {
    if let Some(trace) = ctx.trace {
        let rendered = match findings {
            Some(count) => format!("{label} · {count} variants"),
            None => label.to_string(),
        };
        let _ = trace.step(kind, "hunt-variants", rendered).emit();
    }
}
