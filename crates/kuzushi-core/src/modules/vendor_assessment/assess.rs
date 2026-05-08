use super::*;

pub(in crate::modules) fn assess(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let root = root(&input, ctx)?;
    let scope = merge_scope_inputs(load_scope(&root)?, &input);
    save_scope(&root, &scope)?;
    let run_id = format!("va-{}", unix_millis());
    let run_root = runs_dir(&root).join(&run_id);
    let prompts_dir = run_root.join("prompts");
    fs::create_dir_all(&prompts_dir)
        .with_context(|| format!("Could not create {}", prompts_dir.display()))?;
    let prompts = build_prompt_bundle(&scope);
    for (filename, content) in &prompts {
        fs::write(prompts_dir.join(filename), format!("{content}\n"))?;
    }
    let has_text = scope_has_text(&scope);
    let mut report = build_fallback_report(&run_id, &scope, &run_root, has_text);
    let mut cost_usd = 0.0;
    if has_text {
        let runtime = runtime.context(
            "vendor-assessment:assess with parsed documents requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
        )?;
        let model = resolve_tool_model("vendor-assessment:assess", &input, ctx)?;
        let raw = query_required_structured_json(
            runtime,
            AgentQueryRequest::new(
                model,
                root.clone(),
                "You are Kuzushi's vendor security assessment agent. Return only JSON with overallRisk, confidence, summary, domains, mitigations, and documents.".to_string(),
                prompts
                    .iter()
                    .map(|(_, content)| content.as_str())
                    .collect::<Vec<_>>()
                    .join("\n\n"),
            ),
            StructuredJsonContract::new(
                "vendor-assessment:assess",
                "VendorAssessmentReport",
                vendor_assessment_schema(),
            ),
            require_json_object,
        )?;
        let Value::Object(object) = raw else {
            unreachable!("require_json_object returned non-object");
        };
        merge_report_object(&mut report, object);
        cost_usd = 0.0;
    }
    let report_md = render_report_markdown(&report);
    let scope_path = run_root.join("scope.json");
    let report_path = run_root.join("report.md");
    let report_json_path = run_root.join("report.json");
    fs::write(
        &scope_path,
        format!("{}\n", serde_json::to_string_pretty(&scope)?),
    )?;
    fs::write(&report_path, format!("{report_md}\n"))?;
    fs::write(
        &report_json_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "Vendor assessment complete ({}, {}).\nReport: {}\nJSON:   {}\nScope:  {}\nPrompts: {}",
            report.get("overallRisk").and_then(Value::as_str).unwrap_or("needs-review"),
            report.get("confidence").and_then(Value::as_str).unwrap_or("low"),
            report_path.display(),
            report_json_path.display(),
            scope_path.display(),
            prompts_dir.display(),
        ),
        "data": {
            "runId": run_id,
            "report": report,
            "scope": scope,
            "artifacts": {
                "scopePath": scope_path.display().to_string(),
                "reportPath": report_path.display().to_string(),
                "reportJsonPath": report_json_path.display().to_string(),
                "promptsDir": prompts_dir.display().to_string(),
            },
        },
        "costUsd": cost_usd,
    }))
}

pub(in crate::modules) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("vendor-assessment structured output must be a JSON object")
    }
}

pub(in crate::modules) fn vendor_assessment_schema() -> Value {
    json!({
        "type": "object",
        "required": ["overallRisk", "confidence", "summary"],
        "additionalProperties": true,
        "properties": {
            "overallRisk": {"type": "string"},
            "confidence": {"type": "string"},
            "summary": {"type": "string"},
            "domains": {"type": "array", "items": {"type": "object"}},
            "mitigations": {"type": "array", "items": {"type": "object"}},
            "documents": {"type": "array", "items": {"type": "object"}}
        }
    })
}
