use super::*;

pub fn run_variant_hunt(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let fingerprint = match input.get("fingerprint").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            return Ok(json!({
                "ok": false,
                "output": "variant:hunt requires a fingerprint.",
            }))
        }
    };
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "hunt",
                format!("variant:hunt start · fp={fingerprint}"),
            )
            .emit();
    }
    let target = resolve_tool_target(&input, ctx)?;
    let workspace = ctx.workspace.context(
        "variant:hunt needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("variant:hunt requires the active workspace findings store")?;
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
    if let Some(response) = variant_hunt_subject_rejection(&fingerprint, &finding) {
        return Ok(response);
    }
    let runtime = require_runtime("variant:hunt", runtime)?;
    let model = require_model("variant:hunt", &input, ctx)?;
    let max_findings = positive_usize_input(&input, "maxFindings", 10, 50);
    let thinking_level = agentic_hunter_thinking_level(&input);
    let include_vendored = input
        .get("includeVendored")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let vendor_paths = vendor_paths_from_input(&input);
    let prompt = build_variant_hunt_prompt(&finding, include_vendored, &vendor_paths);
    // Phase scope so the LLM call indents under `hunt-variants` in the feed.
    let _llm_scope = ctx.trace.map(|trace| {
        let phase = trace.step("reasoning", "hunt", "hunt-variants").emit();
        trace.parent_scope(phase)
    });
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.clone(),
            VARIANT_HUNT_SYSTEM_PROMPT.to_string(),
            prompt,
        )
        .with_tool_policy(default_whitebox_static_agent_tool_policy())
        .with_thinking_level(thinking_level),
        StructuredJsonContract::new("variant:hunt", "VariantFindings", findings_schema()),
        require_json_object,
    )?;
    drop(_llm_scope);
    let repo_name = repo_name(&target);
    let findings = normalize_variant_findings(raw, &target, &repo_name, &finding, max_findings)?;
    let persisted = persist_findings(&target, &findings, ctx)?;
    let output = render_variant_hunt_output(
        &finding,
        findings.len(),
        include_vendored,
        findings.as_slice(),
    );
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "hunt",
                format!("variant:hunt complete · {} variants", findings.len()),
            )
            .emit();
    }

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "fingerprint": fingerprint,
            "originalFinding": finding,
            "variants": findings,
            "scope": {
                "includeVendored": include_vendored,
                "vendorPaths": if include_vendored { vendor_paths } else { Vec::<String>::new() },
            },
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

fn variant_hunt_subject_rejection(fingerprint: &str, finding: &Finding) -> Option<Value> {
    let Some(triage) = finding.triage.as_ref() else {
        return Some(json!({
            "ok": false,
            "output": format!(
                "variant:hunt expects a confirmed TP; finding \"{}\" has no triage verdict. Run triage:run first.",
                fingerprint
            ),
        }));
    };
    (triage.verdict != TriageVerdict::TruePositive).then(|| {
        json!({
            "ok": false,
            "output": format!(
                "variant:hunt expects a confirmed TP; finding \"{}\" has verdict \"{}\".",
                fingerprint,
                triage.verdict.as_str()
            ),
        })
    })
}
