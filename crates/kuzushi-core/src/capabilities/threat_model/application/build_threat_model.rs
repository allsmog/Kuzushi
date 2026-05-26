use super::*;

pub(crate) fn build_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<Value> {
    if should_build_deterministically(&input, ctx, runtime) {
        return build_deterministic_threat_model(input, ctx, flavor);
    }
    let runtime = runtime.expect("deterministic path handles missing runtime");
    let input = parse_build_input(&input, ctx, flavor)?;
    let verb = threat_model_build_verb(flavor);
    emit_threat_model_start(ctx, verb, flavor, &input);
    let mut generated = generate_threat_model_document(runtime, ctx, flavor, verb, &input)?;
    let artifacts = write_threat_model_outputs(flavor, &input, &generated.document)?;
    let findings = threat_model_findings(
        &input,
        generated.bridge_findings.take(),
        &generated.document,
    );
    let summary = threat_model_summary(&generated.document);
    let lines = threat_model_output_lines(
        flavor,
        &input,
        &summary,
        findings.len(),
        artifacts.persisted,
    );
    emit_threat_model_done(ctx, verb, flavor, &summary);
    Ok(threat_model_response(
        input, flavor, generated, artifacts, findings, summary, lines,
    ))
}

fn should_build_deterministically(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> bool {
    runtime.is_none() || (read_string(input, &["model"]).is_none() && ctx.config.model.is_none())
}

fn threat_model_build_verb(flavor: BuildFlavor) -> &'static str {
    match flavor {
        BuildFlavor::ThreatModel => "build",
        BuildFlavor::RandoriPasta => "pasta",
    }
}

fn emit_threat_model_start(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    flavor: BuildFlavor,
    input: &BuildInput,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                verb,
                format!(
                    "{} start · methodology={}",
                    flavor.tool_name(),
                    input.methodology
                ),
            )
            .emit();
    }
}

struct GeneratedThreatModel {
    document: Value,
    bridge_findings: Option<Vec<Value>>,
    cost_usd: f64,
}

fn generate_threat_model_document(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: &BuildInput,
) -> Result<GeneratedThreatModel> {
    let prompt = threat_model_prompt(input)?;
    let costed = query_threat_model_document(runtime, ctx, flavor, verb, input, prompt)?;
    let mut generated = normalize_threat_model_raw(costed.value, &input.methodology)?;
    generated.cost_usd = costed.cost_usd;
    Ok(generated)
}

fn threat_model_prompt(input: &BuildInput) -> Result<String> {
    let previous_model = load_persistent_threat_model(&input.target);
    build_agent_prompt(input, previous_model.as_ref())
}

fn query_threat_model_document(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: &BuildInput,
    prompt: String,
) -> Result<crate::structured_output::CostedStructuredJson<Value>> {
    let _llm_scope = begin_threat_model_llm_scope(ctx, verb);
    let costed = crate::structured_output::query_required_structured_json_with_cost(
        runtime,
        AgentQueryRequest::new(
            input.model.clone(),
            input.target.clone(),
            THREAT_MODEL_SYSTEM_PROMPT.to_string(),
            prompt,
        ),
        StructuredJsonContract::new(
            flavor.tool_name(),
            "ThreatModelDocument",
            threat_model_document_schema(),
        ),
        |raw| validate_threat_model_raw(raw, &input.methodology),
    )?;
    drop(_llm_scope);
    Ok(costed)
}

fn begin_threat_model_llm_scope(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
) -> Option<crate::run_artifacts::ParentScope> {
    // Phase scope so the threat-model agent's LLM round-trip surfaces under
    // dfd-collect / stride-classify / actor-stories rather than as a loose
    // top-level event.
    ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                verb,
                "dfd-collect · stride-classify · actor-stories",
            )
            .emit();
        trace.parent_scope(phase)
    })
}

fn validate_threat_model_raw(raw: Value, methodology: &str) -> Result<Value> {
    let (document_candidate, _) = extract_document_and_findings(raw.clone())?;
    normalize_document(document_candidate, methodology)?;
    Ok(raw)
}

fn normalize_threat_model_raw(raw: Value, methodology: &str) -> Result<GeneratedThreatModel> {
    let (document_candidate, bridge_findings) = extract_document_and_findings(raw)?;
    let document = normalize_document(document_candidate, methodology)?;
    let document = apply_methodology(document, methodology)?;
    Ok(GeneratedThreatModel {
        document,
        bridge_findings,
        cost_usd: 0.0,
    })
}

struct ThreatModelArtifacts {
    normalized_artifact: PathBuf,
    persisted: bool,
}

fn write_threat_model_outputs(
    flavor: BuildFlavor,
    input: &BuildInput,
    document: &Value,
) -> Result<ThreatModelArtifacts> {
    let normalized_artifact =
        write_normalized_artifact(&input.target, &input.output_dir, document)?;
    let persisted = persist_threat_model_document(flavor, input, document)?;
    Ok(ThreatModelArtifacts {
        normalized_artifact,
        persisted,
    })
}

fn persist_threat_model_document(
    flavor: BuildFlavor,
    input: &BuildInput,
    document: &Value,
) -> Result<bool> {
    if !flavor.persists_document() {
        return Ok(false);
    }
    save_persistent_threat_model(&input.target, document, !input.preserve_user_edits)
}

fn threat_model_findings(
    input: &BuildInput,
    bridge_findings: Option<Vec<Value>>,
    document: &Value,
) -> Vec<Value> {
    if input.emit_findings {
        build_findings_from_document(document)
    } else {
        bridge_findings.unwrap_or_default()
    }
}

fn threat_model_response(
    input: BuildInput,
    flavor: BuildFlavor,
    generated: GeneratedThreatModel,
    artifacts: ThreatModelArtifacts,
    findings: Vec<Value>,
    summary: ThreatModelSummary,
    mut lines: Vec<String>,
) -> Value {
    append_top_threats(&mut lines, &generated.document);
    let persistent_artifact = persistent_threat_model_path(&input.target);
    let artifact_items = threat_model_artifacts(
        &artifacts.normalized_artifact,
        &persistent_artifact,
        artifacts.persisted,
    );
    json!({
        "ok": summary.threat_count > 0 || summary.node_count > 0 || summary.flow_count > 0,
        "output": lines.join("\n"),
        "artifacts": artifact_items,
        "data": {
            "target": input.target.display().to_string(),
            "repoName": input.repo_name,
            "artifactDir": input.output_dir,
            "normalizedArtifact": artifacts.normalized_artifact.display().to_string(),
            "threatModelPath": persistent_artifact.display().to_string(),
            "provider": flavor.provider(),
            "methodology": input.methodology,
            "slice": input.slice,
            "stages": input.stages,
            "document": generated.document,
            "findings": findings,
            "persisted": artifacts.persisted,
        },
        "costUsd": generated.cost_usd,
    })
}
