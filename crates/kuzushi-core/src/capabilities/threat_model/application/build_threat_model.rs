use super::*;

pub(crate) fn build_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<Value> {
    let runtime = require_threat_model_runtime(runtime, flavor)?;
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

fn require_threat_model_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<&'a dyn AgentRuntime> {
    runtime.with_context(|| {
        format!(
            "{} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
            flavor.tool_name()
        )
    })
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
}

fn generate_threat_model_document(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: &BuildInput,
) -> Result<GeneratedThreatModel> {
    let prompt = threat_model_prompt(input)?;
    let raw = query_threat_model_document(runtime, ctx, flavor, verb, input, prompt)?;
    normalize_threat_model_raw(raw, &input.methodology)
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
) -> Result<Value> {
    let _llm_scope = begin_threat_model_llm_scope(ctx, verb);
    let raw = query_required_structured_json(
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
    Ok(raw)
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

struct ThreatModelSummary {
    threat_count: usize,
    node_count: usize,
    flow_count: usize,
    boundary_count: usize,
}

fn threat_model_summary(document: &Value) -> ThreatModelSummary {
    ThreatModelSummary {
        threat_count: array_len(document.pointer("/threats")),
        node_count: array_len(document.pointer("/dfd/nodes")),
        flow_count: array_len(document.pointer("/dfd/flows")),
        boundary_count: array_len(document.pointer("/dfd/trustBoundaries")),
    }
}

fn threat_model_output_lines(
    flavor: BuildFlavor,
    input: &BuildInput,
    summary: &ThreatModelSummary,
    finding_count: usize,
    persisted: bool,
) -> Vec<String> {
    let mut lines = threat_model_header_lines(flavor, input, persisted);
    lines.extend(threat_model_metric_lines(input, summary, finding_count));
    lines
}

fn threat_model_header_lines(
    flavor: BuildFlavor,
    input: &BuildInput,
    persisted: bool,
) -> Vec<String> {
    match flavor {
        BuildFlavor::ThreatModel => threat_model_build_header_lines(input, persisted),
        BuildFlavor::RandoriPasta => randori_pasta_header_lines(input),
    }
}

fn threat_model_build_header_lines(input: &BuildInput, persisted: bool) -> Vec<String> {
    vec![
        format!(
            "threat-model:build complete for {} ({})",
            input.repo_name,
            input.target.display()
        ),
        format!("  Method:   {}", methodology_label(&input.methodology)),
        format!("  Slice:    {}", input.slice),
        format!("  Provider: {}", BuildFlavor::ThreatModel.provider()),
        format!("  Stages:   {}", input.stages.join(", ")),
        format!("  Artifact: {}", input.output_dir),
        format!("  Saved:    {}", saved_threat_model_status(persisted)),
    ]
}

fn randori_pasta_header_lines(input: &BuildInput) -> Vec<String> {
    vec![
        format!(
            "randori:pasta complete for {} ({})",
            input.repo_name,
            input.target.display()
        ),
        format!("  Stages:   {}", input.stages.join(", ")),
        format!("  Artifact: {}", input.output_dir),
    ]
}

fn saved_threat_model_status(persisted: bool) -> &'static str {
    if persisted {
        ".kuzushi/threat-model.json"
    } else {
        "skipped (operator-edited model preserved)"
    }
}

fn threat_model_metric_lines(
    input: &BuildInput,
    summary: &ThreatModelSummary,
    finding_count: usize,
) -> [String; 4] {
    [
        format!("  Threats:  {}", summary.threat_count),
        format!(
            "  DFD:      {} nodes · {} flows · {} boundaries",
            summary.node_count, summary.flow_count, summary.boundary_count
        ),
        format!(
            "  Findings: {}{}",
            finding_count,
            findings_suppressed_suffix(input.emit_findings)
        ),
        "  Cost:     $0.0000".to_string(),
    ]
}

fn findings_suppressed_suffix(emit_findings: bool) -> &'static str {
    if emit_findings {
        ""
    } else {
        " (emitFindings=false)"
    }
}

fn emit_threat_model_done(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    flavor: BuildFlavor,
    summary: &ThreatModelSummary,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                verb,
                format!(
                    "{} complete · {threats} threats · {nodes} nodes",
                    flavor.tool_name(),
                    threats = summary.threat_count,
                    nodes = summary.node_count
                ),
            )
            .emit();
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
    json!({
        "ok": summary.threat_count > 0 || summary.node_count > 0 || summary.flow_count > 0,
        "output": lines.join("\n"),
        "data": {
            "target": input.target.display().to_string(),
            "repoName": input.repo_name,
            "artifactDir": input.output_dir,
            "normalizedArtifact": artifacts.normalized_artifact.display().to_string(),
            "threatModelPath": input.target.join(".kuzushi").join("threat-model.json").display().to_string(),
            "provider": flavor.provider(),
            "methodology": input.methodology,
            "slice": input.slice,
            "stages": input.stages,
            "document": generated.document,
            "findings": findings,
            "persisted": artifacts.persisted,
        },
        "costUsd": 0.0,
    })
}
