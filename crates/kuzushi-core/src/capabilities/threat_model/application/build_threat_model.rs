use super::*;

pub(crate) fn build_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<Value> {
    if should_build_deterministically(&input, ctx, runtime) {
        reject_source_options_without_runtime(&input, ctx)?;
        return build_deterministic_threat_model(input, ctx, flavor);
    }
    build_agentic_threat_model(input, ctx, runtime, flavor)
}

fn build_agentic_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<Value> {
    let runtime = runtime.expect("deterministic path handles missing runtime");
    let input = parse_build_input(&input, ctx, flavor)?;
    let verb = threat_model_build_verb(flavor);
    emit_threat_model_start(ctx, verb, flavor, &input);
    let source_bundle = load_threat_model_source_bundle(ctx, &input)?;
    emit_source_bundle_loaded(ctx, verb, source_bundle.loaded_count());
    let mut generated =
        generate_threat_model_document(runtime, ctx, flavor, verb, &input, &source_bundle)?;
    let artifacts = write_threat_model_outputs(flavor, &input, &generated.document)?;
    emit_artifact_write(ctx, verb, &artifacts);
    let findings = take_threat_model_findings(&input, &mut generated);
    let summary = threat_model_summary(&generated.document);
    let lines = threat_model_output_lines(
        flavor,
        &input,
        &summary,
        findings.len(),
        artifacts.persisted,
    );
    emit_threat_model_done(ctx, verb, flavor, &summary);
    threat_model_response(
        input,
        flavor,
        generated,
        artifacts,
        findings,
        summary,
        lines,
        source_bundle,
    )
}

fn take_threat_model_findings(
    input: &BuildInput,
    generated: &mut GeneratedThreatModel,
) -> Vec<Value> {
    threat_model_findings(
        input,
        generated.bridge_findings.take(),
        &generated.document,
    )
}

fn should_build_deterministically(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> bool {
    runtime.is_none() || (read_string(input, &["model"]).is_none() && ctx.config.model.is_none())
}

fn reject_source_options_without_runtime(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<()> {
    if has_runtime_only_source_option(input, ctx) {
        anyhow::bail!(
            "threat-model:build seed/design/source prompt options require a configured model/runtime; deterministic no-runtime threat modeling cannot consume them"
        );
    }
    Ok(())
}

fn has_runtime_only_source_option(input: &Value, ctx: &ToolExecutionContext<'_>) -> bool {
    has_nonempty_list(input, "seed")
        || read_string(input, &["designDoc", "design_doc", "design"]).is_some()
        || explicit_prompt_override_requested(input, ctx)
        || nondefault_sources_requested(input)
        || nondefault_context_controls_requested(input)
}

fn has_nonempty_list(input: &Value, key: &str) -> bool {
    match input.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .any(|value| !value.is_empty()),
        Some(Value::String(value)) => !value.trim().is_empty(),
        _ => false,
    }
}

fn nondefault_sources_requested(input: &Value) -> bool {
    let sources = read_string_list(input, &["sources", "sourceArtifacts", "source_artifacts"])
        .into_iter()
        .map(|source| source.to_lowercase())
        .collect::<Vec<_>>();
    !sources.is_empty()
        && !source_lists_match(&sources, &["context", "threat-model"])
        && !source_lists_match(&sources, &["none"])
}

fn nondefault_context_controls_requested(input: &Value) -> bool {
    read_string(input, &["contextMode", "context_mode"]).is_some_and(|mode| {
        let mode = mode.to_ascii_lowercase();
        mode != "auto" && mode != "off"
    })
        || input
            .get("contextLimit")
            .and_then(Value::as_u64)
            .is_some_and(|limit| limit != 200)
        || input
            .get("maxSourceBytes")
            .and_then(Value::as_u64)
            .is_some_and(|limit| limit != 200_000)
}

fn explicit_prompt_override_requested(input: &Value, ctx: &ToolExecutionContext<'_>) -> bool {
    let Some(prompt) = read_string(input, &["THREAT_MODEL_PROMPT"]) else {
        return false;
    };
    !prompt_text_matches(DEFAULT_THREAT_MODEL_GUIDANCE, &prompt)
        && !prompt_matches_workspace_default_prompt(input, ctx, &prompt)
}

fn prompt_matches_workspace_default_prompt(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    prompt: &str,
) -> bool {
    let target = ctx
        .workspace
        .map(|workspace| workspace.root().to_path_buf())
        .or_else(|| read_string(input, &["target"]).map(PathBuf::from));
    let Some(target) = target else {
        return false;
    };
    let path = crate::options::prompt_override_path(&target, "threat-model", "build");
    let Ok(content) = crate::bounded_file::read_utf8_text(&path, MAX_SOURCE_BYTES) else {
        return false;
    };
    if prompt_text_matches(&content, prompt) {
        return true;
    }
    let relative = crate::options::relative_prompt_override_path("threat-model", "build");
    let composed = crate::prompts::compose_target_prompt_context(
        DEFAULT_THREAT_MODEL_GUIDANCE,
        &relative.display().to_string(),
        &content,
    );
    prompt_text_matches(&composed, prompt)
}

fn prompt_text_matches(file_content: &str, prompt: &str) -> bool {
    file_content.trim_end_matches(['\r', '\n']) == prompt.trim_end_matches(['\r', '\n'])
}

fn source_lists_match(actual: &[String], expected: &[&str]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    expected
        .iter()
        .all(|expected| actual.iter().any(|actual| actual == expected))
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

fn emit_source_bundle_loaded(ctx: &ToolExecutionContext<'_>, verb: &str, loaded_count: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                verb,
                format!("source:parent artifacts · {loaded_count} loaded"),
            )
            .emit();
    }
}

fn emit_validation_done(ctx: &ToolExecutionContext<'_>, verb: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("tool-progress", verb, "schema:normalize").emit();
    }
}

fn emit_artifact_write(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    artifacts: &ThreatModelArtifacts,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                verb,
                format!(
                    "artifact:write · {}",
                    artifacts.normalized_artifact.display()
                ),
            )
            .emit();
    }
}

struct GeneratedThreatModel {
    document: Value,
    bridge_findings: Option<Vec<Value>>,
    cost_usd: f64,
    cost_usd_exact: bool,
}

fn generate_threat_model_document(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: &BuildInput,
    source_bundle: &ThreatModelSourceBundle,
) -> Result<GeneratedThreatModel> {
    let prompt = threat_model_prompt(input, source_bundle)?;
    let costed = query_threat_model_document(runtime, ctx, flavor, verb, input, prompt)?;
    let mut generated = normalize_threat_model_raw(costed.value, &input.methodology)?;
    generated.cost_usd = costed.cost_usd;
    generated.cost_usd_exact = costed.cost_usd_exact;
    emit_validation_done(ctx, verb);
    Ok(generated)
}

fn threat_model_prompt(input: &BuildInput, source_bundle: &ThreatModelSourceBundle) -> Result<String> {
    let previous_model = try_load_persistent_threat_model(&input.target)?;
    build_agent_prompt(input, previous_model.as_ref(), source_bundle)
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
            threat_model_system_prompt(),
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
    ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                verb,
                "model:threat synthesis · schema:normalize",
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
        cost_usd_exact: true,
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
    source_bundle: ThreatModelSourceBundle,
) -> Result<Value> {
    append_top_threats(&mut lines, &generated.document);
    let persistent_artifact = persistent_threat_model_path(&input.target);
    let artifact_items = threat_model_artifacts(
        &artifacts.normalized_artifact,
        &persistent_artifact,
        artifacts.persisted,
    );
    let cost = generated_threat_model_cost(&generated)?;
    let data = threat_model_result_data(
        input,
        flavor,
        generated,
        artifacts,
        findings,
        source_bundle,
        persistent_artifact,
    );
    let mut result = json!({
        "ok": summary.threat_count > 0 || summary.node_count > 0 || summary.flow_count > 0,
        "output": lines.join("\n"),
        "artifacts": artifact_items,
        "data": data,
    });
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

fn generated_threat_model_cost(
    generated: &GeneratedThreatModel,
) -> Result<crate::runtime::RuntimeCostReport> {
    let observed = crate::runtime::RuntimeCost::from_usd(
        generated.cost_usd,
        "threat-model generated cost",
    )?;
    Ok(if generated.cost_usd_exact {
        crate::runtime::RuntimeCostReport::known(observed)
    } else {
        crate::runtime::RuntimeCostReport::incomplete(observed)
    })
}

fn threat_model_result_data(
    input: BuildInput,
    flavor: BuildFlavor,
    generated: GeneratedThreatModel,
    artifacts: ThreatModelArtifacts,
    findings: Vec<Value>,
    source_bundle: ThreatModelSourceBundle,
    persistent_artifact: PathBuf,
) -> Value {
    json!({
        "target": input.target.display().to_string(),
        "repoName": input.repo_name,
        "artifactDir": input.output_dir,
        "normalizedArtifact": artifacts.normalized_artifact.display().to_string(),
        "threatModelPath": persistent_artifact.display().to_string(),
        "provider": flavor.provider(),
        "methodology": input.methodology,
        "slice": input.slice,
        "stages": input.stages,
        "sources": source_bundle.metadata_json(),
        "document": generated.document,
        "findings": findings,
        "persisted": artifacts.persisted,
    })
}
