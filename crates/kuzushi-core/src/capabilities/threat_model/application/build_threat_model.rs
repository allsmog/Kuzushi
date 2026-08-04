use super::*;

pub(crate) fn build_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<Value> {
    if deterministic_pipeline_requested(&input) {
        reject_model_only_options_for_deterministic_pipeline(&input, ctx)?;
        return build_deterministic_threat_model(input, ctx, flavor);
    }
    let runtime = require_threat_model_runtime(runtime, flavor)?;
    build_agentic_threat_model(input, ctx, runtime, flavor)
}

/// Threat modeling is model-backed. The runtime-free deterministic fold is an
/// explicit operator choice (`pipeline=deterministic`), never a silent
/// fallback when no model is configured.
fn require_threat_model_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<&'a dyn AgentRuntime> {
    runtime.with_context(|| {
        format!(
            "{} is model-backed and requires a configured model and agent runtime; \
             pass pipeline=deterministic to explicitly request the runtime-free \
             artifact-review-only fold instead",
            flavor.tool_name()
        )
    })
}

fn build_agentic_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    flavor: BuildFlavor,
) -> Result<Value> {
    let input = parse_build_input(&input, ctx, flavor)?;
    let verb = threat_model_build_verb(flavor);
    emit_threat_model_start(ctx, verb, flavor, &input);
    let snapshot = register_result_snapshot(ctx, verb, &input.target);
    let result = if input.is_refine() {
        refine_threat_model(runtime, ctx, flavor, verb, input)?
    } else if input.is_staged() {
        build_staged_threat_model(runtime, ctx, flavor, verb, input)?
    } else {
        build_single_threat_model(runtime, ctx, flavor, verb, input)?
    };
    Ok(attach_result_snapshot(result, snapshot))
}

fn build_single_threat_model(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: BuildInput,
) -> Result<Value> {
    let source_bundle = load_threat_model_source_bundle(ctx, &input)?;
    emit_source_bundle_loaded(ctx, verb, source_bundle.loaded_count());
    let grounding = load_prompt_grounding(&input, ctx)?;
    source_bundle.authenticate_entry_point_sources(&grounding.entry_point_catalog.receipt)?;
    emit_grounding_loaded(ctx, verb, &grounding);
    emit_seed_disclosure(ctx, verb, &input);
    let generated = generate_threat_model_document(
        runtime,
        ctx,
        flavor,
        verb,
        &input,
        &source_bundle,
        &grounding,
    )?;
    finish_agentic_threat_model(
        ctx,
        flavor,
        verb,
        input,
        generated,
        source_bundle,
        grounding,
    )
}

struct ResultSnapshot {
    snapshot_hash: String,
    tree_hash: String,
}

fn register_result_snapshot(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    target: &Path,
) -> Option<ResultSnapshot> {
    let workspace = crate::workspace::WorkspaceTarget::new(target).ok()?;
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let mut observer = |files: usize| {
        if heartbeat.ready() {
            emit_snapshot_progress(ctx, verb, format!("source identity · {files} files hashed"));
        }
    };
    match crate::incremental_index::register_workspace_tree_identity_with_observer(
        &workspace,
        &mut observer,
    ) {
        Ok(indexed) => Some(ResultSnapshot {
            snapshot_hash: indexed.snapshot_hash,
            tree_hash: indexed.tree_hash,
        }),
        Err(error) => {
            emit_snapshot_progress(
                ctx,
                verb,
                format!("source identity unavailable · {error:#}"),
            );
            None
        }
    }
}

fn emit_snapshot_progress(ctx: &ToolExecutionContext<'_>, verb: &str, detail: String) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("tool-progress", verb, detail).emit();
    }
}

fn attach_result_snapshot(mut result: Value, snapshot: Option<ResultSnapshot>) -> Value {
    if let (Some(data), Some(snapshot)) = (result["data"].as_object_mut(), snapshot) {
        data.insert("snapshotHash".to_string(), json!(snapshot.snapshot_hash));
        data.insert("treeHash".to_string(), json!(snapshot.tree_hash));
    }
    result
}

fn finish_agentic_threat_model(
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: BuildInput,
    mut generated: GeneratedThreatModel,
    source_bundle: ThreatModelSourceBundle,
    grounding: PromptGrounding,
) -> Result<Value> {
    let (coverage, parked) =
        finalize_single_document(&mut generated.document, &input.target, &grounding)?;
    emit_coverage_checked(ctx, verb, &coverage);
    let reconciliation = BuildReconciliation::from_report(
        &coverage,
        parked,
        "grounded surfaces",
        &generated.document,
    );
    complete_threat_model_build(
        ctx,
        flavor,
        verb,
        input,
        generated,
        source_bundle,
        reconciliation,
    )
}

fn finalize_single_document(
    document: &mut Value,
    target: &Path,
    grounding: &PromptGrounding,
) -> Result<(CoverageReport, usize)> {
    restore_grounded_entry_point_facts(
        document,
        &grounding.surfaces,
        &grounding.entry_point_catalog.catalog_surfaces,
    )?;
    stamp_provenance(document, target, "single");
    let coverage = check_coverage(document, &grounding.surfaces);
    let parked = park_unaccounted(document, &coverage.gaps);
    apply_coverage(
        document,
        &coverage,
        single_pipeline_gap_fill_method(&coverage),
        parked,
    );
    stamp_entry_point_catalog_receipt(document, &grounding.entry_point_catalog);
    Ok((coverage, parked))
}

/// Shared tail of every agentic build pipeline: artifact writes, persistence,
/// summary lines, and the result envelope. Callers stamp provenance and the
/// measured coverage object on the document before arriving here.
pub(crate) fn complete_threat_model_build(
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: BuildInput,
    mut generated: GeneratedThreatModel,
    source_bundle: ThreatModelSourceBundle,
    reconciliation: BuildReconciliation,
) -> Result<Value> {
    seal_build_document(&mut generated.document, &input, &source_bundle)?;
    let has_concrete_content =
        crate::workflow_attempts::threat_model_has_concrete_content(&generated.document);
    let cost = generated_threat_model_cost(&generated)?;
    let artifacts =
        write_threat_model_outputs(flavor, &input, &generated.document, has_concrete_content)?;
    emit_artifact_write(ctx, verb, &artifacts);
    let version_warning = record_persisted_version(
        ctx,
        &input.target,
        &generated.document,
        "build",
        artifacts.persisted,
    );
    finish_threat_model_build(
        ctx,
        flavor,
        verb,
        input,
        generated,
        source_bundle,
        artifacts,
        has_concrete_content,
        cost,
        version_warning,
        reconciliation,
    )
}

/// Summary lines, terminal trace step, and the result envelope for a
/// finished build.
#[allow(clippy::too_many_arguments)]
fn finish_threat_model_build(
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: BuildInput,
    mut generated: GeneratedThreatModel,
    source_bundle: ThreatModelSourceBundle,
    artifacts: ThreatModelArtifacts,
    has_concrete_content: bool,
    cost: crate::runtime::RuntimeCostReport,
    version_warning: Option<String>,
    reconciliation: BuildReconciliation,
) -> Result<Value> {
    let findings = take_threat_model_findings(&input, &mut generated);
    let summary = threat_model_summary(&generated.document);
    let (lines, warnings) = finished_build_lines(
        flavor,
        &input,
        &summary,
        findings.len(),
        artifacts.persisted,
        has_concrete_content,
        cost,
        version_warning,
        reconciliation,
    );
    emit_threat_model_terminal(ctx, verb, flavor, &summary, has_concrete_content);
    finished_build_response(
        input,
        flavor,
        generated,
        artifacts,
        findings,
        has_concrete_content,
        warnings,
        cost,
        lines,
        source_bundle,
    )
}

#[allow(clippy::too_many_arguments)]
fn finished_build_response(
    input: BuildInput,
    flavor: BuildFlavor,
    generated: GeneratedThreatModel,
    artifacts: ThreatModelArtifacts,
    findings: Vec<Value>,
    has_concrete_content: bool,
    warnings: Vec<String>,
    cost: crate::runtime::RuntimeCostReport,
    lines: Vec<String>,
    source_bundle: ThreatModelSourceBundle,
) -> Result<Value> {
    let honesty = ResultHonesty {
        has_concrete_content,
        warnings,
    };
    threat_model_response(
        input,
        flavor,
        generated,
        artifacts,
        findings,
        honesty,
        cost,
        lines,
        source_bundle,
    )
}

#[allow(clippy::too_many_arguments)]
fn finished_build_lines(
    flavor: BuildFlavor,
    input: &BuildInput,
    summary: &ThreatModelSummary,
    finding_count: usize,
    persisted: bool,
    has_concrete_content: bool,
    cost: crate::runtime::RuntimeCostReport,
    version_warning: Option<String>,
    reconciliation: BuildReconciliation,
) -> (Vec<String>, Vec<String>) {
    let mut lines = threat_model_output_lines(
        flavor,
        input,
        summary,
        finding_count,
        persisted,
        has_concrete_content,
        cost,
    );
    lines.extend(version_warning);
    let warnings = reconciliation.warning_lines();
    append_honesty_warnings(&mut lines, &warnings);
    (lines, warnings)
}

fn append_honesty_warnings(lines: &mut Vec<String>, warnings: &[String]) {
    lines.extend(
        warnings
            .iter()
            .map(|warning| format!("  Warning:  {warning}")),
    );
}

/// Final passes over the model's proposal before it may be persisted: seed
/// lineage and source attestation (system-owned provenance), display/stable
/// identity, then the hard DFD-reference gate. Ordering matters — provenance
/// is stamped while the previous model on disk is still the one that seeded
/// this build.
fn seal_build_document(
    document: &mut Value,
    input: &BuildInput,
    source_bundle: &ThreatModelSourceBundle,
) -> Result<()> {
    stamp_build_seed_lineage(document, input)?;
    stamp_source_provenance(
        document,
        source_bundle.provenance_json(),
        !input.is_refine(),
    );
    finalize_document_identity(document, &input.target)?;
    require_complete_security_context_links(document)
}

/// Seed lineage runs before persistence, while the live model on disk is
/// still the exact document that seeded the prompt. The stamped mode is
/// OBSERVED truth — "seeded" only if a prior model actually entered the
/// prompt — because a label that disagrees with the prompt is the defect this
/// replaces. The requested mode is recorded only when it differs, which
/// covers first builds and explicit sources lists that excluded the model.
fn stamp_build_seed_lineage(document: &mut Value, input: &BuildInput) -> Result<()> {
    let wants_seed = input.is_refine() || input.embeds_prior_model();
    let previous = if wants_seed {
        try_load_persistent_threat_model(&input.target)?
    } else {
        None
    };
    let observed = if input.is_refine() || previous.is_some() {
        "seeded"
    } else {
        "fresh"
    };
    let requested = (observed != input.seed_mode).then_some(input.seed_mode.as_str());
    stamp_seed_lineage(document, observed, requested, previous.as_ref());
    Ok(())
}

/// Contract identity pass on the finished document: content-addressed
/// stableIds, the harness (impact desc, likelihood desc) ordering over the
/// final threat set (gap-fill and the variant scan may have added or
/// re-scored rows after normalization), and persisted `T1..Tn` displayIds
/// carried forward from the previously persisted model so references never
/// renumber across refines.
fn finalize_document_identity(document: &mut Value, target: &Path) -> Result<()> {
    assign_stable_ids(document);
    if let Some(threats) = document.get_mut("threats").and_then(Value::as_array_mut) {
        sort_threats_by_risk(threats);
    }
    let previous = try_load_persistent_threat_model(target)?;
    assign_display_ids(document, previous.as_ref());
    Ok(())
}

/// Best-effort append of the just-persisted document to the version ledger
/// in the index DB. The flat JSON save already succeeded, so a ledger
/// failure must not fail the build -- but it surfaces as an output line
/// instead of being swallowed.
pub(crate) fn record_persisted_version(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    document: &Value,
    source: &str,
    persisted: bool,
) -> Option<String> {
    if !persisted {
        return None;
    }
    let run_id = ctx.run_id();
    match record_threat_model_version(target, document, source, run_id.as_deref()) {
        Ok(_) => None,
        Err(error) => Some(format!(
            "  Warning:  version ledger append failed: {error:#}"
        )),
    }
}

fn take_threat_model_findings(
    input: &BuildInput,
    generated: &mut GeneratedThreatModel,
) -> Vec<Value> {
    threat_model_findings(input, generated.bridge_findings.take(), &generated.document)
}

/// True only when the operator explicitly asked for the runtime-free
/// deterministic fold. The default pipeline is model-backed.
pub(crate) fn deterministic_pipeline_requested(input: &Value) -> bool {
    read_string(input, &["pipeline"])
        .is_some_and(|pipeline| pipeline.eq_ignore_ascii_case("deterministic"))
}

fn reject_model_only_options_for_deterministic_pipeline(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if has_runtime_only_source_option(input, ctx) {
        anyhow::bail!(
            "threat-model:build seed/seedMode/design/source/prompt/staged-pipeline options require the model-backed pipeline; the explicitly requested pipeline=deterministic fold cannot consume them"
        );
    }
    Ok(())
}

fn has_runtime_only_source_option(input: &Value, ctx: &ToolExecutionContext<'_>) -> bool {
    has_nonempty_list(input, "seed")
        || read_string(input, &["vulnsFile", "vulns_file", "vulns"]).is_some()
        || staged_pipeline_options_requested(input)
        || read_string(input, &["designDoc", "design_doc", "design"]).is_some()
        || explicit_prompt_override_requested(input, ctx)
        || nondefault_sources_requested(input)
        || nondefault_context_controls_requested(input)
        || nondefault_seed_mode_requested(input)
}

/// `seedMode` steers prompt composition, so it is meaningless on the
/// runtime-free pipeline. Reject rather than silently ignore it.
fn nondefault_seed_mode_requested(input: &Value) -> bool {
    read_string(input, &["seedMode", "seed_mode"])
        .is_some_and(|mode| !mode.eq_ignore_ascii_case("seeded"))
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

fn staged_pipeline_options_requested(input: &Value) -> bool {
    read_string(input, &["pipeline"]).is_some_and(|pipeline| pipeline.to_lowercase() == "staged")
        || read_string(input, &["mode"]).is_some_and(|mode| mode.to_lowercase() != "build")
        || input.get("budgetUsd").is_some()
        || input.get("budget_usd").is_some()
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
    }) || input
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

pub(crate) fn emit_source_bundle_loaded(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    loaded_count: usize,
) {
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

pub(crate) fn emit_grounding_loaded(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    grounding: &PromptGrounding,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                verb,
                format!(
                    "grounding: {} surfaces · {} confirmed findings",
                    grounding.surfaces.len(),
                    grounding.confirmed_findings.len()
                ),
            )
            .emit();
    }
}

/// A fresh run that leaves a real persisted model on the table says so before
/// the model call. Emitted pre-persist, so the existence check reflects the
/// disk state the operator would be comparing against.
pub(crate) fn emit_seed_disclosure(ctx: &ToolExecutionContext<'_>, verb: &str, input: &BuildInput) {
    if input.embeds_prior_model() || !persistent_threat_model_path(&input.target).exists() {
        return;
    }
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                verb,
                "seed: fresh · persisted threat model excluded from prompt",
            )
            .emit();
    }
}

pub(crate) fn emit_coverage_checked(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    coverage: &CoverageReport,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                verb,
                format!(
                    "coverage: {}/{} entry points covered",
                    coverage.covered(),
                    coverage.considered
                ),
            )
            .emit();
    }
}

fn single_pipeline_gap_fill_method(coverage: &CoverageReport) -> &'static str {
    if coverage.invariant_satisfied() {
        "none-needed"
    } else {
        "unresolved"
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

pub(crate) struct GeneratedThreatModel {
    pub(crate) document: Value,
    pub(crate) bridge_findings: Option<Vec<Value>>,
    pub(crate) cost_usd: f64,
    pub(crate) cost_usd_exact: bool,
}

fn generate_threat_model_document(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: &BuildInput,
    source_bundle: &ThreatModelSourceBundle,
    grounding: &PromptGrounding,
) -> Result<GeneratedThreatModel> {
    let prompt = threat_model_prompt(input, source_bundle, grounding)?;
    let checkpoints = ctx.stage_checkpoints();
    let synthesis_stage = stage_scope(&checkpoints, "synthesis");
    let costed = query_threat_model_document(runtime, ctx, flavor, verb, input, prompt)?;
    complete_stage(synthesis_stage, Vec::new());
    let mut generated = normalize_threat_model_raw(costed.value, &input.methodology)?;
    generated.cost_usd = costed.cost_usd;
    generated.cost_usd_exact = costed.cost_usd_exact;
    emit_validation_done(ctx, verb);
    Ok(generated)
}

fn threat_model_prompt(
    input: &BuildInput,
    source_bundle: &ThreatModelSourceBundle,
    grounding: &PromptGrounding,
) -> Result<String> {
    // The seeding decision resolved at the adapter: fresh — or a sources list
    // that excludes the persisted model — embeds nothing from the previous
    // generation, full document and count summary alike.
    let previous_model = if input.embeds_prior_model() {
        try_load_persistent_threat_model(&input.target)?
    } else {
        None
    };
    build_agent_prompt(input, previous_model.as_ref(), source_bundle, grounding)
}

pub(crate) fn query_threat_model_document(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    verb: &str,
    input: &BuildInput,
    prompt: String,
) -> Result<crate::structured_output::CostedStructuredJson<Value>> {
    let _llm_scope = begin_threat_model_llm_scope(ctx, verb);
    // The prompt embeds every input (source bundle, grounding, previous
    // document), so an unchanged workspace replays the synthesis for free.
    let cache = crate::semantic_cache::SemanticCache::open_for_target(&input.target);
    let costed = crate::structured_output::query_cached_structured_json_with_cost(
        cache.as_ref(),
        runtime,
        AgentQueryRequest::new(
            input.model.clone(),
            input.target.clone(),
            threat_model_system_prompt(),
            prompt,
        )
        .with_max_output_tokens(input.max_output_tokens),
        StructuredJsonContract::new(
            flavor.tool_name(),
            "ThreatModelDocument",
            threat_model_document_schema(),
        ),
        |raw| validate_threat_model_raw(raw, &input.methodology),
    )?
    .costed;
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
    let document = normalize_document(document_candidate, methodology)?;
    require_complete_security_context_links(&document)?;
    Ok(raw)
}

pub(crate) fn normalize_threat_model_raw(
    raw: Value,
    methodology: &str,
) -> Result<GeneratedThreatModel> {
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
    markdown_artifact: PathBuf,
    persisted: bool,
}

fn write_threat_model_outputs(
    flavor: BuildFlavor,
    input: &BuildInput,
    document: &Value,
    has_concrete_content: bool,
) -> Result<ThreatModelArtifacts> {
    let normalized_artifact =
        write_normalized_artifact(&input.target, &input.output_dir, document)?;
    let markdown = render_schema_markdown(
        document,
        &input.repo_name,
        &input.target.display().to_string(),
    );
    let markdown_artifact = write_markdown_artifact(
        &input.target,
        &input.output_dir,
        "THREAT_MODEL.md",
        &markdown,
    )?;
    let persisted = persist_threat_model_document(flavor, input, document, has_concrete_content)?;
    Ok(ThreatModelArtifacts {
        normalized_artifact,
        markdown_artifact,
        persisted,
    })
}

fn persist_threat_model_document(
    flavor: BuildFlavor,
    input: &BuildInput,
    document: &Value,
    has_concrete_content: bool,
) -> Result<bool> {
    if !flavor.persists_document() || !has_concrete_content {
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

/// What the result envelope is permitted to claim about a finished build:
/// whether it produced real content, and which measured honesty axes it
/// failed. Empty warnings plus concrete content is the only `completed` state.
pub(crate) struct ResultHonesty {
    pub(crate) has_concrete_content: bool,
    pub(crate) warnings: Vec<String>,
}

fn threat_model_response(
    input: BuildInput,
    flavor: BuildFlavor,
    generated: GeneratedThreatModel,
    artifacts: ThreatModelArtifacts,
    findings: Vec<Value>,
    honesty: ResultHonesty,
    cost: crate::runtime::RuntimeCostReport,
    mut lines: Vec<String>,
    source_bundle: ThreatModelSourceBundle,
) -> Result<Value> {
    append_top_threats(&mut lines, &generated.document);
    let target = input.target.clone();
    let persistent_artifact = persistent_threat_model_path(&input.target);
    let artifact_items = threat_model_artifacts(
        &artifacts.normalized_artifact,
        &artifacts.markdown_artifact,
        &persistent_artifact,
        artifacts.persisted,
    );
    let data = threat_model_result_data(
        input,
        flavor,
        generated,
        artifacts,
        findings,
        source_bundle,
        persistent_artifact,
    );
    let mut result = threat_model_result_envelope(flavor, &target, lines, data, honesty);
    result["artifacts"] = json!(artifact_items);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

fn threat_model_result_envelope(
    flavor: BuildFlavor,
    target: &Path,
    mut lines: Vec<String>,
    data: Value,
    honesty: ResultHonesty,
) -> Value {
    if honesty.has_concrete_content && honesty.warnings.is_empty() {
        let output = lines.join("\n");
        return crate::module_result::completed_output_result(output.clone(), output, data);
    }
    if honesty.has_concrete_content {
        return honesty_partial_envelope(flavor, lines, data, honesty.warnings);
    }
    let guidance = crate::workflow_attempts::insufficient_map_evidence_message(target);
    lines.push(guidance.clone());
    let mut warnings = vec![json!(guidance)];
    warnings.extend(honesty.warnings.into_iter().map(Value::String));
    crate::module_result::partial_output_result(
        format!(
            "{} produced no concrete threat-model evidence",
            flavor.tool_name()
        ),
        lines.join("\n"),
        warnings,
        data,
    )
}

/// A build that produced real content but failed a measured honesty axis.
/// The document is still useful Map evidence, so it persists and the run
/// stays `ok` — but `completed` would overstate what was accounted for.
fn honesty_partial_envelope(
    flavor: BuildFlavor,
    lines: Vec<String>,
    data: Value,
    honesty_warnings: Vec<String>,
) -> Value {
    let summary = format!("{}: {}", flavor.tool_name(), honesty_warnings.join("; "));
    let warnings = honesty_warnings.into_iter().map(Value::String).collect();
    crate::module_result::partial_output_result(summary, lines.join("\n"), warnings, data)
}

fn generated_threat_model_cost(
    generated: &GeneratedThreatModel,
) -> Result<crate::runtime::RuntimeCostReport> {
    let observed =
        crate::runtime::RuntimeCost::from_usd(generated.cost_usd, "threat-model generated cost")?;
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
        "markdownArtifact": artifacts.markdown_artifact.display().to_string(),
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

#[cfg(test)]
mod catalog_receipt_tests {
    use super::*;

    #[test]
    fn single_finalizer_stamps_catalog_receipt_and_overlap_counts() {
        let target = tempfile::tempdir().unwrap();
        let grounding = PromptGrounding {
            surfaces: Vec::new(),
            confirmed_findings: Vec::new(),
            entry_point_catalog: crate::capabilities::entry_points::EntryPointCatalogGrounding {
                receipt: crate::capabilities::entry_points::EntryPointCatalogReceipt {
                    status: "current".to_string(),
                    sha256: Some("sha256:catalog".to_string()),
                    records: 519,
                    records_selected: 30,
                    grounding_limit: 40,
                    grounding_records_selected: 40,
                    snapshot_timestamp: Some(9),
                    context_sha256: Some("sha256:context".to_string()),
                    tree_hash: None,
                    selection_policy: "risk-kind-stratified-v1".to_string(),
                    revision: None,
                    revision_dirty: None,
                },
                catalog_ids: ["AS-one".to_string()].into_iter().collect(),
                catalog_surfaces: Vec::new(),
            },
        };
        let mut document = json!({
            "threats": [],
            "attackSurface": {"entryPoints": [{"id": "AS-one"}]},
        });

        finalize_single_document(&mut document, target.path(), &grounding).unwrap();

        assert_eq!(
            document["provenance"]["entryPointCatalog"]["records"],
            json!(519)
        );
        assert_eq!(
            document["coverage"]["catalogEntryPointsSelected"],
            json!(30)
        );
        assert_eq!(document["coverage"]["catalogEntryPointsLinked"], json!(1));
    }
}
