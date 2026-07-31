use super::*;
use super::deterministic_dfd::deterministic_dfd;
use super::deterministic_route_context::{
    authorization_flow_input, callback_flow_input, credential_flow_input, cwe_for_surface,
    data_egress_input, file_ingest_input,
};
use crate::attack_surface::{build_attack_surface_map, line_contains_any, AttackSurface, AttackSurfaceKind};

pub(crate) fn build_deterministic_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<Value> {
    let input = parse_deterministic_build_input(&input, ctx, flavor)?;
    let surface_map = build_attack_surface_map(&input.target)?;
    let mut document = deterministic_document(&input, &surface_map.surfaces)?;
    // The explicitly requested deterministic fold stamps the same provenance
    // as the model-backed pipeline: derived surfaces (seeding lines, lineage
    // headers) name the target revision this model was built against instead
    // of degrading to count-only provenance.
    stamp_provenance(&mut document, &input.target, "deterministic");
    require_complete_security_context_links(&document)?;
    let has_concrete_content =
        crate::workflow_attempts::threat_model_has_concrete_content(&document);
    let (normalized_artifact, markdown_artifact) =
        write_deterministic_artifacts(&input, &document)?;
    let persisted =
        persist_deterministic_document(flavor, &input, &document, has_concrete_content)?;
    if let Some(warning) =
        record_persisted_version(ctx, &input.target, &document, "deterministic", persisted)
    {
        if let Some(trace) = ctx.trace {
            let _ = trace.step("tool-progress", "build", warning).emit();
        }
    }
    Ok(deterministic_response(
        input,
        flavor,
        document,
        normalized_artifact,
        markdown_artifact,
        persisted,
        has_concrete_content,
    ))
}

fn write_deterministic_artifacts(
    input: &DeterministicBuildInput,
    document: &Value,
) -> Result<(PathBuf, PathBuf)> {
    let normalized = write_normalized_artifact(&input.target, &input.output_dir, document)?;
    let markdown = render_schema_markdown(
        document,
        &input.repo_name,
        &input.target.display().to_string(),
    );
    let rendered = write_markdown_artifact(
        &input.target,
        &input.output_dir,
        "THREAT_MODEL.md",
        &markdown,
    )?;
    Ok((normalized, rendered))
}

fn deterministic_document(input: &DeterministicBuildInput, surfaces: &[AttackSurface]) -> Result<Value> {
    let threat_surfaces = deterministic_threat_surfaces(surfaces, input.max_threats);
    let narrative_surfaces = surfaces.iter().collect::<Vec<_>>();
    let document = json!({
        "version": "2.0",
        "methodology": input.methodology,
        "dfd": deterministic_dfd(surfaces),
        "threats": deterministic_threats(&threat_surfaces),
        "narrative": deterministic_narrative(&narrative_surfaces),
        "degradation": deterministic_degradation(),
    });
    apply_methodology(normalize_document(document, &input.methodology)?, &input.methodology)
}

fn deterministic_threat_surfaces(
    surfaces: &[AttackSurface],
    max_threats: usize,
) -> Vec<&AttackSurface> {
    surfaces
        .iter()
        .filter(|surface| emits_deterministic_threat(surface))
        .take(max_threats)
        .collect()
}

fn emits_deterministic_threat(surface: &AttackSurface) -> bool {
    // New-4: an `Unknown`-kind surface has no target element id
    // (`target_element_ids_for` returns `&[]`), so emitting a deterministic
    // threat for it would produce an empty `targetElementIds` and fail
    // `require_complete_security_context_links`. The fresh builder never emits
    // `Unknown` today, but a future refactor that folds LOADED surfaces could —
    // this guard keeps such surfaces out of deterministic threats rather than
    // letting them break the security-context-link invariant.
    if surface.kind == AttackSurfaceKind::Unknown {
        return false;
    }
    surface.risk.score >= 50 || surface.kind == AttackSurfaceKind::BackgroundJob
}

fn deterministic_threats(surfaces: &[&AttackSurface]) -> Vec<Value> {
    surfaces
        .iter()
        .enumerate()
        .map(|(index, surface)| deterministic_threat(index, surface))
        .collect()
}

fn deterministic_threat(index: usize, surface: &AttackSurface) -> Value {
    json!({
        "id": format!("DTM-{number:03}", number = index + 1),
        "targetElementIds": target_element_ids_for(surface.kind),
        "category": stride_category_for(surface.kind),
        "title": format!("{} exposure", surface.title),
        "description": deterministic_threat_description(surface),
        "attackVector": surface.route.clone().unwrap_or_else(|| surface.evidence.clone()),
        "preconditions": ["attacker can reach the recorded boundary"],
        "impact": impact_for_risk(&surface.risk.tier),
        "likelihood": likelihood_for_risk(&surface.risk.tier),
        "existingMitigations": [],
        "missingMitigations": ["Review authorization, input handling, and observability for this boundary."],
        "relatedCwe": cwe_for_surface(surface),
        "affectedFiles": affected_file(surface),
        "evidenceAnchors": evidence_anchor(surface),
    })
}

fn deterministic_threat_description(surface: &AttackSurface) -> String {
    format!(
        "Deterministic threat candidate from {} {} at {}.",
        surface_context(surface),
        surface.kind.as_str(),
        surface.path
    )
}

fn surface_context(surface: &AttackSurface) -> String {
    match (surface.framework.as_deref(), surface.language.as_str()) {
        (Some(framework), language) => format!("{framework}/{language}"),
        (None, language) => language.to_string(),
    }
}

fn target_element_ids_for(kind: AttackSurfaceKind) -> &'static [&'static str] {
    match kind {
        AttackSurfaceKind::HttpRoute => &["http-route"],
        AttackSurfaceKind::DbQueryBoundary => &["data-store"],
        AttackSurfaceKind::CommandExecutionBoundary => &["process-execution"],
        AttackSurfaceKind::DeserializationPoint => &["parser-boundary"],
        AttackSurfaceKind::FileUploadParsePath => &["file-upload-parser"],
        AttackSurfaceKind::RpcHandler => &["rpc-handler"],
        AttackSurfaceKind::CliEntrypoint => &["cli-entrypoint"],
        AttackSurfaceKind::BackgroundJob => &["background-job"],
        AttackSurfaceKind::ExternalServiceClient => &["external-service"],
        AttackSurfaceKind::AuthBoundary => &["auth-control"],
        AttackSurfaceKind::SessionStateBoundary => &["session-state"],
        AttackSurfaceKind::RequestTrustBoundary => &["request-trust-control"],
        AttackSurfaceKind::TenantIsolationBoundary => &["tenant-isolation-control"],
        AttackSurfaceKind::InfraConfig => &["infra-config"],
        AttackSurfaceKind::SupplyChain => &["supply-chain"],
        AttackSurfaceKind::Unknown => &[],
    }
}

fn deterministic_narrative(surfaces: &[&AttackSurface]) -> Value {
    json!({
        "overview": "Deterministic threat model generated from repository attack-surface artifacts without LLM enrichment.",
        "inputCategories": deterministic_input_categories(surfaces),
        "attackerStories": surfaces
            .iter()
            .take(5)
            .enumerate()
            .map(|(index, surface)| attacker_story(index, surface))
            .collect::<Vec<_>>(),
        "criticalityBuckets": deterministic_criticality_buckets(surfaces),
        "outOfScope": ["Runtime validation and exploit confirmation did not run in deterministic mode."],
    })
}

fn deterministic_input_categories(surfaces: &[&AttackSurface]) -> Value {
    json!({
        "attackerControlled": strings_from_surfaces(surfaces, attacker_controlled_input),
        "operatorControlled": Vec::<String>::new(),
        "developerControlled": Vec::<String>::new(),
        "externalServices": strings_from_surfaces(surfaces, external_service_input),
        "credentialFlows": strings_from_surfaces(surfaces, credential_flow_input),
        "authorizationFlows": strings_from_surfaces(surfaces, authorization_flow_input),
        "fileIngestFlows": strings_from_surfaces(surfaces, file_ingest_input),
        "dataEgressFlows": strings_from_surfaces(surfaces, data_egress_input),
        "callbackFlows": strings_from_surfaces(surfaces, callback_flow_input),
        "sandboxBoundary": Vec::<String>::new(),
        "assumptions": ["Generated from static attack-surface evidence without LLM enrichment."],
    })
}

fn deterministic_criticality_buckets(surfaces: &[&AttackSurface]) -> Value {
    json!({
        "critical": tier_titles(surfaces, "critical"),
        "high": tier_titles(surfaces, "high"),
        "medium": tier_titles(surfaces, "medium"),
        "low": tier_titles(surfaces, "low"),
    })
}

fn strings_from_surfaces(
    surfaces: &[&AttackSurface],
    mapper: fn(&AttackSurface) -> Option<String>,
) -> Vec<String> {
    surfaces.iter().filter_map(|surface| mapper(surface)).collect()
}

fn attacker_controlled_input(surface: &AttackSurface) -> Option<String> {
    if surface.route.is_some()
        || line_contains_any(&surface.evidence.to_ascii_lowercase(), REQUEST_INPUT_EVIDENCE)
    {
        return Some(surface.title.clone());
    }
    None
}

const REQUEST_INPUT_EVIDENCE: &[&str] = &[
    "$request", "$_", "@request", "cookies[", "cookies.signed", "formvalue(", "json<",
    "cookies.get(", "headers.get(", "params", "query<", "r.body", "r.cookie(",
    "r.header.get(", "req.", "request.", "input", "iformfile", "request.cookies",
    "[frombody", "[fromform", "[fromheader", "[fromquery",
];

fn external_service_input(surface: &AttackSurface) -> Option<String> {
    (surface.kind == AttackSurfaceKind::ExternalServiceClient).then(|| surface.title.clone())
}

fn tier_titles(surfaces: &[&AttackSurface], tier: &str) -> Vec<String> {
    surfaces
        .iter()
        .filter(|surface| surface.risk.tier == tier)
        .map(|surface| surface.title.clone())
        .collect()
}

fn attacker_story(index: usize, surface: &AttackSurface) -> Value {
    json!({
        "title": format!("Exercise {}", surface.title),
        "narrative": format!("An external actor targets {} using the recorded {} {} evidence.", surface.title, surface_context(surface), surface.kind.as_str()),
        "mitigation": "Confirm controls through review and, where appropriate, explicit verification.",
        "threatIds": [format!("DTM-{number:03}", number = index + 1)],
    })
}

fn deterministic_degradation() -> Value {
    json!({
        "mode": "deterministic-no-runtime",
        "reason": "operator explicitly requested pipeline=deterministic; no model call was made",
        "allowedProofLevel": "artifact-review-only; empirical verification did not run",
    })
}

fn stride_category_for(kind: AttackSurfaceKind) -> &'static str {
    match kind {
        AttackSurfaceKind::AuthBoundary | AttackSurfaceKind::SessionStateBoundary => "spoofing",
        AttackSurfaceKind::TenantIsolationBoundary => "elevation-of-privilege",
        AttackSurfaceKind::RequestTrustBoundary => "tampering",
        AttackSurfaceKind::CommandExecutionBoundary => "elevation-of-privilege",
        AttackSurfaceKind::ExternalServiceClient => "information-disclosure",
        AttackSurfaceKind::DbQueryBoundary => "information-disclosure",
        AttackSurfaceKind::BackgroundJob => "denial-of-service",
        _ => "tampering",
    }
}

fn impact_for_risk(tier: &str) -> &'static str {
    match tier {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        _ => "low",
    }
}

fn likelihood_for_risk(tier: &str) -> &'static str {
    match tier {
        "critical" | "high" => "medium",
        _ => "low",
    }
}

fn affected_file(surface: &AttackSurface) -> Vec<Value> {
    vec![json!({
        "filePath": surface.path,
        "startLine": surface.line.unwrap_or(1),
    })]
}

fn evidence_anchor(surface: &AttackSurface) -> Vec<Value> {
    vec![json!({
        "filePath": surface.path,
        "startLine": surface.line.unwrap_or(1),
        "description": format!("{} [{}]", surface.evidence, surface_context(surface)),
        "source": "attack-surface",
    })]
}

fn persist_deterministic_document(
    flavor: BuildFlavor,
    input: &DeterministicBuildInput,
    document: &Value,
    has_concrete_content: bool,
) -> Result<bool> {
    if !flavor.persists_document() || !has_concrete_content {
        return Ok(false);
    }
    save_persistent_threat_model(&input.target, document, !input.preserve_user_edits)
}

#[allow(clippy::too_many_arguments)]
fn deterministic_response(
    input: DeterministicBuildInput,
    flavor: BuildFlavor,
    document: Value,
    normalized_artifact: PathBuf,
    markdown_artifact: PathBuf,
    persisted: bool,
    has_concrete_content: bool,
) -> Value {
    let threat_count = array_len(document.pointer("/threats"));
    let target = input.target.clone();
    let persistent_artifact = persistent_threat_model_path(&input.target);
    let artifacts = threat_model_artifacts(
        &normalized_artifact,
        &markdown_artifact,
        &persistent_artifact,
        persisted,
    );
    let summary = deterministic_summary(&input.repo_name);
    let output = deterministic_output(flavor, &input.repo_name, threat_count);
    let data = deterministic_response_data(
        input,
        document,
        normalized_artifact,
        markdown_artifact,
        persistent_artifact,
        persisted,
    );
    let warning = deterministic_warning(&target, has_concrete_content);
    let mut result =
        crate::module_result::partial_output_result(summary, output, vec![json!(warning)], data);
    result["artifacts"] = json!(artifacts);
    result["costUsd"] = json!(0.0);
    result
}

fn deterministic_warning(target: &Path, has_concrete_content: bool) -> String {
    if !has_concrete_content {
        return crate::workflow_attempts::insufficient_map_evidence_message(target);
    }
    "pipeline=deterministic explicitly requested; generated artifact-review-only threat model without a model call".to_string()
}

fn deterministic_summary(repo_name: &str) -> String {
    format!(
        "Built deterministic threat-model artifact for {repo_name} (explicitly requested; no model call)."
    )
}

fn deterministic_output(flavor: BuildFlavor, repo_name: &str, threat_count: usize) -> String {
    format!(
        "{} ran the explicitly requested deterministic pipeline for {}: {} threat(s).",
        flavor.tool_name(),
        repo_name,
        threat_count
    )
}

fn deterministic_response_data(
    input: DeterministicBuildInput,
    document: Value,
    normalized_artifact: PathBuf,
    markdown_artifact: PathBuf,
    persistent_artifact: PathBuf,
    persisted: bool,
) -> Value {
    json!({
        "target": input.target.display().to_string(),
        "repoName": input.repo_name,
        "artifactDir": input.output_dir,
        "normalizedArtifact": normalized_artifact.display().to_string(),
        "markdownArtifact": markdown_artifact.display().to_string(),
        "threatModelPath": persistent_artifact.display().to_string(),
        "provider": "deterministic",
        "methodology": input.methodology,
        "slice": input.slice,
        "stages": input.stages,
        "document": document,
        "findings": [],
        "persisted": persisted,
        "degradation": deterministic_degradation(),
    })
}
