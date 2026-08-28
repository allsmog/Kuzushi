use super::deterministic_dfd::deterministic_dfd;
use super::deterministic_route_context::{
    authorization_flow_input, callback_flow_input, credential_flow_input, cwe_for_surface,
    data_egress_input, file_ingest_input,
};
use super::*;
use crate::attack_surface::{
    build_attack_surface_map, line_contains_any, AttackSurface, AttackSurfaceKind,
};

pub(crate) const DETERMINISTIC_ENTRY_POINT_SELECTION_POLICY: &str = "deterministic-threat-fold-v1";
const DETERMINISTIC_COVERAGE_METHOD: &str = "deterministic-stable-id-fold-v1";

pub(crate) fn build_deterministic_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<Value> {
    let use_entry_point_catalog = deterministic_catalog_enabled(&input);
    let input = parse_deterministic_build_input(&input, ctx, flavor)?;
    preflight_deterministic_build_lineage(&input)?;
    let surfaces = scoped_attack_surfaces(&input)?;
    let document = prepare_deterministic_document(&input, &surfaces, use_entry_point_catalog)?;
    let has_concrete_content =
        crate::workflow_attempts::threat_model_has_concrete_content(&document);
    let (normalized_artifact, markdown_artifact) =
        write_deterministic_artifacts(&input, &document)?;
    let model_ref = persist_and_record_deterministic_document(
        ctx,
        flavor,
        &input,
        &document,
        has_concrete_content,
    )?;
    let persisted = model_ref.is_some();
    Ok(deterministic_response(
        input,
        flavor,
        document,
        normalized_artifact,
        markdown_artifact,
        persisted,
        model_ref,
        has_concrete_content,
    ))
}

fn preflight_deterministic_build_lineage(input: &DeterministicBuildInput) -> Result<()> {
    let scope = input
        .roots
        .scope
        .clone()
        .map(Ok)
        .unwrap_or_else(|| root_scope_ref(input.workspace_root()))?;
    resolve_build_lineage_selection(
        input.workspace_root(),
        &scope,
        &input.methodology,
        input.model_id.as_ref(),
        input.new_model,
        false,
        true,
    )?;
    Ok(())
}

fn persist_and_record_deterministic_document(
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    input: &DeterministicBuildInput,
    document: &Value,
    has_concrete_content: bool,
) -> Result<Option<ThreatModelRef>> {
    let model_ref = persist_deterministic_document(
        flavor,
        input,
        document,
        has_concrete_content,
        ctx.run_id().as_deref(),
    )?;
    let warning = record_persisted_version(
        ctx,
        input.workspace_root(),
        document,
        "deterministic",
        model_ref.is_some(),
        model_ref.as_ref(),
    );
    emit_deterministic_version_warning(ctx, warning);
    Ok(model_ref)
}

fn emit_deterministic_version_warning(ctx: &ToolExecutionContext<'_>, warning: Option<String>) {
    let (Some(trace), Some(warning)) = (ctx.trace, warning) else {
        return;
    };
    let _ = trace.step("tool-progress", "build", warning).emit();
}

fn scoped_attack_surfaces(input: &DeterministicBuildInput) -> Result<Vec<AttackSurface>> {
    let mut surfaces = build_attack_surface_map(input.analysis_root())?.surfaces;
    let Some(scope) = input.roots.scope.as_ref() else {
        return Ok(surfaces);
    };
    if scope.rel_path == Path::new(".") {
        return Ok(surfaces);
    }
    for surface in &mut surfaces {
        surface.path = scope
            .rel_path
            .join(&surface.path)
            .to_string_lossy()
            .replace('\\', "/");
        surface.id = crate::workspace::attack_surface::attack_surface_id(surface);
    }
    Ok(surfaces)
}

fn prepare_deterministic_document(
    input: &DeterministicBuildInput,
    surfaces: &[AttackSurface],
    use_entry_point_catalog: bool,
) -> Result<Value> {
    let selected = deterministic_threat_surfaces(surfaces, input.max_threats);
    let catalog = deterministic_entry_point_grounding(
        input,
        &selected,
        input.max_threats,
        use_entry_point_catalog,
    )?;
    let mut document = deterministic_document(input, surfaces, &selected)?;
    // Match the model-backed provenance contract while keeping this
    // runtime-free fold explicit and revision-bound.
    stamp_provenance(&mut document, input.workspace_root(), "deterministic");
    finalize_deterministic_entry_points(&mut document, &selected, &catalog)?;
    require_complete_security_context_links(&document)?;
    Ok(document)
}

fn deterministic_catalog_enabled(input: &Value) -> bool {
    let context_off = read_string(input, &["contextMode", "context_mode"])
        .is_some_and(|mode| mode.eq_ignore_ascii_case("off"));
    let sources_none = read_string_list(input, &["sources", "sourceArtifacts", "source_artifacts"])
        .iter()
        .any(|source| source.eq_ignore_ascii_case("none"));
    !context_off && !sources_none
}

fn deterministic_entry_point_grounding(
    input: &DeterministicBuildInput,
    selected: &[AttackSurface],
    grounding_limit: usize,
    enabled: bool,
) -> Result<crate::capabilities::entry_points::EntryPointCatalogGrounding> {
    if input
        .roots
        .scope
        .as_ref()
        .is_some_and(|scope| scope.rel_path != Path::new("."))
    {
        let mut grounding =
            crate::capabilities::entry_points::EntryPointCatalogGrounding::unavailable(
                "scoped-derived",
            );
        stamp_deterministic_selection(&mut grounding, grounding_limit, selected.len());
        return Ok(grounding);
    }
    if !enabled {
        let mut grounding =
            crate::capabilities::entry_points::EntryPointCatalogGrounding::unavailable("disabled");
        stamp_deterministic_selection(&mut grounding, grounding_limit, selected.len());
        return Ok(grounding);
    }
    let resolution = crate::capabilities::entry_points::ensure_current_entry_point_catalog(
        input.workspace_root(),
    )?;
    Ok(deterministic_catalog_grounding(
        &resolution,
        selected,
        grounding_limit,
    ))
}

fn deterministic_catalog_grounding(
    resolution: &crate::capabilities::entry_points::EntryPointCatalogResolution,
    selected: &[AttackSurface],
    grounding_limit: usize,
) -> crate::capabilities::entry_points::EntryPointCatalogGrounding {
    let Some(catalog) = resolution.catalog.as_ref() else {
        let mut grounding =
            crate::capabilities::entry_points::EntryPointCatalogGrounding::unavailable(
                &resolution.status,
            );
        stamp_deterministic_selection(&mut grounding, grounding_limit, selected.len());
        return grounding;
    };
    let catalog_ids = catalog
        .entry_points
        .iter()
        .map(|entry| entry.surface.id.clone())
        .collect::<BTreeSet<_>>();
    let records_selected = selected
        .iter()
        .filter(|surface| catalog_ids.contains(&surface.id))
        .count();
    crate::capabilities::entry_points::EntryPointCatalogGrounding {
        receipt: deterministic_catalog_receipt(
            catalog,
            &resolution.status,
            records_selected,
            grounding_limit,
            selected.len(),
        ),
        catalog_ids,
        catalog_surfaces: catalog
            .entry_points
            .iter()
            .map(|entry| entry.surface.clone())
            .collect(),
    }
}

fn stamp_deterministic_selection(
    grounding: &mut crate::capabilities::entry_points::EntryPointCatalogGrounding,
    grounding_limit: usize,
    selected: usize,
) {
    grounding.receipt.selection_policy = DETERMINISTIC_ENTRY_POINT_SELECTION_POLICY.to_string();
    grounding.receipt.grounding_limit = grounding_limit;
    grounding.receipt.grounding_records_selected = selected;
}

fn deterministic_catalog_receipt(
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
    status: &str,
    records_selected: usize,
    grounding_limit: usize,
    grounding_records_selected: usize,
) -> crate::capabilities::entry_points::EntryPointCatalogReceipt {
    crate::capabilities::entry_points::EntryPointCatalogReceipt {
        status: status.to_string(),
        sha256: Some(catalog.provenance.sha256.clone()),
        records: catalog.total,
        records_selected,
        grounding_limit,
        grounding_records_selected,
        snapshot_timestamp: Some(catalog.snapshot_timestamp),
        context_sha256: Some(catalog.provenance.context_snapshot_sha256.clone()),
        tree_hash: catalog.provenance.context_snapshot_tree_hash.clone(),
        selection_policy: DETERMINISTIC_ENTRY_POINT_SELECTION_POLICY.to_string(),
        revision: catalog.provenance.revision.clone(),
        revision_dirty: catalog.provenance.revision_dirty,
    }
}

fn finalize_deterministic_entry_points(
    document: &mut Value,
    selected: &[AttackSurface],
    catalog: &crate::capabilities::entry_points::EntryPointCatalogGrounding,
) -> Result<()> {
    let coverage = check_coverage(document, selected);
    anyhow::ensure!(
        coverage.invariant_satisfied(),
        "deterministic entry-point fold left {} stable-id coverage gap(s)",
        coverage.gaps.len()
    );
    apply_coverage(document, &coverage, DETERMINISTIC_COVERAGE_METHOD, 0);
    stamp_entry_point_catalog_receipt(document, catalog);
    Ok(())
}

fn write_deterministic_artifacts(
    input: &DeterministicBuildInput,
    document: &Value,
) -> Result<(PathBuf, PathBuf)> {
    let normalized =
        write_normalized_artifact(input.workspace_root(), &input.output_dir, document)?;
    let markdown = render_schema_markdown(
        document,
        &input.repo_name,
        &input.workspace_root().display().to_string(),
    );
    let rendered = write_markdown_artifact(
        input.workspace_root(),
        &input.output_dir,
        "THREAT_MODEL.md",
        &markdown,
    )?;
    Ok((normalized, rendered))
}

fn deterministic_document(
    input: &DeterministicBuildInput,
    surfaces: &[AttackSurface],
    threat_surfaces: &[AttackSurface],
) -> Result<Value> {
    let narrative_surfaces = surfaces.iter().collect::<Vec<_>>();
    let document = json!({
        "version": "2.0",
        "methodology": input.methodology,
        "dfd": deterministic_dfd(surfaces),
        "threats": deterministic_threats(threat_surfaces),
        "attackSurface": {"entryPoints": deterministic_entry_points(threat_surfaces)},
        "narrative": deterministic_narrative(&narrative_surfaces),
        "degradation": deterministic_degradation(),
    });
    apply_methodology(
        normalize_document(document, &input.methodology)?,
        &input.methodology,
    )
}

pub(crate) fn deterministic_threat_surfaces(
    surfaces: &[AttackSurface],
    max_threats: usize,
) -> Vec<AttackSurface> {
    surfaces
        .iter()
        .filter(|surface| emits_deterministic_threat(surface))
        .take(max_threats)
        .cloned()
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

fn deterministic_threats(surfaces: &[AttackSurface]) -> Vec<Value> {
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
        "entryPointIds": [surface.id.clone()],
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

fn deterministic_entry_points(surfaces: &[AttackSurface]) -> Vec<Value> {
    surfaces.iter().map(deterministic_entry_point).collect()
}

fn deterministic_entry_point(surface: &AttackSurface) -> Value {
    json!({
        "id": surface.id,
        "targetElementIds": target_element_ids_for(surface.kind),
        "name": surface.title,
        "kind": surface.kind.as_str(),
        "path": surface.path,
        "line": surface.line,
        "language": surface.language,
        "framework": surface.framework,
        "method": surface.method,
        "route": surface.route,
        "boundary": surface.boundary,
        "evidence": surface.evidence,
        "risk": surface.risk,
        "description": deterministic_threat_description(surface),
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
    surfaces
        .iter()
        .filter_map(|surface| mapper(surface))
        .collect()
}

fn attacker_controlled_input(surface: &AttackSurface) -> Option<String> {
    if surface.route.is_some()
        || line_contains_any(
            &surface.evidence.to_ascii_lowercase(),
            REQUEST_INPUT_EVIDENCE,
        )
    {
        return Some(surface.title.clone());
    }
    None
}

const REQUEST_INPUT_EVIDENCE: &[&str] = &[
    "$request",
    "$_",
    "@request",
    "cookies[",
    "cookies.signed",
    "formvalue(",
    "json<",
    "cookies.get(",
    "headers.get(",
    "params",
    "query<",
    "r.body",
    "r.cookie(",
    "r.header.get(",
    "req.",
    "request.",
    "input",
    "iformfile",
    "request.cookies",
    "[frombody",
    "[fromform",
    "[fromheader",
    "[fromquery",
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
    run_id: Option<&str>,
) -> Result<Option<ThreatModelRef>> {
    if !flavor.persists_document() || !has_concrete_content {
        return Ok(None);
    }
    let scope = input
        .roots
        .scope
        .clone()
        .map(Ok)
        .unwrap_or_else(|| root_scope_ref(input.workspace_root()))?;
    let selection = BuildRevisionSelection {
        workspace_root: input.workspace_root().to_path_buf(),
        label: deterministic_model_label(input, &scope),
        scope,
        methodology: input.methodology.clone(),
        model_id: input.model_id.clone(),
        new_model: input.new_model,
        fresh: true,
        activate: input.activate,
        source: ThreatModelRevisionSource::Build,
        run_id: run_id.map(str::to_string),
        actor: "tool:threat-model:build".to_string(),
    };
    if should_preserve_selected_user_edited_model(&selection, input.preserve_user_edits)? {
        return Ok(None);
    }
    Ok(Some(commit_generated_threat_model_revision(
        document, selection,
    )?))
}

fn deterministic_model_label(input: &DeterministicBuildInput, scope: &ScopeRef) -> String {
    if scope.scope_id == crate::workspace::ROOT_SCOPE_ID {
        format!(
            "{} {}",
            input.repo_name,
            input.methodology.to_ascii_uppercase()
        )
    } else {
        format!(
            "{} · {}",
            scope.rel_path.display(),
            input.methodology.to_ascii_uppercase()
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn deterministic_response(
    input: DeterministicBuildInput,
    flavor: BuildFlavor,
    document: Value,
    normalized_artifact: PathBuf,
    markdown_artifact: PathBuf,
    persisted: bool,
    model_ref: Option<ThreatModelRef>,
    has_concrete_content: bool,
) -> Value {
    let threat_count = array_len(document.pointer("/threats"));
    let target = input.workspace_root().to_path_buf();
    let persistent_artifact = persistent_threat_model_path(input.workspace_root());
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
        model_ref,
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
    model_ref: Option<ThreatModelRef>,
) -> Value {
    json!({
        "target": input.workspace_root().display().to_string(),
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
        "modelRef": model_ref,
        "degradation": deterministic_degradation(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_input(target: &Path) -> DeterministicBuildInput {
        DeterministicBuildInput {
            roots: ThreatModelBuildRoots {
                workspace_root: target.to_path_buf(),
                analysis_root: target.to_path_buf(),
                scope: None,
            },
            repo_name: "fixture".to_string(),
            methodology: "stride".to_string(),
            slice: "all".to_string(),
            stages: vec!["dfd".to_string()],
            output_dir: ".kuzushi/test-artifacts".to_string(),
            max_threats: 5,
            preserve_user_edits: true,
            model_id: None,
            new_model: false,
            activate: None,
        }
    }

    fn route_surface() -> AttackSurface {
        let mut surface = AttackSurface {
            id: String::new(),
            kind: AttackSurfaceKind::HttpRoute,
            path: "src/api.rs".to_string(),
            line: Some(42),
            language: "rust".to_string(),
            framework: Some("axum".to_string()),
            title: "POST /oauth/callback".to_string(),
            evidence: "router.route".to_string(),
            method: Some("POST".to_string()),
            route: Some("/oauth/callback".to_string()),
            boundary: Some("public_http".to_string()),
            risk: crate::attack_surface::AttackSurfaceRisk {
                rank: 1,
                score: 80,
                tier: "high".to_string(),
                reasons: vec!["public route".to_string()],
            },
            metadata: json!({"handler": "oauth_callback"}),
        };
        surface.id = crate::workspace::attack_surface::attack_surface_id(&surface);
        surface
    }

    fn deterministic_test_document(target: &Path) -> (Value, Vec<AttackSurface>) {
        let surfaces = vec![route_surface()];
        let selected = deterministic_threat_surfaces(&surfaces, 5);
        let document = deterministic_document(&build_input(target), &surfaces, &selected).unwrap();
        (document, selected)
    }

    #[test]
    fn selected_surfaces_use_the_same_stable_id_in_inventory_and_threats() {
        let target = tempfile::tempdir().unwrap();
        let (mut document, selected) = deterministic_test_document(target.path());
        let grounding =
            deterministic_entry_point_grounding(&build_input(target.path()), &selected, 5, true)
                .unwrap();

        finalize_deterministic_entry_points(&mut document, &selected, &grounding).unwrap();

        assert_eq!(
            document["threats"][0]["entryPointIds"],
            json!([selected[0].id.clone()])
        );
        assert_eq!(
            document["attackSurface"]["entryPoints"][0]["id"],
            json!(selected[0].id.clone())
        );
        assert_eq!(
            document["attackSurface"]["entryPoints"][0]["targetElementIds"],
            json!(["http-route"])
        );
        assert_eq!(document["coverage"]["entryPointsConsidered"], json!(1));
        assert_eq!(document["coverage"]["entryPointsCovered"], json!(1));
        assert_eq!(document["coverage"]["invariantSatisfied"], json!(true));
        assert_eq!(
            document["provenance"]["entryPointCatalog"]["status"],
            json!("missing")
        );
        require_complete_security_context_links(&document).unwrap();
    }

    #[test]
    fn current_typed_catalog_stamps_digest_and_exact_link_counts() {
        let target = tempfile::tempdir().unwrap();
        let surface = route_surface();
        let tree_hash =
            crate::incremental_index::current_workspace_tree_hash(target.path()).unwrap();
        let snapshot = json!({
            "target": target.path().display().to_string(),
            "timestamp": 123,
            "provenance": {"treeHash": tree_hash},
            "attackSurfaceMap": {"surfaces": [surface]},
        });
        let path = crate::context::context_snapshot_path(target.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&snapshot).unwrap()).unwrap();
        let (mut document, selected) = deterministic_test_document(target.path());

        let grounding =
            deterministic_entry_point_grounding(&build_input(target.path()), &selected, 5, true)
                .unwrap();
        finalize_deterministic_entry_points(&mut document, &selected, &grounding).unwrap();

        let receipt = &document["provenance"]["entryPointCatalog"];
        assert_eq!(receipt["status"], json!("refreshed"));
        assert!(receipt["sha256"].as_str().unwrap().starts_with("sha256:"));
        assert_eq!(receipt["records"], json!(1));
        assert_eq!(receipt["recordsSelected"], json!(1));
        assert_eq!(receipt["groundingLimit"], json!(5));
        assert_eq!(receipt["groundingRecordsSelected"], json!(1));
        assert_eq!(
            receipt["selectionPolicy"],
            json!(DETERMINISTIC_ENTRY_POINT_SELECTION_POLICY)
        );
        assert_eq!(document["coverage"]["catalogEntryPointsTotal"], json!(1));
        assert_eq!(document["coverage"]["catalogEntryPointsSelected"], json!(1));
        assert_eq!(document["coverage"]["catalogEntryPointsLinked"], json!(1));
    }

    #[test]
    fn scoped_deterministic_grounding_never_claims_the_workspace_catalog() {
        let target = tempfile::tempdir().unwrap();
        let analysis_root = target.path().join("services/api");
        fs::create_dir_all(&analysis_root).unwrap();
        let mut input = build_input(target.path());
        input.roots.analysis_root = analysis_root;
        input.roots.scope = Some(ScopeRef {
            scope_id: "scope_api".to_string(),
            rel_path: PathBuf::from("services/api"),
            project_model_sha256: format!("sha256:{}", "a".repeat(64)),
            target_revision: "fixture".to_string(),
        });
        let selected = vec![route_surface()];

        let grounding = deterministic_entry_point_grounding(&input, &selected, 5, true).unwrap();

        assert_eq!(grounding.receipt.status, "scoped-derived");
        assert_eq!(grounding.receipt.records, 0);
        assert!(grounding.catalog_ids.is_empty());
        assert!(grounding.catalog_surfaces.is_empty());
    }

    #[test]
    fn deterministic_preflight_accepts_stale_scope_without_explicit_lineage() {
        let target = tempfile::tempdir().unwrap();
        let stored_scope = deterministic_scope("tree-a");
        let stored = commit_deterministic_lineage(target.path(), stored_scope.clone());
        let mut input = build_input(target.path());
        let mut current_scope = stored_scope;
        current_scope.project_model_sha256 = "tree-b".to_string();
        input.roots.scope = Some(current_scope);

        preflight_deterministic_build_lineage(&input).unwrap();
        input.model_id = Some(stored.model_id);
        let error = preflight_deterministic_build_lineage(&input).unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match the requested scope and methodology"));
    }

    fn deterministic_scope(binding: &str) -> ScopeRef {
        ScopeRef {
            scope_id: "scope_api".to_string(),
            rel_path: PathBuf::from("services/api"),
            project_model_sha256: binding.to_string(),
            target_revision: "fixture".to_string(),
        }
    }

    fn commit_deterministic_lineage(root: &Path, scope: ScopeRef) -> ThreatModelRef {
        commit_threat_model_revision(
            root,
            &json!({
                "version": "2.0",
                "methodology": "stride",
                "dfd": {"nodes": [{"id": "app"}], "flows": [], "trustBoundaries": []},
                "threats": [],
                "summary": {}
            }),
            ThreatModelCommit {
                model_id: None,
                new_model: false,
                label: "fixture".to_string(),
                scope,
                methodology: "stride".to_string(),
                source: ThreatModelRevisionSource::Build,
                source_revision_id: None,
                run_id: None,
                activate: Some(false),
                actor: "test".to_string(),
            },
        )
        .unwrap()
        .model_ref
    }

    #[test]
    fn stable_id_verification_rejects_a_path_substituted_for_the_id() {
        let target = tempfile::tempdir().unwrap();
        let (mut document, selected) = deterministic_test_document(target.path());
        document["threats"][0]["entryPointIds"] = json!(["src/api.rs"]);
        let grounding =
            crate::capabilities::entry_points::EntryPointCatalogGrounding::unavailable("missing");

        let error = finalize_deterministic_entry_points(&mut document, &selected, &grounding)
            .unwrap_err()
            .to_string();

        assert!(error.contains("stable-id coverage gap"), "{error}");
    }
}
