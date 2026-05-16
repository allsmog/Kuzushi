use super::*;
use super::deterministic_dfd::deterministic_dfd;
use crate::attack_surface::{
    build_attack_surface_map, line_contains_any, AttackSurface, AttackSurfaceKind,
};

pub(crate) fn build_deterministic_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<Value> {
    let input = parse_deterministic_build_input(&input, ctx, flavor)?;
    let surface_map = build_attack_surface_map(&input.target)?;
    let document = deterministic_document(&input, &surface_map.surfaces)?;
    let normalized_artifact = write_normalized_artifact(&input.target, &input.output_dir, &document)?;
    let persisted = persist_deterministic_document(flavor, &input, &document)?;
    Ok(deterministic_response(
        input,
        flavor,
        document,
        normalized_artifact,
        persisted,
    ))
}

fn deterministic_document(input: &DeterministicBuildInput, surfaces: &[AttackSurface]) -> Result<Value> {
    let threat_surfaces = deterministic_threat_surfaces(surfaces, input.max_threats);
    let document = json!({
        "version": "2.0",
        "methodology": input.methodology,
        "dfd": deterministic_dfd(surfaces),
        "threats": deterministic_threats(&threat_surfaces),
        "narrative": deterministic_narrative(&threat_surfaces),
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
        "description": format!("Deterministic threat candidate from {} at {}.", surface.kind.as_str(), surface.path),
        "attackVector": surface.route.clone().unwrap_or_else(|| surface.evidence.clone()),
        "preconditions": ["attacker can reach the recorded boundary"],
        "impact": impact_for_risk(&surface.risk.tier),
        "likelihood": likelihood_for_risk(&surface.risk.tier),
        "existingMitigations": [],
        "missingMitigations": ["Review authorization, input handling, and observability for this boundary."],
        "relatedCwe": cwe_for(surface.kind),
        "affectedFiles": affected_file(surface),
        "evidenceAnchors": evidence_anchor(surface),
    })
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
        || line_contains_any(
            &surface.evidence.to_ascii_lowercase(),
            &["req.", "request.", "params", "input"],
        )
    {
        return Some(surface.title.clone());
    }
    None
}

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
        "narrative": format!("An external actor targets {} using the recorded {} evidence.", surface.title, surface.kind.as_str()),
        "mitigation": "Confirm controls through review and, where appropriate, explicit verification.",
        "threatIds": [format!("DTM-{number:03}", number = index + 1)],
    })
}

fn deterministic_degradation() -> Value {
    json!({
        "mode": "deterministic-no-runtime",
        "reason": "agent runtime unavailable; no model call was made",
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

fn cwe_for(kind: AttackSurfaceKind) -> Vec<&'static str> {
    match kind {
        AttackSurfaceKind::HttpRoute => vec!["CWE-20"],
        AttackSurfaceKind::RpcHandler => vec!["CWE-20"],
        AttackSurfaceKind::CommandExecutionBoundary => vec!["CWE-78"],
        AttackSurfaceKind::DbQueryBoundary => vec!["CWE-89"],
        AttackSurfaceKind::DeserializationPoint => vec!["CWE-502"],
        AttackSurfaceKind::FileUploadParsePath => vec!["CWE-434"],
        AttackSurfaceKind::BackgroundJob => vec!["CWE-400"],
        AttackSurfaceKind::ExternalServiceClient => vec!["CWE-918"],
        AttackSurfaceKind::CliEntrypoint => vec!["CWE-20"],
        AttackSurfaceKind::AuthBoundary => vec!["CWE-287"],
        AttackSurfaceKind::SessionStateBoundary => vec!["CWE-384"],
        AttackSurfaceKind::RequestTrustBoundary => vec!["CWE-352"],
        AttackSurfaceKind::TenantIsolationBoundary => vec!["CWE-639"],
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
        "description": surface.evidence,
        "source": "attack-surface",
    })]
}

fn persist_deterministic_document(
    flavor: BuildFlavor,
    input: &DeterministicBuildInput,
    document: &Value,
) -> Result<bool> {
    if !flavor.persists_document() {
        return Ok(false);
    }
    save_persistent_threat_model(&input.target, document, !input.preserve_user_edits)
}

fn deterministic_response(
    input: DeterministicBuildInput,
    flavor: BuildFlavor,
    document: Value,
    normalized_artifact: PathBuf,
    persisted: bool,
) -> Value {
    let threat_count = array_len(document.pointer("/threats"));
    let persistent_artifact = input.target.join(".kuzushi").join("threat-model.json");
    let artifacts = threat_model_artifacts(&normalized_artifact, &persistent_artifact, persisted);
    json!({
        "ok": true,
        "status": "partial",
        "summary": format!("Built deterministic threat-model artifact for {} without LLM runtime.", input.repo_name),
        "output": format!("{} degraded deterministically for {}: {} threat(s).", flavor.tool_name(), input.repo_name, threat_count),
        "artifacts": artifacts,
        "warnings": ["agent runtime unavailable; generated artifact-review-only threat model"],
        "errors": [],
        "data": {
            "target": input.target.display().to_string(),
            "repoName": input.repo_name,
            "artifactDir": input.output_dir,
            "normalizedArtifact": normalized_artifact.display().to_string(),
            "threatModelPath": persistent_artifact.display().to_string(),
            "provider": "deterministic",
            "methodology": input.methodology,
            "slice": input.slice,
            "stages": input.stages,
            "document": document,
            "findings": [],
            "persisted": persisted,
            "degradation": deterministic_degradation(),
        },
        "costUsd": 0.0,
    })
}
