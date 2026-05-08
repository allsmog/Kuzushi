use super::*;

pub(in crate::modules) fn attack_surface_routes(
    map: &crate::attack_surface::AttackSurfaceMap,
) -> Vec<Value> {
    map.surfaces
        .iter()
        .filter(|surface| surface.kind == crate::attack_surface::AttackSurfaceKind::HttpRoute)
        .map(|surface| {
            json!({
                "id": surface.id,
                "path": surface.route,
                "method": surface.method,
                "source": surface.path,
                "line": surface.line,
                "framework": surface.framework,
                "evidence": surface.evidence,
            })
        })
        .collect()
}

pub(in crate::modules) fn attack_surface_app_model_items(
    map: &crate::attack_surface::AttackSurfaceMap,
    kind: crate::attack_surface::AttackSurfaceKind,
) -> Vec<Value> {
    map.surfaces
        .iter()
        .filter(|surface| surface.kind == kind)
        .map(|surface| {
            json!({
                "id": surface.id,
                "kind": surface.kind.as_str(),
                "source": surface.path,
                "line": surface.line,
                "title": surface.title,
                "evidence": surface.evidence,
                "boundary": surface.boundary,
            })
        })
        .collect()
}

pub(in crate::modules) fn attack_surface_service_boundaries(
    map: &crate::attack_surface::AttackSurfaceMap,
) -> Vec<Value> {
    map.surfaces
        .iter()
        .filter(|surface| {
            matches!(
                surface.kind,
                crate::attack_surface::AttackSurfaceKind::AuthBoundary
                    | crate::attack_surface::AttackSurfaceKind::CommandExecutionBoundary
                    | crate::attack_surface::AttackSurfaceKind::FileUploadParsePath
                    | crate::attack_surface::AttackSurfaceKind::RpcHandler
            )
        })
        .map(|surface| {
            json!({
                "id": surface.id,
                "kind": surface.kind.as_str(),
                "source": surface.path,
                "line": surface.line,
                "title": surface.title,
                "route": surface.route,
                "method": surface.method,
                "boundary": surface.boundary,
            })
        })
        .collect()
}

pub(in crate::modules) fn save_context_snapshot(root: &Path, snapshot: &Value) -> Result<PathBuf> {
    let snapshot_path = root.join(".kuzushi").join("context-snapshot.json");
    if let Some(parent) = snapshot_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    let body = format!("{}\n", serde_json::to_string_pretty(snapshot)?);
    fs::write(&snapshot_path, body)
        .with_context(|| format!("Could not write {}", snapshot_path.display()))?;
    Ok(snapshot_path)
}

pub(in crate::modules) fn generated_context_slices(
    scope: &str,
    enrichment: bool,
) -> Vec<&'static str> {
    match scope {
        "repo" => vec!["repo"],
        "enrichment" => vec!["enrichment"],
        "app-model" => vec!["app-model"],
        _ if enrichment => vec!["all", "repo", "app-model", "enrichment"],
        _ => vec!["repo", "app-model"],
    }
}

pub(in crate::modules) fn stale_context_slices(scope: &str) -> Vec<&'static str> {
    match scope {
        "repo" => vec!["enrichment", "app-model"],
        "enrichment" => vec!["app-model"],
        _ => vec![],
    }
}

pub(in crate::modules) fn infer_repo_context(root: &Path, files: &[String]) -> Result<Value> {
    let mut signals = RepoContextSignals::default();
    for file in files {
        signals.ingest_file(file);
    }
    signals.inspect_manifests(root)?;
    Ok(signals.into_json())
}

#[derive(Default)]
pub(in crate::modules) struct RepoContextSignals {
    pub(in crate::modules) languages: BTreeSet<&'static str>,
    pub(in crate::modules) frameworks: BTreeSet<&'static str>,
    pub(in crate::modules) auth_patterns: BTreeSet<&'static str>,
    pub(in crate::modules) orm_or_db: BTreeSet<&'static str>,
    pub(in crate::modules) entry_points: BTreeSet<String>,
    pub(in crate::modules) sanitization_libs: BTreeSet<&'static str>,
}
