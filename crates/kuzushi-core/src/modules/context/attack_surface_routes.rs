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
                    | crate::attack_surface::AttackSurfaceKind::SessionStateBoundary
                    | crate::attack_surface::AttackSurfaceKind::RequestTrustBoundary
                    | crate::attack_surface::AttackSurfaceKind::TenantIsolationBoundary
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

pub(in crate::modules) fn save_context_snapshot(
    root: &Path,
    snapshot: &mut Value,
) -> Result<PathBuf> {
    let path = crate::context::context_snapshot_path(root);
    let relative = path
        .strip_prefix(root)
        .context("Context snapshot path escaped the workspace")?;
    let body = bounded_snapshot_body(snapshot, SNAPSHOT_WRITE_BUDGET)?;
    crate::workspace::write_workspace_state_file(root, relative, body.as_bytes())
}

/// Every snapshot consumer reads through the MAX_CONTEXT_SNAPSHOT_BYTES
/// bound, so a write over that budget produces an artifact kz itself
/// rejects (`ctx:malformed` on monorepo-scale targets). Margin covers the
/// trailing newline and filesystem rounding.
const SNAPSHOT_WRITE_BUDGET: usize = crate::context::MAX_CONTEXT_SNAPSHOT_BYTES - 1024;

const SNAPSHOT_ARRAY_CAPS: [usize; 11] =
    [50_000, 20_000, 10_000, 5_000, 2_000, 1_000, 500, 200, 100, 50, 20];

/// Serialize within `budget`: an oversized snapshot has its arrays capped at
/// the largest cap that fits, mutated in place so the caller's response and
/// partial-coverage flag match what was persisted. Truncation is explicit —
/// `/repositoryInventory/truncation` drives the existing partial marker.
fn bounded_snapshot_body(snapshot: &mut Value, budget: usize) -> Result<String> {
    let body = pretty_snapshot_body(snapshot)?;
    if body.len() <= budget {
        return Ok(body);
    }
    let mut omitted: u64 = 0;
    for cap in SNAPSHOT_ARRAY_CAPS {
        omitted += cap_arrays_in_place(snapshot, cap);
        mark_snapshot_truncation(snapshot, cap, omitted);
        let body = pretty_snapshot_body(snapshot)?;
        if body.len() <= budget {
            return Ok(body);
        }
    }
    anyhow::bail!(
        "context snapshot exceeds the {budget}-byte write budget even with \
         arrays capped at {} entries",
        SNAPSHOT_ARRAY_CAPS[SNAPSHOT_ARRAY_CAPS.len() - 1]
    )
}

fn pretty_snapshot_body(snapshot: &Value) -> Result<String> {
    Ok(format!("{}\n", serde_json::to_string_pretty(snapshot)?))
}

fn cap_arrays_in_place(value: &mut Value, cap: usize) -> u64 {
    match value {
        Value::Array(items) => {
            let dropped = items.len().saturating_sub(cap) as u64;
            items.truncate(cap);
            dropped + items.iter_mut().map(|item| cap_arrays_in_place(item, cap)).sum::<u64>()
        }
        Value::Object(map) => map
            .values_mut()
            .map(|value| cap_arrays_in_place(value, cap))
            .sum(),
        _ => 0,
    }
}

fn mark_snapshot_truncation(snapshot: &mut Value, cap: usize, omitted: u64) {
    let marker = json!({
        "reason": "snapshot byte budget",
        "arrayCap": cap,
        "omittedEntries": omitted,
    });
    if let Some(inventory) = snapshot
        .get_mut("repositoryInventory")
        .and_then(Value::as_object_mut)
    {
        inventory.insert("truncation".to_string(), marker.clone());
    }
    if let Some(object) = snapshot.as_object_mut() {
        object.insert("snapshotTruncation".to_string(), marker);
    }
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

#[cfg(test)]
mod snapshot_budget_tests {
    use super::*;

    fn oversized_snapshot() -> Value {
        let entries: Vec<Value> = (0..200)
            .map(|index| json!({"path": format!("src/module/file_{index}.rs")}))
            .collect();
        json!({
            "repositoryInventory": {"sourceFiles": entries.clone()},
            "attackSurfaceMap": {"surfaces": entries},
        })
    }

    #[test]
    fn snapshot_within_budget_is_written_verbatim_without_markers() {
        let mut snapshot = json!({"repositoryInventory": {"sourceFiles": []}});
        let body = bounded_snapshot_body(&mut snapshot, 1024 * 1024).unwrap();

        assert!(body.ends_with('\n'));
        assert!(snapshot.get("snapshotTruncation").is_none());
        assert!(snapshot["repositoryInventory"].get("truncation").is_none());
    }

    /// A snapshot over the reader budget must come back under it with the
    /// arrays capped and the truncation stated — never as a file the
    /// context feed will reject as malformed.
    #[test]
    fn oversized_snapshot_is_capped_under_budget_and_marked_partial() {
        let mut snapshot = oversized_snapshot();
        let budget = 4 * 1024;

        let body = bounded_snapshot_body(&mut snapshot, budget).unwrap();

        assert!(body.len() <= budget, "body still {} bytes", body.len());
        let written: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(written, snapshot, "disk and in-memory snapshot must match");
        let marker = &snapshot["snapshotTruncation"];
        assert_eq!(marker["reason"], json!("snapshot byte budget"));
        assert!(marker["omittedEntries"].as_u64().unwrap() > 0);
        // The existing partial-coverage flag keys off this pointer.
        assert!(snapshot
            .pointer("/repositoryInventory/truncation")
            .is_some_and(|value| !value.is_null()));
        let surfaces = snapshot["attackSurfaceMap"]["surfaces"].as_array().unwrap();
        assert!(surfaces.len() < 200);
    }

    #[test]
    fn impossible_budget_fails_loudly_instead_of_writing_unreadable_state() {
        let mut snapshot = oversized_snapshot();

        let error = bounded_snapshot_body(&mut snapshot, 16).unwrap_err();

        assert!(error.to_string().contains("write budget"));
    }
}
