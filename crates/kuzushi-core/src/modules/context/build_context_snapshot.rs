use super::*;

pub(in crate::modules) fn build_context_snapshot(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("context:build requires a workspace target")?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "build",
                format!(
                    "context:build start · target={}",
                    workspace.root().display()
                ),
            )
            .emit();
    }
    let sample_limit = input
        .get("sampleLimit")
        .or_else(|| input.get("limit"))
        .and_then(Value::as_u64)
        .unwrap_or(200)
        .min(2_000) as usize;
    let discovery = input
        .get("discovery")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "auto" | "flat" | "modules"))
        .unwrap_or("auto");
    let enrichment = input
        .get("enrichment")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if enrichment {
        anyhow::bail!(
            "context:build Rust native executor does not support LLM enrichment yet; run with {{\"enrichment\":false}} or use a pi-agent-core-backed context adapter once configured"
        );
    }
    let scope = input
        .get("scope")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "all" | "repo" | "enrichment" | "app-model"))
        .unwrap_or("all");

    let mut files_sample = Vec::new();
    let mut files_indexed = 0usize;
    collect_context_files(
        workspace.root(),
        workspace.root(),
        sample_limit,
        &mut files_indexed,
        &mut files_sample,
    )?;

    let repo_context = infer_repo_context(workspace.root(), &files_sample)?;
    let repository_inventory =
        crate::repository_inventory::build_repository_inventory(workspace.root())?;
    let attack_surface_map = crate::attack_surface::build_attack_surface_map_from_inventory(
        workspace.root(),
        &repository_inventory,
    )?;
    let app_model_routes = attack_surface_routes(&attack_surface_map);
    let app_model_background_jobs = attack_surface_app_model_items(
        &attack_surface_map,
        crate::attack_surface::AttackSurfaceKind::BackgroundJob,
    );
    let app_model_data_stores = attack_surface_app_model_items(
        &attack_surface_map,
        crate::attack_surface::AttackSurfaceKind::DbQueryBoundary,
    );
    let app_model_service_boundaries = attack_surface_service_boundaries(&attack_surface_map);
    let file_tree = files_sample
        .iter()
        .map(|path| json!({ "path": path }))
        .collect::<Vec<_>>();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis() as u64;
    let snapshot = json!({
        "target": workspace.root().display().to_string(),
        "timestamp": now_ms,
        "discovery": discovery,
        "options": {
            "enrichment": enrichment,
        },
        "repoContext": repo_context,
        "repositoryInventory": repository_inventory,
        "attackSurfaceMap": attack_surface_map,
        "fileIndex": {
            "tree": file_tree,
            "totalFiles": files_indexed,
            "truncated": files_indexed > files_sample.len(),
            "patternMatches": {},
        },
        "appModel": {
            "routes": app_model_routes,
            "outboundClients": [],
            "serviceBoundaries": app_model_service_boundaries,
            "dataStores": app_model_data_stores,
            "backgroundJobs": app_model_background_jobs,
        },
        "generatedSlices": generated_context_slices(scope, enrichment),
        "staleSlices": stale_context_slices(scope),
        "scanner": "native-context-lite",
        "filesIndexed": files_indexed,
        "filesSample": files_sample,
    });

    let snapshot_path = save_context_snapshot(workspace.root(), &snapshot)?;
    let output = format!(
        "context:build indexed {} file{} under {}\n  Snapshot: {}",
        files_indexed,
        if files_indexed == 1 { "" } else { "s" },
        workspace.root().display(),
        snapshot_path.display()
    );
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "build",
                format!("context:build complete · {} files indexed", files_indexed),
            )
            .emit();
    }

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "root": workspace.root().display().to_string(),
            "stateDir": workspace.state_dir().display().to_string(),
            "snapshotPath": snapshot_path.display().to_string(),
            "snapshot": snapshot,
        },
    }))
}
