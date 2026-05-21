use super::*;

pub(in crate::modules) fn build_context_snapshot(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("context:build requires a workspace target")?;
    let options = context_build_options(&input)?;

    emit_context_build_start(ctx, workspace.root());
    let file_sample = collect_context_file_sample(workspace.root(), options.sample_limit)?;
    let snapshot = context_snapshot_value(workspace.root(), &options, &file_sample)?;
    let snapshot_path = save_context_snapshot(workspace.root(), &snapshot)?;
    emit_context_build_done(ctx, file_sample.files_indexed);
    let state_dir = workspace.state_dir();

    Ok(context_build_response(
        workspace.root(),
        &state_dir,
        &snapshot_path,
        snapshot,
        file_sample.files_indexed,
    ))
}

struct ContextBuildOptions {
    sample_limit: usize,
    discovery: String,
    enrichment: bool,
    scope: String,
}

struct ContextFileSample {
    files_indexed: usize,
    files_sample: Vec<String>,
}

fn context_build_options(input: &Value) -> Result<ContextBuildOptions> {
    let enrichment = read_enrichment(input);
    reject_enrichment(enrichment)?;
    Ok(ContextBuildOptions {
        sample_limit: read_sample_limit(input),
        discovery: read_discovery(input),
        enrichment,
        scope: read_scope(input),
    })
}

fn read_sample_limit(input: &Value) -> usize {
    input
        .get("sampleLimit")
        .or_else(|| input.get("limit"))
        .and_then(Value::as_u64)
        .unwrap_or(200)
        .min(2_000) as usize
}

fn read_discovery(input: &Value) -> String {
    input
        .get("discovery")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "auto" | "flat" | "modules"))
        .unwrap_or("auto")
        .to_string()
}

fn read_enrichment(input: &Value) -> bool {
    input
        .get("enrichment")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn read_scope(input: &Value) -> String {
    input
        .get("scope")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "all" | "repo" | "enrichment" | "app-model"))
        .unwrap_or("all")
        .to_string()
}

fn reject_enrichment(enrichment: bool) -> Result<()> {
    if enrichment {
        anyhow::bail!(
            "context:build Rust native executor does not support LLM enrichment yet; run with {{\"enrichment\":false}} or use a pi-agent-core-backed context adapter once configured"
        );
    }
    Ok(())
}

fn collect_context_file_sample(root: &Path, sample_limit: usize) -> Result<ContextFileSample> {
    let mut files_sample = Vec::new();
    let mut files_indexed = 0;
    collect_context_files(
        root,
        root,
        sample_limit,
        &mut files_indexed,
        &mut files_sample,
    )?;
    Ok(ContextFileSample {
        files_indexed,
        files_sample,
    })
}

fn context_snapshot_value(
    root: &Path,
    options: &ContextBuildOptions,
    file_sample: &ContextFileSample,
) -> Result<Value> {
    let repo_context = infer_repo_context(root, &file_sample.files_sample)?;
    let repository_inventory = crate::repository_inventory::build_repository_inventory(root)?;
    let attack_surface_map = crate::attack_surface::build_attack_surface_map_from_inventory(
        root,
        &repository_inventory,
    )?;
    Ok(json!({
        "target": root.display().to_string(),
        "timestamp": now_ms()?,
        "discovery": options.discovery,
        "options": {
            "enrichment": options.enrichment,
        },
        "repoContext": repo_context,
        "repositoryInventory": repository_inventory,
        "attackSurfaceMap": attack_surface_map,
        "fileIndex": file_index(file_sample),
        "appModel": app_model(&attack_surface_map),
        "generatedSlices": generated_context_slices(&options.scope, options.enrichment),
        "staleSlices": stale_context_slices(&options.scope),
        "scanner": "native-context-lite",
        "filesIndexed": file_sample.files_indexed,
        "filesSample": file_sample.files_sample,
    }))
}

fn file_index(file_sample: &ContextFileSample) -> Value {
    json!({
        "tree": file_tree(&file_sample.files_sample),
        "totalFiles": file_sample.files_indexed,
        "truncated": file_sample.files_indexed > file_sample.files_sample.len(),
        "patternMatches": {},
    })
}

fn file_tree(files_sample: &[String]) -> Vec<Value> {
    files_sample
        .iter()
        .map(|path| json!({ "path": path }))
        .collect()
}

fn app_model(map: &crate::attack_surface::AttackSurfaceMap) -> Value {
    json!({
        "routes": attack_surface_routes(map),
        "outboundClients": app_model_items(map, crate::attack_surface::AttackSurfaceKind::ExternalServiceClient),
        "serviceBoundaries": attack_surface_service_boundaries(map),
        "dataStores": app_model_items(map, crate::attack_surface::AttackSurfaceKind::DbQueryBoundary),
        "backgroundJobs": app_model_items(map, crate::attack_surface::AttackSurfaceKind::BackgroundJob),
    })
}

fn app_model_items(
    map: &crate::attack_surface::AttackSurfaceMap,
    kind: crate::attack_surface::AttackSurfaceKind,
) -> Vec<Value> {
    attack_surface_app_model_items(map, kind)
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis() as u64)
}

fn emit_context_build_start(ctx: &ToolExecutionContext<'_>, root: &Path) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "build",
                format!("context:build start · target={}", root.display()),
            )
            .emit();
    }
}

fn emit_context_build_done(ctx: &ToolExecutionContext<'_>, files_indexed: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "build",
                format!("context:build complete · {} files indexed", files_indexed),
            )
            .emit();
    }
}

fn context_build_response(
    root: &Path,
    state_dir: &Path,
    snapshot_path: &Path,
    snapshot: Value,
    files_indexed: usize,
) -> Value {
    let output = context_build_output(root, snapshot_path, files_indexed);
    let data = json!({
        "root": root.display().to_string(),
        "stateDir": state_dir.display().to_string(),
        "snapshotPath": snapshot_path.display().to_string(),
        "snapshot": snapshot,
    });
    crate::module_result::completed_output_result(output.clone(), output, data)
}

fn context_build_output(root: &Path, snapshot_path: &Path, files_indexed: usize) -> String {
    format!(
        "context:build indexed {} file{} under {}\n  Snapshot: {}",
        files_indexed,
        plural_suffix(files_indexed),
        root.display(),
        snapshot_path.display()
    )
}

fn plural_suffix(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}
