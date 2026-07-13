use super::*;

pub(in crate::modules) fn build_context_snapshot(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "context:build",
        ))?;
    let options = context_build_options(&input)?;

    emit_context_build_start(ctx, workspace.root());
    emit_context_build_stage(ctx, ContextBuildStage::ScanFiles, None);
    let file_sample = collect_context_file_sample(workspace.root(), options.sample_limit)?;
    let snapshot =
        context_snapshot_value_with_progress(workspace.root(), &options, &file_sample, |stage| {
            let detail = (stage == ContextBuildStage::InferRepository)
                .then(|| format!("{} files indexed", file_sample.files_indexed));
            emit_context_build_stage(ctx, stage, detail);
        })?;
    emit_context_build_stage(ctx, ContextBuildStage::WriteSnapshot, None);
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

pub(crate) struct ContextSnapshotBuild {
    pub(crate) snapshot: Value,
}

pub(crate) fn build_context_snapshot_for_root(
    root: &Path,
    sample_limit: usize,
) -> Result<ContextSnapshotBuild> {
    let options = ContextBuildOptions {
        sample_limit: sample_limit.min(2_000),
        discovery: "auto".to_string(),
        enrichment: false,
        scope: "all".to_string(),
    };
    build_context_snapshot_for_root_with_options(root, &options)
}

fn build_context_snapshot_for_root_with_options(
    root: &Path,
    options: &ContextBuildOptions,
) -> Result<ContextSnapshotBuild> {
    let file_sample = collect_context_file_sample(root, options.sample_limit)?;
    let snapshot = context_snapshot_value(root, options, &file_sample)?;
    save_context_snapshot(root, &snapshot)?;
    Ok(ContextSnapshotBuild { snapshot })
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
            "context:build Rust native executor does not support LLM enrichment yet; run with {{\"enrichment\":false}} or use a LangGraph-backed context adapter once configured"
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
    context_snapshot_value_with_progress(root, options, file_sample, |_| {})
}

fn context_snapshot_value_with_progress(
    root: &Path,
    options: &ContextBuildOptions,
    file_sample: &ContextFileSample,
    mut progress: impl FnMut(ContextBuildStage),
) -> Result<Value> {
    progress(ContextBuildStage::InferRepository);
    let repo_context = infer_repo_context(root, &file_sample.files_sample)?;
    progress(ContextBuildStage::BuildInventory);
    let repository_inventory = crate::repository_inventory::build_repository_inventory(root)?;
    progress(ContextBuildStage::MapAttackSurface);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextBuildStage {
    ScanFiles,
    InferRepository,
    BuildInventory,
    MapAttackSurface,
    WriteSnapshot,
}

impl ContextBuildStage {
    fn position(self) -> usize {
        match self {
            Self::ScanFiles => 1,
            Self::InferRepository => 2,
            Self::BuildInventory => 3,
            Self::MapAttackSurface => 4,
            Self::WriteSnapshot => 5,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ScanFiles => "scanning repository files",
            Self::InferRepository => "inferring repository context",
            Self::BuildInventory => "building repository inventory",
            Self::MapAttackSurface => "mapping attack surface",
            Self::WriteSnapshot => "writing context snapshot",
        }
    }
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

/// Emit each in-progress assembly stage so Activity can show the current work
/// and the age of the last real progress signal instead of only spinning.
fn emit_context_build_stage(
    ctx: &ToolExecutionContext<'_>,
    stage: ContextBuildStage,
    detail: Option<String>,
) {
    if let Some(trace) = ctx.trace {
        let detail = detail
            .map(|value| format!(" · {value}"))
            .unwrap_or_default();
        let label = format!("stage {}/5 · {}{}", stage.position(), stage.label(), detail);
        let _ = trace.step("tool-progress", "build", label).emit();
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

#[cfg(test)]
mod stage_tests {
    use super::*;

    #[test]
    fn context_snapshot_reports_each_expensive_assembly_stage_in_order() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
        let sample = ContextFileSample {
            files_indexed: 1,
            files_sample: vec!["src/lib.rs".to_string()],
        };
        let options = ContextBuildOptions {
            sample_limit: 10,
            discovery: "auto".to_string(),
            enrichment: false,
            scope: "all".to_string(),
        };
        let mut stages = Vec::new();

        context_snapshot_value_with_progress(temp.path(), &options, &sample, |stage| {
            stages.push(stage)
        })
        .unwrap();

        assert_eq!(
            stages,
            vec![
                ContextBuildStage::InferRepository,
                ContextBuildStage::BuildInventory,
                ContextBuildStage::MapAttackSurface,
            ]
        );
    }
}
