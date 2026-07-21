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
    let mut snapshot =
        context_snapshot_value_with_progress(workspace.root(), &options, &file_sample, |stage| {
            let detail = (stage == ContextBuildStage::InferRepository)
                .then(|| format!("{} files indexed", file_sample.files_indexed));
            emit_context_build_stage(ctx, stage, detail);
        })?;
    emit_context_build_stage(ctx, ContextBuildStage::WriteSnapshot, None);
    let snapshot_path = save_context_snapshot(workspace.root(), &mut snapshot)?;
    let provenance = match index_snapshot_provenance(workspace) {
        Ok(provenance) => Some(provenance),
        Err(error) => {
            emit_context_build_note(ctx, format!("tree identity unavailable: {error:#}"));
            None
        }
    };
    let partial = context_partial(&file_sample, &snapshot);
    emit_context_build_done(ctx, file_sample.files_indexed, partial);
    let state_dir = workspace.state_dir();

    Ok(context_build_response(
        workspace.root(),
        &state_dir,
        &snapshot_path,
        snapshot,
        file_sample.files_indexed,
        partial,
        provenance,
    ))
}

struct SnapshotProvenance {
    snapshot_hash: String,
    tree_hash: String,
}

/// A map attempt can only advance the journey when its runs carry a
/// verifiable content identity. A clean git commit provides one for free; a
/// dirty tree (untracked state, vendored churn) needs the indexed-snapshot
/// claim, so the build registers the hash-only tree identity — no blob
/// storage, so monorepo-scale targets fit — and cites it. Losing the claim
/// (identity budget, unreadable file) costs identity verification only —
/// never the build.
fn index_snapshot_provenance(
    workspace: &crate::workspace::WorkspaceTarget,
) -> Result<SnapshotProvenance> {
    let indexed = crate::incremental_index::register_workspace_tree_identity(workspace)?;
    Ok(SnapshotProvenance {
        snapshot_hash: indexed.snapshot_hash,
        tree_hash: indexed.tree_hash,
    })
}

/// Operator-visible diagnostic in the run trace: a swallowed provenance
/// failure would leave "the map never advances" undebuggable from the logs.
fn emit_context_build_note(ctx: &ToolExecutionContext<'_>, note: String) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("tool-progress", "build", note).emit();
    }
}

/// True when any walk budget stopped short: the snapshot is usable but must
/// be presented as partial coverage, never as a complete map.
fn context_partial(file_sample: &ContextFileSample, snapshot: &Value) -> bool {
    file_sample.walk_truncated
        || snapshot
            .pointer("/repositoryInventory/truncation")
            .is_some_and(|value| !value.is_null())
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
    let mut snapshot = context_snapshot_value(root, options, &file_sample)?;
    save_context_snapshot(root, &mut snapshot)?;
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
    walk_truncated: bool,
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
    let walk_truncated = collect_context_files(
        root,
        root,
        sample_limit,
        &mut files_indexed,
        &mut files_sample,
    )?;
    Ok(ContextFileSample {
        files_indexed,
        files_sample,
        walk_truncated,
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
        // Distinct from `truncated` (sample smaller than index): the WALK
        // itself hit the entry cap, so totalFiles undercounts the repository.
        "walkTruncated": file_sample.walk_truncated,
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

fn emit_context_build_done(ctx: &ToolExecutionContext<'_>, files_indexed: usize, partial: bool) {
    if let Some(trace) = ctx.trace {
        let coverage = if partial { " (partial coverage)" } else { "" };
        let _ = trace
            .step(
                "done",
                "build",
                format!(
                    "context:build complete · {} files indexed{}",
                    files_indexed, coverage
                ),
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
    partial: bool,
    provenance: Option<SnapshotProvenance>,
) -> Value {
    let output = context_build_output(root, snapshot_path, files_indexed, partial);
    let mut data = json!({
        "root": root.display().to_string(),
        "stateDir": state_dir.display().to_string(),
        "snapshotPath": snapshot_path.display().to_string(),
        "snapshot": result_snapshot_view(snapshot),
        "partialCoverage": partial,
    });
    // The identity verifier rejects a null hash claim, so the keys exist
    // only when the indexed snapshot was actually registered.
    if let Some(provenance) = provenance {
        data["snapshotHash"] = json!(provenance.snapshot_hash);
        data["treeHash"] = json!(provenance.tree_hash);
    }
    crate::module_result::completed_output_result(output.clone(), output, data)
}

const RESULT_EMBED_LIST_CAP: usize = 500;

/// The on-disk snapshot keeps full detail; the copy embedded in the tool
/// result must stay within the CAS object size limit, so oversized
/// surface/app-model lists are capped with an explicit omission count
/// instead of persisting tens of MB into every run artifact.
fn result_snapshot_view(mut snapshot: Value) -> Value {
    for section in ["attackSurfaceMap", "appModel"] {
        if let Some(object) = snapshot.get_mut(section).and_then(Value::as_object_mut) {
            cap_embedded_lists(object);
        }
    }
    snapshot
}

fn cap_embedded_lists(object: &mut serde_json::Map<String, Value>) {
    let mut omitted = Vec::new();
    for (key, value) in object.iter_mut() {
        if let Some(items) = value.as_array_mut() {
            if items.len() > RESULT_EMBED_LIST_CAP {
                omitted.push((key.clone(), items.len() - RESULT_EMBED_LIST_CAP));
                items.truncate(RESULT_EMBED_LIST_CAP);
            }
        }
    }
    for (key, count) in omitted {
        object.insert(format!("{key}OmittedFromResult"), json!(count));
    }
}

fn context_build_output(
    root: &Path,
    snapshot_path: &Path,
    files_indexed: usize,
    partial: bool,
) -> String {
    let mut output = format!(
        "context:build indexed {} file{} under {}\n  Snapshot: {}",
        files_indexed,
        plural_suffix(files_indexed),
        root.display(),
        snapshot_path.display()
    );
    if partial {
        output.push_str(
            "\n  Coverage: PARTIAL — a walk cap was reached and the snapshot is marked truncated; \
             scope the target (or audit via shards) for full coverage",
        );
    }
    output
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
            walk_truncated: false,
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

    #[test]
    fn partial_coverage_is_stated_in_operator_output_and_snapshot_flags() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_path = temp.path().join("context-snapshot.json");
        let capped_sample = ContextFileSample {
            files_indexed: 1,
            files_sample: vec!["src/lib.rs".to_string()],
            walk_truncated: true,
        };

        assert!(context_partial(&capped_sample, &json!({})));
        assert!(context_partial(
            &ContextFileSample {
                files_indexed: 1,
                files_sample: vec![],
                walk_truncated: false,
            },
            &json!({"repositoryInventory": {"truncation": {"reason": "entry cap"}}}),
        ));

        let output = context_build_output(temp.path(), &snapshot_path, 1, true);
        assert!(output.contains("Coverage: PARTIAL"));
        let complete = context_build_output(temp.path(), &snapshot_path, 1, false);
        assert!(!complete.contains("PARTIAL"));

        let index = file_index(&capped_sample);
        assert_eq!(index["walkTruncated"], json!(true));
    }

    #[test]
    fn result_embed_caps_oversized_lists_and_counts_the_omission() {
        let oversized: Vec<Value> = (0..RESULT_EMBED_LIST_CAP + 40)
            .map(|index| json!({"path": format!("src/file{index}.rs")}))
            .collect();
        let snapshot = json!({
            "repositoryInventory": {"rootName": "demo"},
            "attackSurfaceMap": {"surfaces": oversized, "summary": {"total": 540}},
            "appModel": {"routes": [{"path": "/one"}]},
        });

        let view = result_snapshot_view(snapshot);

        let surfaces = view["attackSurfaceMap"]["surfaces"].as_array().unwrap();
        assert_eq!(surfaces.len(), RESULT_EMBED_LIST_CAP);
        assert_eq!(
            view["attackSurfaceMap"]["surfacesOmittedFromResult"],
            json!(40)
        );
        // Small lists and non-list fields pass through verbatim, with no
        // omission markers added.
        assert_eq!(view["appModel"]["routes"].as_array().unwrap().len(), 1);
        assert!(view["appModel"].get("routesOmittedFromResult").is_none());
        assert_eq!(view["attackSurfaceMap"]["summary"], json!({"total": 540}));
        assert_eq!(view["repositoryInventory"], json!({"rootName": "demo"}));
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;

    /// On a dirty tree the attempt ledger can only credit a map whose run
    /// cites a registered indexed snapshot — the response must carry the
    /// claim the identity verifier reads.
    #[test]
    fn build_response_cites_the_registered_indexed_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();

        let provenance = index_snapshot_provenance(&workspace).expect("indexable workspace");
        let response = context_build_response(
            temp.path(),
            &workspace.state_dir(),
            &temp.path().join(".kuzushi/context-snapshot.json"),
            json!({}),
            1,
            false,
            Some(provenance),
        );

        let snapshot_hash = response["data"]["snapshotHash"].as_str().unwrap();
        let tree_hash = response["data"]["treeHash"].as_str().unwrap();
        assert!(!snapshot_hash.is_empty() && !tree_hash.is_empty());
        assert_eq!(
            tree_hash,
            crate::incremental_index::current_workspace_tree_hash(temp.path()).unwrap(),
            "claimed tree must match the live workspace"
        );
    }

    #[test]
    fn missing_provenance_omits_the_claim_keys_entirely() {
        let temp = tempfile::tempdir().unwrap();

        let response = context_build_response(
            temp.path(),
            &temp.path().join(".kuzushi/v3"),
            &temp.path().join(".kuzushi/context-snapshot.json"),
            json!({}),
            0,
            true,
            None,
        );

        assert!(response["data"].get("snapshotHash").is_none());
        assert!(response["data"].get("treeHash").is_none());
    }
}
