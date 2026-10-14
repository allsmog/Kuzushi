use super::*;

pub(in crate::modules) fn build_context_snapshot(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    enricher: Option<&dyn ContextEnrichmentProvider>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            tool_name,
        ))?;
    let options = context_build_options(tool_name, &input)?;
    anyhow::ensure!(!ctx.is_cancelled(), "Context preparation canceled before repository inspection");
    emit_context_build_start(ctx, workspace.root());
    let starting = trace_snapshot_provenance(workspace, ctx, ContextBuildStage::BuildInventory)?;
    let mut artifact = build_context_artifact(workspace.root(), &options, ctx)?;
    let (snapshot_path, provenance, cost) = finalize_context_artifact(
        &mut artifact,
        &input,
        &options,
        &starting,
        workspace,
        ctx,
        enricher,
    )?;
    Ok(context_artifact_response(
        workspace,
        snapshot_path,
        provenance,
        cost,
        artifact,
        ctx,
    ))
}

fn finalize_context_artifact(
    artifact: &mut ContextBuildArtifact,
    input: &Value,
    options: &ContextBuildOptions,
    starting: &SnapshotProvenance,
    workspace: &crate::workspace::WorkspaceTarget,
    ctx: &ToolExecutionContext<'_>,
    enricher: Option<&dyn ContextEnrichmentProvider>,
) -> Result<(
    PathBuf,
    SnapshotProvenance,
    Option<crate::runtime::RuntimeCostReport>,
)> {
    emit_context_build_stage(
        ctx,
        ContextBuildStage::FinalizeSlices,
        Some(if options.enrichment_requested() {
            "running model enrichment".to_string()
        } else {
            "deterministic slices only".to_string()
        }),
    );
    let cost = apply_requested_enrichment(
        &mut artifact.snapshot,
        &input,
        &options,
        workspace.root(),
        ctx,
        enricher,
    )?;
    let provenance =
        trace_snapshot_provenance(workspace, ctx, ContextBuildStage::RegisterTreeIdentity)?;
    require_unchanged_context_tree(&starting.tree_hash, &provenance.tree_hash)?;
    stamp_context_tree_hash(&mut artifact.snapshot, &provenance.tree_hash)?;
    emit_context_build_stage(ctx, ContextBuildStage::WriteSnapshot, None);
    let snapshot_path = save_context_snapshot(workspace.root(), &mut artifact.snapshot)?;
    Ok((snapshot_path, provenance, cost))
}

fn context_artifact_response(
    workspace: &crate::workspace::WorkspaceTarget,
    snapshot_path: PathBuf,
    provenance: SnapshotProvenance,
    cost: Option<crate::runtime::RuntimeCostReport>,
    mut artifact: ContextBuildArtifact,
    ctx: &ToolExecutionContext<'_>,
) -> Value {
    artifact.partial = context_partial_from_snapshot(artifact.partial, &artifact.snapshot);
    emit_context_build_done(ctx, artifact.files_indexed, artifact.partial);
    let mut response = context_build_response(
        workspace.root(),
        &workspace.state_dir(),
        &snapshot_path,
        artifact.snapshot,
        artifact.files_indexed,
        artifact.partial,
        Some(provenance),
    );
    if let Some(cost) = cost {
        crate::module_result::apply_runtime_cost_report(&mut response, cost);
    }
    response
}

struct ContextBuildArtifact {
    snapshot: Value,
    files_indexed: usize,
    partial: bool,
}

fn build_context_artifact(
    root: &Path,
    options: &ContextBuildOptions,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ContextBuildArtifact> {
    match options.scope.as_str() {
        "enrichment" | "app-model" => update_existing_context_artifact(root, options),
        _ => rebuild_context_artifact(root, options, ctx),
    }
}

fn rebuild_context_artifact(
    root: &Path,
    options: &ContextBuildOptions,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ContextBuildArtifact> {
    let (file_sample, mut snapshot) = assemble_context_snapshot(root, options, ctx)?;
    if options.scope == "repo" {
        remove_snapshot_slice(&mut snapshot, "appModel");
        remove_snapshot_enrichment(&mut snapshot);
    }
    apply_scope_metadata(&mut snapshot, options)?;
    Ok(ContextBuildArtifact {
        partial: context_partial(&file_sample, &snapshot),
        files_indexed: file_sample.files_indexed,
        snapshot,
    })
}

fn update_existing_context_artifact(
    root: &Path,
    options: &ContextBuildOptions,
) -> Result<ContextBuildArtifact> {
    let mut snapshot = read_current_context_snapshot(root, &options.scope)?;
    if options.scope == "app-model" {
        let map: crate::attack_surface::AttackSurfaceMap = serde_json::from_value(
            snapshot
                .get("attackSurfaceMap")
                .cloned()
                .context("context snapshot has no attack-surface map")?,
        )
        .context("context snapshot attack-surface map is malformed")?;
        snapshot["appModel"] = app_model(&map);
    }
    snapshot["timestamp"] = json!(now_ms()?);
    apply_scope_metadata(&mut snapshot, options)?;
    let files_indexed = snapshot
        .get("filesIndexed")
        .or_else(|| snapshot.pointer("/fileIndex/totalFiles"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    Ok(ContextBuildArtifact {
        partial: context_partial_from_snapshot(false, &snapshot),
        files_indexed,
        snapshot,
    })
}

fn read_current_context_snapshot(root: &Path, scope: &str) -> Result<Value> {
    let path = crate::context::context_snapshot_path(root);
    let body = crate::bounded_file::read_utf8_text_within(
        root,
        &path,
        crate::context::MAX_CONTEXT_SNAPSHOT_BYTES,
    )
    .with_context(|| {
        format!(
            "context:build scope={scope} requires a current deterministic snapshot; run scope=all first"
        )
    })?;
    let snapshot: Value = serde_json::from_str(&body)
        .context("current context snapshot is not valid JSON; run scope=all")?;
    match crate::context::context_snapshot_freshness(root, &snapshot) {
        crate::context::ContextSnapshotFreshness::Current => Ok(snapshot),
        freshness => anyhow::bail!(
            "context:build scope={scope} requires a current deterministic snapshot: {}; run scope=all",
            freshness.disclosure().unwrap_or("freshness unverified")
        ),
    }
}

fn apply_requested_enrichment(
    snapshot: &mut Value,
    input: &Value,
    options: &ContextBuildOptions,
    root: &Path,
    ctx: &ToolExecutionContext<'_>,
    enricher: Option<&dyn ContextEnrichmentProvider>,
) -> Result<Option<crate::runtime::RuntimeCostReport>> {
    if !options.enrichment_requested() {
        if options.scope == "all" {
            remove_snapshot_enrichment(snapshot);
        }
        return Ok(None);
    }
    let outcome = enricher
        .context("context:build enrichment provider is unavailable")?
        .enrich(snapshot, input, root, ctx)?;
    snapshot["enrichedContext"] = serde_json::to_value(&outcome.value)?;
    stamp_enrichment_provenance(snapshot, &outcome)?;
    snapshot["options"]["enrichment"] = json!(true);
    Ok(Some(outcome.cost))
}

fn stamp_enrichment_provenance(snapshot: &mut Value, outcome: &EnrichmentOutcome) -> Result<()> {
    let provenance = snapshot
        .get_mut("provenance")
        .and_then(Value::as_object_mut)
        .context("context snapshot provenance is not an object")?;
    provenance.insert(
        "enrichment".to_string(),
        json!({
            "schemaVersion": 1,
            "model": outcome.model,
            "promptSha256": outcome.prompt_sha256,
            "generatedAt": now_ms()?,
        }),
    );
    Ok(())
}

fn remove_snapshot_slice(snapshot: &mut Value, key: &str) {
    if let Some(object) = snapshot.as_object_mut() {
        object.remove(key);
    }
}

fn remove_snapshot_enrichment(snapshot: &mut Value) {
    remove_snapshot_slice(snapshot, "enrichedContext");
    if let Some(provenance) = snapshot
        .get_mut("provenance")
        .and_then(Value::as_object_mut)
    {
        provenance.remove("enrichment");
    }
}

fn apply_scope_metadata(snapshot: &mut Value, options: &ContextBuildOptions) -> Result<()> {
    let object = snapshot
        .as_object_mut()
        .context("context snapshot is not an object")?;
    object.insert(
        "generatedSlices".to_string(),
        json!(generated_context_slices(
            &options.scope,
            options.enrichment_requested()
        )),
    );
    object.insert(
        "staleSlices".to_string(),
        json!(stale_context_slices(&options.scope)),
    );
    object
        .entry("options".to_string())
        .or_insert_with(|| json!({}))["enrichment"] = json!(options.enrichment_requested());
    Ok(())
}

fn assemble_context_snapshot(
    root: &Path,
    options: &ContextBuildOptions,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(ContextFileSample, Value)> {
    let (file_sample, snapshot) = context_snapshot_value_with_progress(
        root,
        options,
        |stage, detail| {
            emit_context_build_stage(ctx, stage, detail);
        },
        &|| ctx.is_cancelled(),
    )?;
    Ok((file_sample, snapshot))
}

fn trace_snapshot_provenance(
    workspace: &crate::workspace::WorkspaceTarget,
    ctx: &ToolExecutionContext<'_>,
    stage: ContextBuildStage,
) -> Result<SnapshotProvenance> {
    emit_context_build_stage(ctx, stage, None);
    let mut heartbeat = crate::progress::HeartbeatGate::new(INVENTORY_HEARTBEAT);
    let mut on_files_hashed = |files: usize| {
        if heartbeat.ready() {
            emit_context_build_stage(ctx, stage, Some(format!("{files} files hashed")));
        }
    };
    index_snapshot_provenance(workspace, &mut on_files_hashed).map_err(|error| {
        emit_context_build_note(ctx, format!("tree identity unavailable: {error:#}"));
        error.context("context:build requires a content tree identity")
    })
}

struct SnapshotProvenance {
    snapshot_hash: String,
    tree_hash: String,
}

/// A map attempt can only advance the journey when its runs carry a
/// verifiable content identity. A clean git commit provides one for free; a
/// dirty tree (untracked state, vendored churn) needs the indexed-snapshot
/// claim, so the build registers the hash-only tree identity — no blob
/// storage, so monorepo-scale targets fit — and cites it. A context snapshot
/// without that identity cannot truthfully be reused for dirty or non-Git
/// targets, so identity failure is an explicit build error.
fn index_snapshot_provenance(
    workspace: &crate::workspace::WorkspaceTarget,
    on_files_hashed: &mut dyn FnMut(usize),
) -> Result<SnapshotProvenance> {
    let indexed = crate::incremental_index::register_workspace_tree_identity_with_observer(
        workspace,
        on_files_hashed,
    )?;
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

fn stamp_context_tree_hash(snapshot: &mut Value, tree_hash: &str) -> Result<()> {
    let provenance = snapshot
        .get_mut("provenance")
        .and_then(Value::as_object_mut)
        .context("context snapshot provenance is not an object")?;
    provenance.insert("treeHash".to_string(), json!(tree_hash));
    if let Some(enrichment) = provenance
        .get_mut("enrichment")
        .and_then(Value::as_object_mut)
    {
        enrichment.insert("treeHash".to_string(), json!(tree_hash));
    }
    Ok(())
}

fn require_unchanged_context_tree(starting: &str, ending: &str) -> Result<()> {
    anyhow::ensure!(
        starting == ending,
        "target source changed while context snapshot rows were assembled; retry `context:build`"
    );
    Ok(())
}

/// True when any walk budget stopped short: the snapshot is usable but must
/// be presented as partial coverage, never as a complete map.
fn context_partial(file_sample: &ContextFileSample, snapshot: &Value) -> bool {
    context_partial_from_snapshot(file_sample.walk_truncated, snapshot)
}

fn context_partial_from_snapshot(walk_truncated: bool, snapshot: &Value) -> bool {
    walk_truncated
        || snapshot
            .pointer("/repositoryInventory/truncation")
            .is_some_and(|value| !value.is_null())
}

pub(crate) fn build_context_snapshot_for_root(root: &Path, sample_limit: usize) -> Result<()> {
    let mut snapshot = build_context_snapshot_value_for_root(root, sample_limit)?;
    save_context_snapshot(root, &mut snapshot)?;
    Ok(())
}

/// Builds an authenticated snapshot without choosing a persistence root.
/// Scoped threat-model builds use this so repository evidence comes from the
/// analysis root while `.kuzushi` ownership stays with the workspace root.
pub(crate) fn build_context_snapshot_value_for_root(
    root: &Path,
    sample_limit: usize,
) -> Result<Value> {
    let options = ContextBuildOptions {
        sample_limit: sample_limit.min(MAX_CONTEXT_SAMPLE_FILES),
        discovery: "auto".to_string(),
        enrichment: false,
        scope: "all".to_string(),
    };
    build_context_snapshot_value_for_root_with_options(root, &options)
}

fn build_context_snapshot_value_for_root_with_options(
    root: &Path,
    options: &ContextBuildOptions,
) -> Result<Value> {
    let starting_tree_hash = crate::incremental_index::current_workspace_tree_hash(root)
        .context("context snapshot requires a content tree identity")?;
    let (_, mut snapshot) = context_snapshot_value_with_progress(root, options, |_, _| {}, &|| false)?;
    let tree_hash = crate::incremental_index::current_workspace_tree_hash(root)
        .context("context snapshot requires a content tree identity")?;
    require_unchanged_context_tree(&starting_tree_hash, &tree_hash)?;
    stamp_context_tree_hash(&mut snapshot, &tree_hash)?;
    Ok(snapshot)
}

struct ContextBuildOptions {
    sample_limit: usize,
    discovery: String,
    enrichment: bool,
    scope: String,
}

impl ContextBuildOptions {
    fn enrichment_requested(&self) -> bool {
        self.enrichment || self.scope == "enrichment"
    }
}

fn context_build_options(tool_name: &str, input: &Value) -> Result<ContextBuildOptions> {
    let enrichment = read_enrichment(input);
    let options = ContextBuildOptions {
        sample_limit: read_sample_limit(input)?,
        discovery: read_discovery(input),
        enrichment,
        scope: read_scope(input),
    };
    validate_context_build_options(tool_name, &options)?;
    Ok(options)
}

fn read_sample_limit(input: &Value) -> Result<usize> {
    let Some(value) = input
        .get("sampleLimit")
        .or_else(|| input.get("limit"))
    else {
        return Ok(200);
    };
    let limit = value.as_u64().context("sampleLimit must be an integer from 1 to 2000")?;
    anyhow::ensure!((1..=MAX_CONTEXT_SAMPLE_FILES as u64).contains(&limit), "sampleLimit must be an integer from 1 to 2000");
    Ok(limit as usize)
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

fn validate_context_build_options(tool_name: &str, options: &ContextBuildOptions) -> Result<()> {
    if tool_name == "context-lite:index" && options.enrichment_requested() {
        anyhow::bail!("context-lite:index is deterministic; use context:build for enrichment");
    }
    if options.enrichment && matches!(options.scope.as_str(), "repo" | "app-model") {
        anyhow::bail!(
            "Enrichment cannot be combined with scope={}; choose scope=all or scope=enrichment, or set Enrichment to no",
            options.scope
        );
    }
    Ok(())
}

/// Heartbeat cadence for the inventory walk: monorepo walks run for minutes,
/// and without intra-stage progress the run watchdog reports a healthy walk
/// as NO PROGRESS SIGNAL.
const INVENTORY_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(5);

fn context_snapshot_value_with_progress(
    root: &Path,
    options: &ContextBuildOptions,
    mut progress: impl FnMut(ContextBuildStage, Option<String>),
    should_cancel: &dyn Fn() -> bool,
) -> Result<(ContextFileSample, Value)> {
    let repository_inventory = build_context_inventory(root, &mut progress, should_cancel)?;
    anyhow::ensure!(!should_cancel(), "Context preparation canceled after bounded inventory; prior snapshot was not replaced");
    progress(ContextBuildStage::ScanFiles, None);
    let file_sample = inventory_file_sample(&repository_inventory, options.sample_limit)?;
    progress(ContextBuildStage::InferRepository, Some(format!("{} files enumerated", file_sample.files_indexed)));
    let mut repo_context = infer_repo_context(root, &file_sample.files_sample)?;
    apply_inventory_repo_context(&mut repo_context, &repository_inventory);
    progress(ContextBuildStage::MapAttackSurface, None);
    let attack_surface_map = crate::attack_surface::build_attack_surface_map_from_inventory(
        root,
        &repository_inventory,
    )?;
    let snapshot = context_snapshot_document(
        root,
        options,
        &file_sample,
        repo_context,
        repository_inventory,
        attack_surface_map,
    )?;
    Ok((file_sample, snapshot))
}

fn build_context_inventory(
    root: &Path,
    progress: &mut impl FnMut(ContextBuildStage, Option<String>),
    should_cancel: &dyn Fn() -> bool,
) -> Result<crate::repository_inventory::RepositoryInventory> {
    progress(ContextBuildStage::BuildInventory, None);
    let mut inventory_heartbeat = crate::progress::HeartbeatGate::new(INVENTORY_HEARTBEAT);
    let mut on_entries = |entries: usize| {
        if inventory_heartbeat.ready() {
            progress(
                ContextBuildStage::BuildInventory,
                Some(format!("{entries} entries walked")),
            );
        }
    };
    crate::repository_inventory::build_repository_inventory_with_observer(
        root,
        &mut on_entries,
        should_cancel,
    )
}

fn context_snapshot_document(
    root: &Path,
    options: &ContextBuildOptions,
    file_sample: &ContextFileSample,
    repo_context: Value,
    repository_inventory: crate::repository_inventory::RepositoryInventory,
    attack_surface_map: crate::attack_surface::AttackSurfaceMap,
) -> Result<Value> {
    let provenance = context_snapshot_revision(root);
    let mut index = file_index(file_sample);
    if let Some(inspection) = &repository_inventory.inspection {
        index["enumeration"] = json!(inspection.enumeration);
        index["sampleOrder"] = json!("depth_then_path");
    }
    Ok(json!({
        "target": root.display().to_string(),
        "timestamp": now_ms()?,
        "provenance": provenance,
        "discovery": options.discovery,
        "options": {
            "enrichment": options.enrichment,
        },
        "repoContext": repo_context,
        "repositoryInventory": repository_inventory,
        "attackSurfaceMap": attack_surface_map,
        "fileIndex": index,
        "appModel": app_model(&attack_surface_map),
        "generatedSlices": generated_context_slices(&options.scope, options.enrichment),
        "staleSlices": stale_context_slices(&options.scope),
        "scanner": "native-context-lite",
        "filesIndexed": file_sample.files_indexed,
        "filesSample": file_sample.files_sample,
    }))
}

fn context_snapshot_revision(root: &Path) -> Value {
    crate::workspace::target_git_metadata(root).map_or_else(
        || json!({}),
        |metadata| {
            json!({
                "revision": metadata.sha,
                "revisionDirty": metadata.dirty,
            })
        },
    )
}

/// The alphabetical file sample can land entirely in one corner of a
/// monorepo (a Python-heavy tools/ tree on a Scala repo), so the whole-repo
/// inventory is the authority on languages and frameworks. Languages are
/// ordered dominant-first (taint language selection reads index 0); the
/// sample keeps seeding the signals the inventory does not carry
/// (entry points, auth/ORM manifest probes).
fn apply_inventory_repo_context(
    repo_context: &mut Value,
    inventory: &crate::repository_inventory::RepositoryInventory,
) {
    if !inventory.languages.is_empty() {
        let mut languages: Vec<_> = inventory.languages.iter().collect();
        languages.sort_by(|left, right| {
            right
                .files
                .cmp(&left.files)
                .then_with(|| left.name.cmp(&right.name))
        });
        repo_context["languages"] = json!(languages
            .iter()
            .map(|language| language.name.clone())
            .collect::<Vec<_>>());
    }
    let mut frameworks: std::collections::BTreeSet<String> = repo_context["frameworks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect();
    frameworks.extend(
        inventory
            .frameworks
            .iter()
            .map(|framework| framework.name.clone()),
    );
    repo_context["frameworks"] = json!(frameworks.into_iter().collect::<Vec<_>>());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextBuildStage {
    ScanFiles,
    InferRepository,
    BuildInventory,
    MapAttackSurface,
    FinalizeSlices,
    WriteSnapshot,
    RegisterTreeIdentity,
}

const CONTEXT_BUILD_STAGE_COUNT: usize = 7;

impl ContextBuildStage {
    fn position(self) -> usize {
        match self {
            Self::BuildInventory => 1,
            Self::ScanFiles => 2,
            Self::InferRepository => 3,
            Self::MapAttackSurface => 4,
            Self::FinalizeSlices => 5,
            Self::RegisterTreeIdentity => 6,
            Self::WriteSnapshot => 7,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ScanFiles => "selecting inventory file sample",
            Self::InferRepository => "inferring repository context",
            Self::BuildInventory => "building repository inventory",
            Self::MapAttackSurface => "mapping attack surface",
            Self::FinalizeSlices => "finalizing context slices",
            Self::WriteSnapshot => "writing context snapshot",
            Self::RegisterTreeIdentity => "registering tree identity",
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
        let label = format!(
            "stage {}/{} · {}{}",
            stage.position(),
            CONTEXT_BUILD_STAGE_COUNT,
            stage.label(),
            detail
        );
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
    let enrichment_claims = context_enrichment_claim_count(&snapshot);
    let mut output = context_build_output(root, snapshot_path, files_indexed, partial);
    if enrichment_claims > 0 {
        output.push_str(&format!(
            "\n  Enrichment: {enrichment_claims} source-cited security context claim{}",
            plural_suffix(enrichment_claims)
        ));
    }
    let mut data = json!({
        "root": root.display().to_string(),
        "stateDir": state_dir.display().to_string(),
        "snapshotPath": snapshot_path.display().to_string(),
        "snapshot": result_snapshot_view(snapshot),
        "partialCoverage": partial,
        "enrichmentClaimCount": enrichment_claims,
    });
    // The identity verifier rejects a null hash claim, so the keys exist
    // only when the indexed snapshot was actually registered.
    if let Some(provenance) = provenance {
        data["snapshotHash"] = json!(provenance.snapshot_hash);
        data["treeHash"] = json!(provenance.tree_hash);
    }
    // Summary must stay one line: result cards escape control characters,
    // so a multi-line summary renders literal `\n` sequences. The full
    // multi-line detail belongs to `output` only.
    let summary = output.lines().next().unwrap_or_default().to_string();
    crate::module_result::completed_output_result(summary, output, data)
}

fn context_enrichment_claim_count(snapshot: &Value) -> usize {
    [
        "customMiddleware",
        "customSanitizers",
        "trustBoundaries",
        "dataClassifications",
        "architecturalNotes",
    ]
    .iter()
    .map(|key| {
        snapshot
            .pointer(&format!("/enrichedContext/{key}"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    })
    .sum()
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
            "\n  Coverage: PARTIAL. An inspection cap was reached and the snapshot is marked truncated; \
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
    fn inventory_cancellation_stops_before_inference_and_publication() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("owned.rs"), "// Owned cancellation fixture.\n").unwrap();
        let options = ContextBuildOptions { sample_limit:2, discovery:"auto".into(), enrichment:false, scope:"all".into() };
        let checks = std::cell::Cell::new(0);
        let cancel = || { checks.set(checks.get()+1); checks.get()>1 };
        let mut stages = Vec::new();
        let error = context_snapshot_value_with_progress(root.path(), &options, |stage,_| stages.push(stage), &cancel).unwrap_err();
        assert!(error.to_string().contains("canceled after bounded inventory"));
        assert_eq!(stages, [ContextBuildStage::BuildInventory]);
        assert!(!crate::context::context_snapshot_path(root.path()).exists());
    }

    #[test]
    fn context_snapshot_reports_each_expensive_assembly_stage_in_order() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
        let options = ContextBuildOptions {
            sample_limit: 10,
            discovery: "auto".to_string(),
            enrichment: false,
            scope: "all".to_string(),
        };
        let mut stages = Vec::new();

        context_snapshot_value_with_progress(
            temp.path(),
            &options,
            |stage, _| stages.push(stage),
            &|| false,
        )
        .unwrap();

        assert_eq!(
            stages,
            vec![
                ContextBuildStage::BuildInventory,
                ContextBuildStage::ScanFiles,
                ContextBuildStage::InferRepository,
                ContextBuildStage::MapAttackSurface,
            ]
        );
    }

    /// The monorepo regression: an alphabetical 200-file sample hit a
    /// Python-heavy corner of a Scala/Java monorepo and the snapshot reported
    /// `languages: Python`. The inventory's whole-repo counts must win, with
    /// the dominant language first.
    #[test]
    fn inventory_language_counts_override_the_sample_guess() {
        let mut repo_context = json!({
            "languages": ["Python"],
            "frameworks": ["flask"],
            "entryPoints": ["app.py"],
        });
        let inventory = crate::repository_inventory::RepositoryInventory {
            inspection: None,
            root_name: "monorepo".to_string(),
            languages: vec![
                crate::repository_inventory::InventoryLanguage {
                    name: "Java".to_string(),
                    files: 20_000,
                    bytes: 1,
                },
                crate::repository_inventory::InventoryLanguage {
                    name: "Python".to_string(),
                    files: 900,
                    bytes: 1,
                },
                crate::repository_inventory::InventoryLanguage {
                    name: "Scala".to_string(),
                    files: 45_000,
                    bytes: 1,
                },
            ],
            source_files: Vec::new(),
            manifests: Vec::new(),
            dependency_manifests: Vec::new(),
            config_files: Vec::new(),
            frameworks: vec![crate::repository_inventory::InventoryFramework {
                name: "spring".to_string(),
                language: "Java".to_string(),
                evidence: vec!["services/pom.xml".to_string()],
            }],
            entrypoints: Vec::new(),
            routes_controllers: Vec::new(),
            generated_vendor_paths: Vec::new(),
            truncation: None,
        };

        apply_inventory_repo_context(&mut repo_context, &inventory);

        assert_eq!(
            repo_context["languages"],
            json!(["Scala", "Java", "Python"]),
            "dominant language must come first"
        );
        assert_eq!(repo_context["frameworks"], json!(["flask", "spring"]));
        // Sample-derived signals the inventory does not carry survive.
        assert_eq!(repo_context["entryPoints"], json!(["app.py"]));
    }

    #[test]
    fn empty_inventory_keeps_the_sample_language_guess() {
        let mut repo_context = json!({"languages": ["Rust"], "frameworks": []});
        let inventory = crate::repository_inventory::RepositoryInventory {
            inspection: None,
            root_name: "tiny".to_string(),
            languages: Vec::new(),
            source_files: Vec::new(),
            manifests: Vec::new(),
            dependency_manifests: Vec::new(),
            config_files: Vec::new(),
            frameworks: Vec::new(),
            entrypoints: Vec::new(),
            routes_controllers: Vec::new(),
            generated_vendor_paths: Vec::new(),
            truncation: None,
        };

        apply_inventory_repo_context(&mut repo_context, &inventory);

        assert_eq!(repo_context["languages"], json!(["Rust"]));
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

    #[test]
    fn context_assembly_rejects_a_changed_source_tree() {
        let error = require_unchanged_context_tree("tree-before", "tree-after").unwrap_err();
        assert!(error.to_string().contains("source changed"), "{error:#}");
        require_unchanged_context_tree("tree-stable", "tree-stable").unwrap();
    }

    /// On a dirty tree the attempt ledger can only credit a map whose run
    /// cites a registered indexed snapshot — the response must carry the
    /// claim the identity verifier reads.
    #[test]
    fn build_response_cites_the_registered_indexed_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();

        let mut hashed_counts = Vec::new();
        let provenance =
            index_snapshot_provenance(&workspace, &mut |files| hashed_counts.push(files))
                .expect("indexable workspace");
        assert!(
            !hashed_counts.is_empty(),
            "identity walk must report per-file progress so monorepo builds are never silent"
        );
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
