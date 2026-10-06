//! Executors for `threat-model:verify` and `threat-model:import`.
//!
//! Verify grounds the live persisted document against the target and stamps
//! the verdict back (no versions-ledger row — a timestamp-only change would
//! defeat the ledger's sha dedupe). Import is the explicit front door for
//! externally-authored documents: normalize → provenance(`import`) → verify
//! → stamp → save (refusing to clobber a user-edited live doc without
//! `force`) → ledger row `source='import'`.

use super::*;

const IMPORT_MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn verify_threat_model_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace_root = verification_root(ctx)?;
    crate::workspace::source_snapshot::run_source_bound_tool(
        ctx,
        "threat-model:verify",
        workspace_root,
        || verify_document_for_root(input, workspace_root, ctx.run_id()),
    )
}

fn verify_document_for_root(
    input: Value,
    workspace_root: &Path,
    run_id: Option<String>,
) -> Result<Value> {
    let roots = read_build_roots(&input, workspace_root)?;
    let selected_scope = roots
        .scope
        .clone()
        .map(Ok)
        .unwrap_or_else(|| root_scope_ref(workspace_root))?;
    let (mut document, selected_ref) = load_verification_document(&input, workspace_root)?;
    let verification = verify_threat_model_document_with_roots(&document, &roots)?;
    stamp_verification(&mut document, &verification);
    let write = input.get("write").and_then(Value::as_bool).unwrap_or(true);
    let written_ref = write_verified_revision(
        workspace_root,
        &document,
        selected_ref.as_ref(),
        &selected_scope,
        write,
        run_id,
    )?;
    Ok(verification_result(
        verification,
        write,
        selected_ref,
        written_ref,
    ))
}

fn verification_root<'a>(ctx: &'a ToolExecutionContext<'_>) -> Result<&'a Path> {
    Ok(ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "threat-model:verify",
        ))?
        .root())
}

fn load_verification_document(
    input: &Value,
    root: &Path,
) -> Result<(Value, Option<ThreatModelRef>)> {
    load_requested_threat_model(input, root)?.context(
        "threat-model:verify requires a persisted threat model \
         (.kuzushi/threat-model.json); run threat-model:build or \
         threat-model:import first",
    )
}

fn write_verified_revision(
    root: &Path,
    document: &Value,
    selected_ref: Option<&ThreatModelRef>,
    selected_scope: &ScopeRef,
    write: bool,
    run_id: Option<String>,
) -> Result<Option<ThreatModelRef>> {
    let written = write
        .then(|| persist_verified_revision(root, document, selected_ref, selected_scope, run_id))
        .transpose()?
        .map(|committed| committed.model_ref);
    Ok(written)
}

fn verification_result(
    verification: ThreatModelVerification,
    write: bool,
    selected_ref: Option<ThreatModelRef>,
    written_ref: Option<ThreatModelRef>,
) -> Value {
    let output = format!(
        "threat-model:verify — {} ({} cited paths, {} missing; {} link errors; coverage {}/{}){}",
        verification.verdict,
        verification.checked_paths,
        verification.missing_count,
        verification.link_error_count,
        verification.coverage_considered - verification.coverage_gaps,
        verification.coverage_considered,
        degraded_grounding_note(verification.grounding_degraded.as_deref()),
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "verification": verification,
            "written": write,
            "sourceModelRef": selected_ref,
            "modelRef": written_ref,
        }),
    )
}

fn persist_verified_revision(
    root: &Path,
    document: &Value,
    selected_ref: Option<&ThreatModelRef>,
    selected_scope: &ScopeRef,
    run_id: Option<String>,
) -> Result<ThreatModelCommitResult> {
    let manifest = open_writable_threat_model_store(root)?;
    let model_ref = selected_ref
        .cloned()
        .or(manifest.active.clone())
        .context("threat-model store has no selected lineage")?;
    let model = manifest
        .models
        .iter()
        .find(|model| model.model_id == model_ref.model_id)
        .context("selected threat-model lineage is absent from manifest")?;
    let document = verification_revision_document(document, model, &model_ref)?;
    commit_threat_model_revision(
        root,
        &document,
        ThreatModelCommit {
            model_id: Some(model.model_id.clone()),
            new_model: false,
            label: model.label.clone(),
            scope: selected_scope.clone(),
            methodology: model.methodology.clone(),
            source: ThreatModelRevisionSource::Verify,
            source_revision_id: Some(model_ref.revision_id),
            run_id,
            activate: None,
            actor: "tool:threat-model:verify".to_string(),
        },
    )
}

fn verification_revision_document(
    document: &Value,
    model: &ThreatModelMetadata,
    model_ref: &ThreatModelRef,
) -> Result<Value> {
    let is_legacy = model
        .revisions
        .iter()
        .find(|revision| revision.revision_id == model_ref.revision_id)
        .is_some_and(|revision| revision.source == ThreatModelRevisionSource::LegacyImport);
    if !is_legacy {
        return Ok(document.clone());
    }
    legacy_persistence_envelope(document, &model.methodology)
}

fn legacy_persistence_envelope(document: &Value, methodology: &str) -> Result<Value> {
    let mut document = document.clone();
    let object = document
        .as_object_mut()
        .context("legacy ThreatModelDocument must be a JSON object")?;
    object.entry("version").or_insert_with(|| json!("2.0"));
    object
        .entry("methodology")
        .or_insert_with(|| json!(methodology));
    object.entry("threats").or_insert_with(|| json!([]));
    object.entry("summary").or_insert_with(|| json!({}));
    let dfd = object.entry("dfd").or_insert_with(|| json!({}));
    let dfd = dfd
        .as_object_mut()
        .context("legacy ThreatModelDocument.dfd must be an object")?;
    for field in ["nodes", "flows", "trustBoundaries"] {
        dfd.entry(field).or_insert_with(|| json!([]));
    }
    Ok(document)
}

/// A verdict measured without the entry-point catalog says so on the same
/// line the operator reads the verdict from.
fn degraded_grounding_note(disclosure: Option<&str>) -> String {
    match disclosure {
        Some(disclosure) => format!(" — degraded grounding: {disclosure}"),
        None => String::new(),
    }
}

pub(crate) fn import_threat_model_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "threat-model:import",
        ))?;
    let root = workspace.root();
    let raw = import_document_value(&input)?;
    let methodology = import_methodology(&input, &raw);
    let mut document = normalize_document(raw, &methodology)?;
    require_complete_security_context_links(&document)?;
    stamp_provenance(&mut document, root, "import");
    let snapshot = bind_import_to_current_tree(&mut document, root)?;
    let verification = verify_threat_model_document(&document, root)?;
    stamp_verification(&mut document, &verification);
    let model_ref = persist_imported_document(root, &document, &methodology, &input, ctx.run_id())?;
    let output = format!(
        "threat-model:import saved ({}; {} threats, verification {})",
        methodology,
        document
            .get("threats")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        verification.verdict,
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "methodology": methodology,
            "verification": verification,
            "modelRef": model_ref,
            "snapshot": {"snapshotHash": snapshot.snapshot_hash, "treeHash": snapshot.tree_hash},
            "document": document,
        }),
    ))
}

fn bind_import_to_current_tree(
    document: &mut Value,
    root: &Path,
) -> Result<crate::incremental_index::IndexedWorkspaceSnapshot> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    workspace.ensure_state_dir()?;
    crate::FindingStore::open(workspace.findings_db_path())?;
    let snapshot = crate::incremental_index::index_workspace_snapshot(&workspace)
        .context("Could not authenticate the imported threat model's target snapshot")?;
    let object = document
        .as_object_mut()
        .context("normalized threat model must be an object")?;
    let provenance = object
        .entry("provenance")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("normalized threat-model provenance must be an object")?;
    provenance.insert("treeHash".to_string(), json!(snapshot.tree_hash));
    Ok(snapshot)
}

fn persist_imported_document(
    root: &Path,
    document: &Value,
    methodology: &str,
    input: &Value,
    run_id: Option<String>,
) -> Result<ThreatModelRef> {
    let force = input.get("force").and_then(Value::as_bool).unwrap_or(false);
    prepare_import_store(root, force)?;
    let model_id = input
        .get("modelId")
        .and_then(Value::as_str)
        .map(ThreatModelId::parse)
        .transpose()?;
    let request = ThreatModelCommit {
        new_model: model_id.is_none(),
        model_id,
        label: import_label(input, methodology),
        scope: root_scope_ref(root)?,
        methodology: methodology.to_string(),
        source: ThreatModelRevisionSource::Import,
        source_revision_id: None,
        run_id,
        activate: Some(
            input
                .get("activate")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        ),
        actor: "tool:threat-model:import".to_string(),
    };
    let committed = commit_threat_model_revision(root, document, request)?;
    record_threat_model_version_with_ref(root, document, "import", None, &committed.model_ref)?;
    Ok(committed.model_ref)
}

fn prepare_import_store(root: &Path, force: bool) -> Result<ThreatModelManifest> {
    match open_writable_threat_model_store(root) {
        Ok(manifest) => Ok(manifest),
        Err(error) if force && error.downcast_ref::<ThreatModelStoreError>().is_some() => {
            discard_divergent_import_mirror(root)?;
            load_threat_model_manifest(root)?.context("threat-model manifest is missing")
        }
        Err(error) if error.downcast_ref::<ThreatModelStoreError>().is_some() => Err(error).context(
            "threat-model:import refused a divergent compatibility mirror; adopt edits or pass force=true",
        ),
        Err(error) => Err(error),
    }
}

fn discard_divergent_import_mirror(root: &Path) -> Result<()> {
    let manifest = load_threat_model_manifest(root)?.context("threat-model manifest is missing")?;
    let active = manifest
        .active
        .context("threat-model manifest has no active revision")?;
    activate_threat_model(
        root,
        &active.model_id,
        Some(&active.revision_id),
        "tool:threat-model:import",
        MirrorAction::Discard,
    )?;
    Ok(())
}

fn import_label(input: &Value, methodology: &str) -> String {
    input
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("Imported {} threat model", methodology.to_ascii_uppercase()))
}

fn import_document_value(input: &Value) -> Result<Value> {
    if let Some(document) = input.get("document") {
        if !document.is_null() {
            return Ok(document.clone());
        }
    }
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .context("threat-model:import requires `path` or an inline `document`")?;
    let body = crate::bounded_file::read_utf8_text(Path::new(path), IMPORT_MAX_DOCUMENT_BYTES)
        .with_context(|| format!("Could not read threat-model document {path}"))?;
    serde_json::from_str(&body).with_context(|| format!("{path} is not valid JSON"))
}

/// Explicit option wins; else the document's own methodology; else stride.
fn import_methodology(input: &Value, raw: &Value) -> String {
    input
        .get("methodology")
        .and_then(Value::as_str)
        .or_else(|| raw.get("methodology").and_then(Value::as_str))
        .or_else(|| raw.pointer("/document/methodology").and_then(Value::as_str))
        .unwrap_or("stride")
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod verify_import_tests {
    use super::*;
    use crate::modules::ExecutionAuthorization;
    use crate::{V2Config, WorkspaceTarget};

    fn accept_import(workspace: &WorkspaceTarget, config: &V2Config) -> ThreatModelRef {
        use crate::run_artifacts::*;
        use crate::workflow_attempts::*;
        let root = workspace.root();
        let registry = crate::modules::ModuleRegistry::with_v2_builtins();
        let context = ctx(config, workspace);
        let input = json!({"document":hand_written_document(root),"label":"Accepted Alpha"});
        let record = ToolRunRecord::new(root, "accepted-import", "tool", "threat-model:import");
        try_record_tool_run_started_with_reproducibility(record, &input, None, None, vec![])
            .unwrap();
        let observation =
            crate::run_lifecycle::RunObservationHandle::jsonl(root, "accepted-import").unwrap();
        let call = crate::modules::ApplicationToolCall::start(
            observation.clone(),
            "threat-model:import",
            &input,
            None,
            None,
        )
        .unwrap();
        let output = registry
            .execute_tool("threat-model:import", input, &context)
            .unwrap();
        let reference = serde_json::from_value(output["data"]["modelRef"].clone()).unwrap();
        let completion = call.completion_from_result(&Ok(output.clone()));
        try_record_tool_run_complete_settled(record, &output, &observation, completion).unwrap();
        drop(observation);
        let completed = PhaseAttemptCompleted::new(
            crate::WorkflowPhase::Map,
            vec!["accepted-import".into()],
            PhaseTargetSnapshot::capture(root),
            PhaseAttemptOutcome::Completed,
        )
        .with_attempt_id(crate::run_lifecycle::RunAttemptId::new().to_string());
        append_phase_attempt_completed_with_v2(root, completed.clone()).unwrap();
        append_phase_attempt_disposition(
            root,
            PhaseAttemptDispositionRecorded::new(
                completed.attempt_id,
                PhaseAttemptDisposition::Selected {
                    acknowledged_partial: false,
                },
            ),
        )
        .unwrap();
        reference
    }

    #[test]
    fn accepted_import_supplies_exact_context_to_study_after_active_model_changes() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let alpha = accept_import(&workspace, &config);
        let registry = crate::modules::ModuleRegistry::with_v2_builtins();
        let context = ctx(&config, &workspace);
        let beta = registry
            .execute_tool(
                "threat-model:import",
                json!({
                    "document":hand_written_document(workspace.root()), "label":"Active Beta"
                }),
                &context,
            )
            .unwrap();
        let result = registry
            .execute_tool(
                "campaign:study",
                json!({"campaignId":"accepted-map-study",
            "scanInput":{"taskMode":"manual","tasks":["secret-scan"]}}),
                &context,
            )
            .unwrap();
        assert!(result["ok"].as_bool().unwrap());
        let active = load_active_threat_model(workspace.root())
            .unwrap()
            .unwrap()
            .model_ref;
        assert_eq!(json!(active), beta["data"]["modelRef"]);
        assert_ne!(active, alpha);
        let receipt = crate::capabilities::campaign::load_study_plan_receipt(
            workspace.root(),
            "accepted-map-study",
        )
        .unwrap();
        assert_eq!(receipt.scan_input["threatModelRef"], json!(alpha));
        assert_eq!(receipt.job_count, 3);
    }

    #[test]
    fn changed_source_requires_fresh_map_or_explicit_context_for_new_study() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let alpha = accept_import(&workspace, &config);
        std::fs::write(workspace.root().join("src/app.py"), "changed source\n").unwrap();
        let registry = crate::modules::ModuleRegistry::with_v2_builtins();
        let context = ctx(&config, &workspace);
        let input = json!({"campaignId":"source-changed-study", "scanInput":{"taskMode":"manual","tasks":["secret-scan"]}});
        let error = registry
            .execute_tool("campaign:study", input.clone(), &context)
            .unwrap_err();
        assert!(
            error.to_string().contains("earlier source content"),
            "{error:#}"
        );
        let mut explicit = input;
        explicit["scanInput"]["threatModelRef"] = json!(alpha);
        registry
            .execute_tool("campaign:study", explicit, &context)
            .unwrap();
    }

    fn fixture() -> (tempfile::TempDir, WorkspaceTarget) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/app.py"), "a\nb\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        (temp, workspace)
    }

    fn run_git(root: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    fn commit_all(root: &Path, message: &str) {
        run_git(root, &["add", "-A"]);
        run_git(root, &["commit", "-qm", message]);
    }

    fn active_model(manifest: &ThreatModelManifest) -> &ThreatModelMetadata {
        let active = manifest.active.as_ref().unwrap();
        manifest
            .models
            .iter()
            .find(|model| model.model_id == active.model_id)
            .unwrap()
    }

    fn ctx<'a>(config: &'a V2Config, workspace: &'a WorkspaceTarget) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: ExecutionAuthorization::default(),
        }
    }

    fn hand_written_document(root: &Path) -> Value {
        let surfaces = grounding_surfaces(root, 40).unwrap();
        let entry_point_ids = surfaces
            .iter()
            .map(|surface| surface.id.clone())
            .collect::<Vec<_>>();
        let entry_points = surfaces
            .iter()
            .map(|surface| {
                json!({
                    "id": surface.id,
                    "name": surface.title,
                    "path": surface.path,
                    "evidence": surface.evidence,
                    "targetElementIds": ["app"],
                })
            })
            .collect::<Vec<_>>();
        json!({
            "methodology": "stride",
            "dfd": {
                "nodes": [{"id": "app"}],
                "flows": [],
                "trustBoundaries": []
            },
            "threats": [{
                "id": "T-001",
                "targetElementIds": ["app"],
                "entryPointIds": entry_point_ids,
                "title": "download traversal",
                "affectedFiles": ["src/app.py"],
            }],
            "attackSurface": {"entryPoints": entry_points},
        })
    }

    #[test]
    fn import_saves_verifies_and_ledgers_the_document() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);
        let result = import_threat_model_adapter(
            json!({"document": hand_written_document(workspace.root())}),
            &ctx,
        )
        .unwrap();
        assert_eq!(
            result["data"]["verification"]["verdict"],
            json!("verified"),
            "{result:#}"
        );

        let live = load_persistent_threat_model(workspace.root())
            .unwrap()
            .unwrap();
        assert_eq!(
            live.pointer("/verification/verdict"),
            Some(&json!("verified"))
        );
        assert_eq!(live.pointer("/provenance/pipeline"), Some(&json!("import")));
        let versions = list_threat_model_versions(workspace.root(), 10).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].source, "import");
    }

    #[test]
    fn import_preserves_a_legacy_hand_edit_before_creating_a_new_model() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);
        let mut edited = hand_written_document(workspace.root());
        edited["userEdited"] = json!(true);
        save_persistent_threat_model(workspace.root(), &edited, true).unwrap();

        import_threat_model_adapter(
            json!({"document": hand_written_document(workspace.root())}),
            &ctx,
        )
        .unwrap();

        let manifest = load_threat_model_manifest(workspace.root())
            .unwrap()
            .unwrap();
        assert_eq!(manifest.models.len(), 2);
        let legacy = &manifest.models[0];
        assert_eq!(
            legacy.revisions[0].source,
            ThreatModelRevisionSource::LegacyImport
        );
        let preserved = load_threat_model_revision(
            workspace.root(),
            &legacy.model_id,
            Some(&legacy.revisions[0].revision_id),
        )
        .unwrap();
        assert_eq!(preserved.document, edited);
    }

    #[test]
    fn import_refuses_a_divergent_managed_mirror_without_force() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);
        import_threat_model_adapter(
            json!({"document": hand_written_document(workspace.root())}),
            &ctx,
        )
        .unwrap();
        let mut edited = load_persistent_threat_model(workspace.root())
            .unwrap()
            .unwrap();
        edited["operatorNote"] = json!("keep me");
        save_persistent_threat_model(workspace.root(), &edited, true).unwrap();

        let refused = import_threat_model_adapter(
            json!({"document": hand_written_document(workspace.root())}),
            &ctx,
        )
        .unwrap_err();

        assert!(refused.to_string().contains("force=true"), "{refused:#}");
        let mirror = fs::read_to_string(persistent_threat_model_path(workspace.root())).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&mirror).unwrap(), edited);
    }

    #[test]
    fn import_rejects_dangling_context_links_without_replacing_live_document() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);
        let live = hand_written_document(workspace.root());
        save_persistent_threat_model(workspace.root(), &live, true).unwrap();
        let mut invalid = hand_written_document(workspace.root());
        invalid["threats"][0]["targetElementIds"] = json!(["missing"]);

        let error = import_threat_model_adapter(json!({"document": invalid, "force": true}), &ctx)
            .unwrap_err();

        assert!(error.to_string().contains("unknown DFD id `missing`"));
        assert_eq!(
            load_persistent_threat_model(workspace.root())
                .unwrap()
                .unwrap(),
            live
        );
    }

    #[test]
    fn verify_write_preserves_user_edits_and_stamps_the_verdict() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);
        let mut edited = hand_written_document(workspace.root());
        edited["userEdited"] = json!(true);
        bind_import_to_current_tree(&mut edited, workspace.root()).unwrap();
        save_persistent_threat_model(workspace.root(), &edited, true).unwrap();

        verify_threat_model_adapter(json!({}), &ctx).unwrap();

        let live = load_persistent_threat_model(workspace.root())
            .unwrap()
            .unwrap();
        assert_eq!(live.get("userEdited"), Some(&json!(true)));
        assert!(live.get("verification").is_some());
        assert!(
            list_threat_model_versions(workspace.root(), 10)
                .unwrap()
                .is_empty(),
            "verify never writes a versions-ledger row"
        );
    }

    #[test]
    fn verify_revision_records_the_current_target_revision() {
        let (_temp, workspace) = fixture();
        run_git(workspace.root(), &["init", "-q"]);
        commit_all(workspace.root(), "initial");
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);
        import_threat_model_adapter(
            json!({"document": hand_written_document(workspace.root())}),
            &ctx,
        )
        .unwrap();
        let initial_manifest = load_threat_model_manifest(workspace.root())
            .unwrap()
            .unwrap();
        let before = active_model(&initial_manifest)
            .scope
            .target_revision
            .clone();

        std::fs::write(workspace.root().join("src/app.py"), "a\nb\nc\n").unwrap();
        commit_all(workspace.root(), "next");
        let current = crate::workspace::target_git_metadata(workspace.root())
            .unwrap()
            .sha;
        verify_threat_model_adapter(json!({}), &ctx).unwrap();

        let manifest = load_threat_model_manifest(workspace.root())
            .unwrap()
            .unwrap();
        let model = active_model(&manifest);
        assert_ne!(before, current);
        assert_eq!(model.scope.target_revision, current);
        assert_eq!(
            model
                .revisions
                .last()
                .unwrap()
                .scope
                .as_ref()
                .unwrap()
                .target_revision,
            current
        );
    }

    #[test]
    fn scoped_read_and_verify_never_fall_back_to_the_active_root_model() {
        let (_temp, workspace) = fixture();
        std::fs::create_dir_all(workspace.root().join("apps/api")).unwrap();
        save_api_scope_tree(workspace.root());
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);
        import_threat_model_adapter(
            json!({"document": hand_written_document(workspace.root())}),
            &ctx,
        )
        .unwrap();
        let before = load_threat_model_manifest(workspace.root())
            .unwrap()
            .unwrap();

        let read =
            read_threat_model(json!({"scope": "id:api"}), &ctx, ReadFlavor::ThreatModel).unwrap();
        let verify_error = verify_threat_model_adapter(json!({"scope": "id:api"}), &ctx)
            .unwrap_err()
            .to_string();

        assert_eq!(read["status"], json!("failed"));
        assert_eq!(read["data"]["reason"], json!("missing-output-dir"));
        assert!(verify_error.contains("requires a persisted threat model"));
        assert_eq!(
            load_threat_model_manifest(workspace.root())
                .unwrap()
                .unwrap(),
            before,
            "failed scoped verification must not append to the active root lineage"
        );
    }

    fn save_api_scope_tree(root: &Path) {
        crate::workspace::save_nested_project_scopes(
            root,
            &crate::workspace::NestedProjectScopeTree {
                schema_version: 2,
                root: crate::workspace::ROOT_SCOPE_ID.to_string(),
                scopes: vec![
                    crate::capabilities::threat_model::root_scope(),
                    crate::workspace::NestedProjectScope {
                        id: "api".to_string(),
                        parent: Some(crate::workspace::ROOT_SCOPE_ID.to_string()),
                        kind: crate::workspace::NestedProjectKind::PackageRoot,
                        rel_path: "apps/api".to_string(),
                        inherited_sections: Vec::new(),
                    },
                ],
            },
        )
        .unwrap();
    }
}
