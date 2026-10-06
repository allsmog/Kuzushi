use super::*;

pub(super) fn active_view_hydration_keys(app: &ShellApp) -> Vec<ViewHydrationKey> {
    let reality = crate::ui_view_models::journey_reality_projection(app);
    let workbench_page = crate::ui_view_models::active_workbench_page_with_reality_phase(
        app,
        reality.as_ref().map(|reality| reality.current),
    );
    let mut keys = app
        .target()
        .is_some()
        .then(common_target_keys)
        .unwrap_or_default();
    append_phase_receipt_outcome_keys(app, &mut keys);
    append_map_context_keys(app, &mut keys);
    append_checkpoint_revision_key(
        reality
            .as_ref()
            .and_then(|reality| reality.checkpoint_drift.as_ref()),
        &mut keys,
    );
    append_project_document_key(app, &mut keys);
    append_view_hydration_keys(app, app.shell_view(), workbench_page, &mut keys);
    if let Some(origin) = app
        .router
        .overlay_origin()
        .filter(|origin| *origin != app.shell_view())
    {
        append_view_hydration_keys(app, origin, workbench_page, &mut keys);
    }
    keys.sort();
    keys.dedup();
    keys
}

fn append_checkpoint_revision_key(
    drift: Option<&crate::ui_view_models::CheckpointDrift>,
    keys: &mut Vec<ViewHydrationKey>,
) {
    let Some(drift) = drift else {
        return;
    };
    if drift.accepted_revision == drift.current_revision {
        return;
    }
    let (Some(accepted_revision), Some(current_revision)) = (
        drift.accepted_revision.clone(),
        drift.current_revision.clone(),
    ) else {
        return;
    };
    keys.push(ViewHydrationKey::RevisionRelationship {
        accepted_revision,
        current_revision,
    });
}

fn append_view_hydration_keys(
    app: &ShellApp,
    view: ShellView,
    workbench_page: WorkbenchPage,
    keys: &mut Vec<ViewHydrationKey>,
) {
    match view {
        ShellView::Home => append_home_keys(app, keys),
        ShellView::Recommend => append_latest_run_keys(app, keys),
        ShellView::Module => append_module_keys(app, keys),
        ShellView::Workbench => append_workbench_keys(app, workbench_page, keys),
        ShellView::Tune | ShellView::PromptsEditor => append_prompt_keys(app, keys),
        ShellView::Threat | ShellView::ThreatEditor | ShellView::Scene => {
            append_threat_model_key(app, keys);
            append_entry_point_catalog_key(app, keys);
        }
        ShellView::RunDiff => append_run_diff_keys(app, keys),
        ShellView::Replay => append_replay_keys(app, keys, app.router.replay().run_id()),
        ShellView::Trace => append_trace_keys(keys, app.router.trace().run_id()),
        ShellView::Health => append_health_keys(app, keys),
        ShellView::ProjectModel => append_project_model_keys(app, keys),
        ShellView::StrategyQueue => keys.push(ViewHydrationKey::StrategyQueue),
        ShellView::Campaign => append_study_keys(app, keys),
        ShellView::Report => keys.push(ViewHydrationKey::InvestigationReport {
            run_refs: app.report_scan_run_refs(),
        }),
        ShellView::FailureHandoff => {
            append_latest_run_keys(app, keys);
        }
        _ => {}
    }
}

fn append_study_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    keys.push(ViewHydrationKey::ThreatModelStore);
    let Some(config) = &app.router.campaign().batch_scan_config else {
        return;
    };
    if config.context_generation.is_some() {
        return;
    }
    keys.push(ViewHydrationKey::StudyUsageCatalogue);
    if let Some(run_id) = &config.prior_run_id {
        keys.push(ViewHydrationKey::StudyUsageRun {
            run_id: run_id.clone(),
        });
    }
}

fn common_target_keys() -> Vec<ViewHydrationKey> {
    vec![
        ViewHydrationKey::FileCompletionValues,
        ViewHydrationKey::FindingCompletionValues,
        ViewHydrationKey::RunIdCompletionValues,
        ViewHydrationKey::TargetProfile,
        ViewHydrationKey::MapArtifacts,
        ViewHydrationKey::TargetBase,
        ViewHydrationKey::GitMetadata,
        ViewHydrationKey::ProjectScopeTree,
        ViewHydrationKey::RunSummaryEntries,
    ]
}

fn append_phase_receipt_outcome_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    if app.target().is_none() {
        return;
    }
    keys.extend(WorkflowPhase::ORDER.iter().filter_map(|phase| {
        app.engagement
            .unresolved_phase_attempt(*phase)
            .map(|record| ViewHydrationKey::PhaseReceiptOutcome {
                attempt_id: record.completed.attempt_id.clone(),
            })
    }));
}

fn append_home_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    keys.push(ViewHydrationKey::LatestRunPointer);
    let Some(run_id) = cached_latest_run_id(app) else {
        return;
    };
    for artifact in kuzushi_core::run_artifacts::canonical_run_artifact_specs() {
        keys.push(run_artifact_key(&run_id, artifact.leaf));
    }
    keys.push(run_artifact_key(&run_id, "attack-surface.json"));
}

fn append_latest_run_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    keys.push(ViewHydrationKey::LatestRunPointer);
    let Some(run_id) = cached_latest_run_id(app) else {
        return;
    };
    for leaf in [
        "recommendations.json",
        "attack-surface.json",
        "failures.json",
    ] {
        keys.push(run_artifact_key(&run_id, leaf));
    }
}

fn cached_latest_run_id(app: &ShellApp) -> Option<String> {
    let state = app
        .workbench_cache()
        .borrow()
        .cached_latest_run_pointer(app.target());
    let ViewDataState::Ready(LatestRunPointerState::Ready(run_id)) = state else {
        return None;
    };
    Some(run_id.as_str().to_string())
}

fn append_module_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let (Some(target), Some(module)) = (app.target(), app.focused_module()) else {
        return;
    };
    keys.push(ViewHydrationKey::DirectoryListing {
        path: kuzushi_core::module_prompt_root(target, module),
    });
}

fn append_workbench_keys(
    app: &ShellApp,
    workbench_page: WorkbenchPage,
    keys: &mut Vec<ViewHydrationKey>,
) {
    append_latest_run_keys(app, keys);
    append_threat_model_key(app, keys);
    append_entry_point_catalog_key(app, keys);
    append_selected_source_key(app, keys);
    append_scanned_snippet_key(app, keys);
    append_selected_proof_key(app, keys);
    append_finding_audit_dataflow_key(app, keys);
    append_finding_patch_truth_key(app, workbench_page, keys);
    keys.extend([
        ViewHydrationKey::StrategyQueue,
        ViewHydrationKey::HarnessFile,
    ]);
    append_scan_receipt_keys(app, workbench_page, keys);
    append_scan_recommendation_key(workbench_page, keys);
    let Some(target) = app.target() else {
        return;
    };
    keys.push(ViewHydrationKey::PathState {
        path: kuzushi_core::workspace_codeql_db_path(target),
    });
}

/// The recommender fold runs git diffs and a repo walk, so it hydrates only
/// while the Map page could actually show the rows.
fn append_scan_recommendation_key(workbench_page: WorkbenchPage, keys: &mut Vec<ViewHydrationKey>) {
    if workbench_page != WorkbenchPage::Map {
        return;
    }
    keys.push(ViewHydrationKey::ScanRecommendations);
}

/// The deep-auditor's cited dataflow evidence for the selected finding, shown
/// in the Review detail pane and the Prove page. One cached sqlite read per
/// finding; requested for the current finding only, never the whole ledger.
fn append_finding_audit_dataflow_key(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let Some((_, finding)) = crate::ui_view_models::current_finding_for_detail(app) else {
        return;
    };
    keys.push(ViewHydrationKey::FindingAuditDataflow {
        fingerprint: finding.fingerprint,
    });
}

fn append_finding_patch_truth_key(
    app: &ShellApp,
    workbench_page: WorkbenchPage,
    keys: &mut Vec<ViewHydrationKey>,
) {
    if workbench_page != WorkbenchPage::Fix {
        return;
    }
    let Some((_, finding)) = crate::ui_view_models::current_finding_for_detail(app) else {
        return;
    };
    let target_revision = app
        .engagement
        .phase_target_snapshot()
        .and_then(|snapshot| snapshot.revision.clone());
    keys.push(ViewHydrationKey::FindingPatchTruth {
        fingerprint: finding.fingerprint,
        finding_scan_id: finding.scan_id,
        target_revision,
    });
}

fn append_scan_receipt_keys(
    app: &ShellApp,
    workbench_page: WorkbenchPage,
    keys: &mut Vec<ViewHydrationKey>,
) {
    if workbench_page != WorkbenchPage::Scan {
        return;
    }
    let Some((attempt, _)) = app.engagement.displayed_phase_attempt(WorkflowPhase::Scan) else {
        return;
    };
    keys.extend(
        attempt
            .completed
            .run_refs
            .iter()
            .rev()
            .cloned()
            .map(|run_id| ViewHydrationKey::ScanStageReceipt { run_id }),
    );
}

fn append_selected_source_key(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let (Some(target), Some((_, finding))) = (
        app.target(),
        crate::ui_view_models::current_finding_for_detail(app),
    ) else {
        return;
    };
    let reported = PathBuf::from(finding.file_path);
    let path = if reported.is_absolute() {
        reported
    } else {
        target.join(reported)
    };
    keys.push(ViewHydrationKey::SourceFile { path });
}

/// The scanned-time copy of the selected finding's source, for the SOURCE
/// section's staleness fallback. One cached sqlite+blob read per finding.
fn append_scanned_snippet_key(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let Some((_, finding)) = crate::ui_view_models::current_finding_for_detail(app) else {
        return;
    };
    if finding.start_line == 0 {
        return;
    }
    let stable_fp = finding
        .identity_id
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone());
    keys.push(ViewHydrationKey::ScannedSnippet {
        stable_fp,
        scan_id: finding.scan_id,
        focus_line: finding.start_line,
    });
}

fn append_selected_proof_key(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let Some((_, finding)) = crate::ui_view_models::current_finding_for_detail(app) else {
        return;
    };
    let Some(run_id) = finding
        .verification
        .and_then(|verification| verification.verification_run_id)
        .filter(|run_id| !run_id.is_empty())
    else {
        return;
    };
    keys.push(run_artifact_key(&run_id, "items.jsonl"));
}

fn append_prompt_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    keys.push(ViewHydrationKey::PromptMutations);
    let Some(target) = app.target() else {
        return;
    };
    for prompt in app.focused_prompt_specs() {
        keys.push(ViewHydrationKey::PromptOverrideHash {
            path: kuzushi_core::prompt_override_path(target, &prompt.module_id, &prompt.verb),
        });
    }
}

fn append_map_context_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    if app.target().is_none() {
        return;
    }
    if let Some(run_refs) = crate::ui_view_models::map_context_run_refs(app) {
        keys.push(ViewHydrationKey::MapRunContext { run_refs });
    }
    if let Some(attempt) = app.engagement.selected_phase_attempt(WorkflowPhase::Map) {
        keys.push(ViewHydrationKey::MapRunContext {
            run_refs: attempt.completed.run_refs.clone(),
        });
    }
}

fn append_threat_model_key(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let Some(target) = app.target() else {
        return;
    };
    keys.extend([
        ViewHydrationKey::ThreatModelStore,
        ViewHydrationKey::JsonFile {
            path: kuzushi_core::capabilities::persistent_threat_model_path(target),
        },
    ]);
}

fn append_entry_point_catalog_key(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let Some(target) = app.target() else {
        return;
    };
    keys.push(ViewHydrationKey::JsonFile {
        path: kuzushi_core::workspace::workspace_state_root(target).join("entry-points.json"),
    });
    keys.push(ViewHydrationKey::JsonFile {
        path: kuzushi_core::context_snapshot_path(target),
    });
}

fn append_project_model_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    append_threat_model_key(app, keys);
    append_project_document_key(app, keys);
}

fn append_project_document_key(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let Some(target) = app.target() else {
        return;
    };
    let revision = match app
        .workbench_cache()
        .borrow()
        .cached_git_metadata(Some(target))
    {
        ViewDataState::Ready(Some(git)) => Some(git.sha),
        ViewDataState::Ready(None) => None,
        ViewDataState::NotRequested | ViewDataState::Loading => return,
    };
    let scope_id = app
        .active_scope()
        .map(|scope| scope.id.clone())
        .unwrap_or_else(|| kuzushi_core::workspace::ROOT_SCOPE_ID.to_string());
    keys.push(ViewHydrationKey::ProjectModelDocument { scope_id, revision });
}

fn append_health_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let credential_env = effective_credential_env(app);
    keys.push(ViewHydrationKey::HealthChecks {
        credential_env: credential_env.clone(),
    });
    let Some(target) = app.target() else {
        return;
    };
    // Route the cpg has_artifacts truth through the hydration cache so
    // `cpg_graph_row` reads a memoized flag instead of running `read_dir` on
    // the render path (mirrors the codeql-db PathState probe below).
    keys.push(ViewHydrationKey::CpgArtifacts);
    let paths = vec![
        kuzushi_core::workspace_codeql_db_path(target),
        kuzushi_core::legacy_workspace_codeql_db_path(target),
        kuzushi_core::legacy_codeql_db_path(target),
    ];
    keys.extend(
        paths
            .into_iter()
            .map(|path| ViewHydrationKey::PathState { path }),
    );
}

fn effective_credential_env(app: &ShellApp) -> String {
    let configured = app.config().runtime.api_key_env.clone();
    let Some(model) = app.config().model.as_deref() else {
        return configured;
    };
    kuzushi_core::runtime::bridge_api_key_env_for_model(model, &configured).unwrap_or(configured)
}

fn append_run_diff_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    append_run_json_keys(keys, app.router.run_diff().left());
    append_run_json_keys(keys, app.router.run_diff().right());
}

fn append_run_json_keys(keys: &mut Vec<ViewHydrationKey>, run_id: &str) {
    if run_id.is_empty() || kuzushi_core::RunId::parse(run_id).is_err() {
        return;
    }
    keys.push(run_artifact_key(run_id, "run.json"));
    keys.push(run_artifact_key(run_id, "findings.json"));
    keys.push(run_artifact_key(run_id, "result.json"));
    keys.push(run_artifact_key(run_id, "scan-input.json"));
    keys.push(ViewHydrationKey::ScanStageReceipt {
        run_id: run_id.to_string(),
    });
}

fn append_replay_keys(_app: &ShellApp, keys: &mut Vec<ViewHydrationKey>, run_id: &str) {
    if run_id.is_empty() {
        return;
    }
    keys.push(run_artifact_key(run_id, "run.json"));
    keys.push(ViewHydrationKey::RunProjection {
        run_id: run_id.to_string(),
    });
}

fn append_trace_keys(keys: &mut Vec<ViewHydrationKey>, run_id: &str) {
    if run_id.is_empty() {
        return;
    }
    for leaf in ["items.jsonl", "triage.jsonl", "verify.jsonl", "patch.jsonl"] {
        keys.push(run_artifact_key(run_id, leaf));
    }
    keys.push(ViewHydrationKey::RunProjection {
        run_id: run_id.to_string(),
    });
}

fn run_artifact_key(run_id: &str, leaf: &str) -> ViewHydrationKey {
    ViewHydrationKey::RunArtifactText {
        run_id: run_id.to_string(),
        leaf: leaf.to_string(),
    }
}
