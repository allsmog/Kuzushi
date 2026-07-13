use super::*;

pub(super) fn active_view_hydration_keys(app: &ShellApp) -> Vec<ViewHydrationKey> {
    let mut keys = app
        .target()
        .is_some()
        .then(common_target_keys)
        .unwrap_or_default();
    append_project_document_key(app, &mut keys);
    match rendered_shell_view(app) {
        ShellView::Home => append_home_keys(app, &mut keys),
        ShellView::Recommend => append_latest_run_keys(app, &mut keys),
        ShellView::Module => append_module_keys(app, &mut keys),
        ShellView::Workbench => append_workbench_keys(app, &mut keys),
        ShellView::Tune | ShellView::PromptsEditor => append_prompt_keys(app, &mut keys),
        ShellView::Threat | ShellView::ThreatEditor | ShellView::Scene => {
            append_threat_model_key(app, &mut keys);
        }
        ShellView::RunDiff => append_run_diff_keys(app, &mut keys),
        ShellView::Replay => append_replay_keys(&mut keys, app.router.replay().run_id()),
        ShellView::Trace => append_trace_keys(&mut keys, app.router.trace().run_id()),
        ShellView::Health => append_health_keys(app, &mut keys),
        ShellView::ProjectModel => append_project_model_keys(app, &mut keys),
        ShellView::StrategyQueue => keys.push(ViewHydrationKey::StrategyQueue),
        ShellView::FailureHandoff | ShellView::AgentChat => {
            append_latest_run_keys(app, &mut keys);
        }
        _ => {}
    }
    keys.sort();
    keys.dedup();
    keys
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

fn rendered_shell_view(app: &ShellApp) -> ShellView {
    app.router
        .overlay_origin()
        .filter(|origin| *origin != app.shell_view())
        .unwrap_or_else(|| app.shell_view())
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

fn append_workbench_keys(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    append_latest_run_keys(app, keys);
    append_threat_model_key(app, keys);
    append_selected_source_key(app, keys);
    append_selected_proof_key(app, keys);
    keys.extend([
        ViewHydrationKey::StrategyQueue,
        ViewHydrationKey::HarnessFile,
    ]);
    let Some(target) = app.target() else {
        return;
    };
    for relative in [".kuzushi/cpg.bin", ".kuzushi/codeql-db"] {
        keys.push(ViewHydrationKey::PathState {
            path: target.join(relative),
        });
    }
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
    keys.push(run_artifact_key(&run_id, "trace.jsonl"));
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

fn append_threat_model_key(app: &ShellApp, keys: &mut Vec<ViewHydrationKey>) {
    let Some(target) = app.target() else {
        return;
    };
    keys.push(ViewHydrationKey::JsonFile {
        path: kuzushi_core::capabilities::persistent_threat_model_path(target),
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
    let mut paths = vec![
        kuzushi_core::workspace_codeql_db_path(target),
        kuzushi_core::legacy_codeql_db_path(target),
        target.join(".kuzushi/cpg.bin"),
    ];
    if let ViewDataState::Ready(checks) = app
        .workbench_cache()
        .borrow()
        .cached_health_checks(Some(target), &credential_env)
    {
        if let Some(path) = checks.configured_joern_cpg {
            paths.push(path);
        }
    }
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
}

fn append_replay_keys(keys: &mut Vec<ViewHydrationKey>, run_id: &str) {
    if run_id.is_empty() {
        return;
    }
    keys.push(run_artifact_key(run_id, "run.json"));
    keys.push(run_artifact_key(run_id, "result.json"));
    keys.push(run_artifact_key(run_id, "triage.jsonl"));
}

fn append_trace_keys(keys: &mut Vec<ViewHydrationKey>, run_id: &str) {
    if run_id.is_empty() {
        return;
    }
    for leaf in ["trace.jsonl", "triage.jsonl", "verify.jsonl", "patch.jsonl"] {
        keys.push(run_artifact_key(run_id, leaf));
    }
    keys.push(ViewHydrationKey::RunTrace {
        run_id: run_id.to_string(),
    });
}

fn run_artifact_key(run_id: &str, leaf: &str) -> ViewHydrationKey {
    ViewHydrationKey::RunArtifactText {
        run_id: run_id.to_string(),
        leaf: leaf.to_string(),
    }
}
