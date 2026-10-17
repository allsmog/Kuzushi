use super::*;
use crate::app::{JsonFileState, ViewDataState};
use std::hash::{Hash, Hasher};

pub(crate) fn worklist_artifact_version(app: &ShellApp) -> Option<u64> {
    let path = kuzushi_core::context_snapshot_path(app.target()?);
    let content_hash = app
        .workbench_cache()
        .borrow()
        .cached_json_file_content_sha256(&path);
    if let Some(content_hash) = content_hash {
        return Some(identity_hash(&("context-content", content_hash)));
    }
    let context_version = app
        .workbench_cache()
        .borrow()
        .cached_nonmissing_json_file_version(&path);
    let identity = (context_version, fallback_artifact_version(app));
    if identity == (None, None) {
        return None;
    }
    Some(identity_hash(&identity))
}

fn fallback_artifact_version(app: &ShellApp) -> Option<u64> {
    let target = app.target()?;
    let cache = app.workbench_cache().borrow();
    let ViewDataState::Ready(kuzushi_core::LatestRunPointerState::Ready(id)) =
        cache.cached_latest_run_pointer(Some(target))
    else {
        return None;
    };
    cache.cached_nonmissing_run_artifact_version(target, id.as_str(), "attack-surface.json")
}

fn identity_hash(value: &impl Hash) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

pub(super) fn worklist_artifact_state(app: &ShellApp) -> AttackSurfaceArtifactState {
    let Some(target) = app.target() else {
        return AttackSurfaceArtifactState::Absent;
    };
    let path = kuzushi_core::context_snapshot_path(target);
    let state = app
        .workbench_cache()
        .borrow()
        .cached_json_file(target, &path);
    match state {
        ViewDataState::Ready(JsonFileState::Present(value)) => context_map_state(value),
        ViewDataState::Ready(
            JsonFileState::Malformed | JsonFileState::Unreadable | JsonFileState::NonFile,
        ) => AttackSurfaceArtifactState::CorruptOrUnreadable,
        _ => attack_surface_artifact_state(app),
    }
}

fn context_map_state(value: serde_json::Value) -> AttackSurfaceArtifactState {
    match value.get("attackSurfaceMap") {
        Some(map) => AttackSurfaceArtifactState::Present(map.clone()),
        None => AttackSurfaceArtifactState::CorruptOrUnreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context_value(path: &str) -> serde_json::Value {
        json!({"attackSurfaceMap":{"rootName":"owned synthetic metadata",
            "surfaces":[{"id":"owned-synthetic", "kind":"cli_entrypoint", "path":path,
                "language":"rust", "title":"Synthetic metadata", "evidence":"Synthetic metadata",
                "risk":{"rank":1,"score":42,"tier":"medium","reasons":[]}, "metadata":null}],
            "summary":{"total":1,"byKind":{"cli_entrypoint":1},"byFile":{path:1}}}})
    }

    fn cache_context(app: &mut ShellApp, value: &serde_json::Value) {
        let path = kuzushi_core::context_snapshot_path(app.target().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, value.to_string()).unwrap();
        app.workbench_cache()
            .borrow_mut()
            .invalidate_json_file(&path);
        app.hydrate_active_view_blocking();
    }

    #[test]
    fn saved_context_builds_worklist_without_any_latest_run_artifact() {
        let root = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(root.path().to_path_buf()));
        cache_context(&mut app, &context_value("src/saved-settings.rs"));
        assert!(attack_surface_artifact_version(&app).is_none());
        let model = worklist_model(&app);
        assert_eq!(model.ranked_total, 1);
        assert_eq!(model.rows[0].location, "src/saved-settings.rs");
        assert!(model.rows[0].summary.contains("42/100"));
    }

    #[test]
    fn regenerated_saved_context_invalidates_an_earlier_capture() {
        let root = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(root.path().to_path_buf()));
        cache_context(&mut app, &context_value("src/before.rs"));
        let before = worklist_artifact_version(&app);
        app.cache_tool_snapshot(
            "worklist:rank",
            &json!({"data":{
            "target":root.path(), "rows":[{"rank":1,"path":"src/captured.rs","citations":[]}],
            "rankedTotal":1}}),
        );
        assert_eq!(worklist_model(&app).rows[0].location, "src/captured.rs");
        cache_context(&mut app, &context_value("src/before.rs"));
        assert_eq!(worklist_artifact_version(&app), before);
        assert_eq!(worklist_model(&app).rows[0].location, "src/captured.rs");
        cache_context(&mut app, &context_value("src/after.rs"));
        assert_ne!(worklist_artifact_version(&app), before);
        assert_eq!(worklist_model(&app).rows[0].location, "src/after.rs");
    }

    #[test]
    fn unreadable_context_is_disclosed_instead_of_a_missing_map_claim() {
        let root = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(root.path().to_path_buf()));
        cache_context(
            &mut app,
            &json!({"unrelated":"synthetic malformed context"}),
        );
        let model = worklist_model(&app);
        assert!(model.rows.is_empty());
        assert!(model
            .degraded
            .iter()
            .any(|reason| reason.contains("unreadable")));
    }
    #[test]
    fn hydrating_missing_context_and_run_artifacts_preserves_an_explicit_ranking() {
        let root = tempfile::tempdir().unwrap();
        let dir = kuzushi_core::workspace::workspace_state_dir(root.path()).join("runs/owned-rank");
        std::fs::create_dir_all(&dir).unwrap();
        let mut run = kuzushi_core::RunSummary::running(
            "owned-rank",
            "tool",
            Some("worklist:rank".into()),
            root.path().display().to_string(),
        );
        run.status = "partial".into();
        std::fs::write(dir.join("run.json"), serde_json::to_vec(&run).unwrap()).unwrap();
        std::fs::write(
            dir.parent().unwrap().parent().unwrap().join("latest"),
            "owned-rank",
        )
        .unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(root.path().to_path_buf()));
        let data = json!({"target":root.path(),"rows":[{"rank":1,"path":"owned.c","citations":[]}],"rankedTotal":1,"contributors":{"systemsHunt":"live"}});
        let before = worklist_artifact_version(&app);
        app.cache_tool_snapshot("worklist:rank", &json!({"data":data}));
        app.hydrate_all_view_data_for_test();
        assert_eq!(worklist_artifact_version(&app), before);
        assert_eq!(worklist_model(&app).rows[0].location, "owned.c");
    }
}
