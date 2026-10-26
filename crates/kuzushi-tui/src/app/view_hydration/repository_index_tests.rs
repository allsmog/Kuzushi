use super::*;

#[test]
fn external_repository_index_refreshes_the_projection_without_taking_input() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.hydrate_active_view_blocking();
    assert!(!app.domain().context_view().exists);
    app.set_input("held operator draft λ");
    let snapshot = kuzushi_core::context_snapshot_path(root.path());
    std::fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
    std::fs::write(&snapshot, r#"{"filesIndexed":3,"fileIndex":[]}"#).unwrap();
    let effects = app
        .apply_external_workspace_state_change(&[PathBuf::from(".kuzushi/context-snapshot.json")]);
    EffectRuntime::execute(&mut app, effects);
    app.hydrate_active_view_blocking();

    assert!(app.domain().context_view().exists);
    assert_eq!(app.domain().context_view().files_indexed, Some(3));
    assert_ne!(
        app.domain().context_view().freshness,
        Some(kuzushi_core::context::ContextSnapshotFreshness::Current)
    );
    assert_eq!(app.input(), "held operator draft λ");
    assert_eq!(app.shell_view(), ShellView::Workbench);
}

#[test]
fn changed_malformed_and_removed_indexes_replace_the_old_projection() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let path = kuzushi_core::context_snapshot_path(root.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for (body, exists, state) in [
        (
            Some(r#"{"filesIndexed":5,"fileIndex":[]}"#),
            true,
            "unverifiable",
        ),
        (Some("{"), false, "malformed"),
        (None, false, "missing"),
    ] {
        match body {
            Some(body) => std::fs::write(&path, body).unwrap(),
            None => std::fs::remove_file(&path).unwrap(),
        }
        let effects = app.apply_external_workspace_state_change(&[PathBuf::from(
            ".kuzushi/context-snapshot.json",
        )]);
        EffectRuntime::execute(&mut app, effects);
        app.hydrate_active_view_blocking();
        assert_eq!(app.domain().context_view().exists, exists);
        assert_eq!(crate::ui_view_models::context_snapshot_state(&app), state);
    }
}

#[test]
fn failed_index_read_preserves_an_explicit_unavailable_state_and_draft() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Context);
    app.set_input("held index inspection");
    app.apply_view_hydration_drain(ViewHydrationDrain {
        results: vec![],
        failures: vec![ViewHydrationFailure {
            target: workspace.root().to_path_buf(),
            key: ViewHydrationKey::RepositoryIndex,
        }],
    });
    assert_eq!(
        crate::ui_view_models::context_snapshot_state(&app),
        "unavailable"
    );
    let plain = crate::renderer::render_plain_app(&app, 80);
    assert!(plain.contains("repository index read failed"), "{plain}");
    assert!(!plain.contains("No context snapshot exists"), "{plain}");
    assert_eq!(app.input(), "held index inspection");
}
