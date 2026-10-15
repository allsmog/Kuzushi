use super::*;

#[test]
fn observations_are_an_explicit_scope_action_and_preserve_the_draft_and_job() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("owned.rs"),
        "// Owned inert fixture, never executed\n",
    )
    .unwrap();
    kuzushi_core::capabilities::campaign::compile_scan_batch_plan(
        kuzushi_core::capabilities::campaign::ScanBatchPlanSpec {
            root: root.path(),
            batch_id: Some("owned-observations".into()),
            trials: 3,
            requested_workers: 1,
            gate_policy: Default::default(),
            prepared_input: serde_json::json!({"taskMode":"manual","tasks":["secret-scan"]}),
            config: &kuzushi_core::V2Config::default(),
            registry: &kuzushi_core::ModuleRegistry::with_v2_builtins(),
        },
    )
    .unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_campaign_view(Some("owned-observations".into()));
    assert!(app.router.campaign().active_batch_id.is_none());
    app.router.campaign_mut().selected_job = 1;
    app.set_input("held operator draft");
    app.apply_campaign_hotkey(ViewHotkeyAction::CampaignOpenObservations);
    assert_eq!(
        app.router.campaign().active_batch_id.as_deref(),
        Some("owned-observations")
    );
    assert_eq!(app.router.campaign().selected_job, 1);
    assert!(app
        .router
        .campaign()
        .notice
        .as_deref()
        .unwrap()
        .contains("batch clear"));
    assert_eq!(app.input(), "held operator draft");
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert!(!kuzushi_core::capabilities::campaign::campaign_queue_path(
        root.path(),
        "owned-observations"
    )
    .exists());
    assert!(app
        .router
        .campaign()
        .active_batch_report
        .as_ref()
        .unwrap()
        .all_attempt_run_ids()
        .is_empty());
}

#[test]
fn unsupported_campaign_does_not_replace_the_review_scope() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.router.campaign_mut().active_batch_id = Some("retained-scope".into());
    app.apply_campaign_hotkey(ViewHotkeyAction::CampaignOpenObservations);
    assert_eq!(
        app.router.campaign().active_batch_id.as_deref(),
        Some("retained-scope")
    );
    assert!(app
        .router
        .campaign()
        .notice
        .as_deref()
        .unwrap()
        .contains("Select a discovery batch"));
}
