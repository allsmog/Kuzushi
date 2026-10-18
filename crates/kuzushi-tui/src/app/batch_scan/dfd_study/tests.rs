use super::*;
use crate::app::InputMode;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{
    ScopeRef, ThreatModelCommit, ThreatModelRevisionSource, V2Config, WorkspaceTarget,
};
use serde_json::json;

fn graph() -> Value {
    json!({"version":"1","methodology":"stride","summary":{},"threats":[],
        "dfd":{"nodes":[{"id":"api","name":"Request API","type":"process","trustZone":"app"},
            {"id":"store","name":"Store","type":"data_store","trustZone":"data"}],
            "flows":[{"id":"save","sourceId":"api","targetId":"store","description":"Store input","trustBoundaryIds":["edge"]}],
            "trustBoundaries":[{"id":"edge","name":"Storage edge","outerZone":"app","innerZone":"data","crossingFlowIds":["save"]}]},
        "attackSurface":{"entryPoints":[{"id":"first","name":"Spaced source","path":" app /source.rs","targetElementIds":["api","save","edge"]},
            {"id":"second","name":"Other source","path":"src/a,b.rs","targetElementIds":["api","save","edge"]}],"roleGates":[],"externalSinks":[],"trustedCallers":[]}})
}

fn fixture() -> (tempfile::TempDir, ShellApp, ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    for file in [" app /source.rs", "src/a,b.rs", "loose.rs"] {
        let path = root.path().join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "// owned source fixture\n").unwrap();
    }
    let reference = kuzushi_core::capabilities::commit_threat_model_revision(
        root.path(),
        &graph(),
        ThreatModelCommit {
            model_id: None,
            new_model: true,
            label: "Owned DFD".into(),
            scope: ScopeRef::legacy_root(root.path(), &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(),
            source: ThreatModelRevisionSource::Import,
            source_revision_id: None,
            run_id: None,
            activate: Some(true),
            actor: "fixture".into(),
        },
    )
    .unwrap()
    .model_ref;
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.hydrate_all_view_data_for_test();
    app.open_map_scene_to_page(crate::scene3d::VizPage::Dfd);
    app.set_input_mode(InputMode::Navigate);
    (root, app, reference)
}

fn config(app: &ShellApp) -> &BatchScanConfig {
    app.router.campaign().batch_scan_config.as_ref().unwrap()
}

#[test]
fn node_flow_and_boundary_plan_only_exact_linked_paths_with_three_pass_defaults() {
    for selected in [0, 2, 3] {
        let (root, mut app, reference) = fixture();
        app.router.scene_mut().set_dfd_selection(selected, 4);
        let update = app.open_selected_dfd_study();
        assert!(update.effects.is_empty());
        let config = config(&app);
        assert_eq!(
            config.study.scan_input.as_ref().unwrap()["paths"],
            json!([" app /source.rs", "src/a,b.rs"])
        );
        assert_eq!(
            config.study.scan_input.as_ref().unwrap()["threatModelRef"],
            json!(reference)
        );
        assert_eq!(
            (
                config.trials,
                config.requested_workers,
                config.study.max_job_attempts
            ),
            (3, 1, 1)
        );
        assert!(!config.study.approved());
        assert!(config.study.plan_identity().is_none());
        let notice = config.notice.as_ref().unwrap();
        assert!(notice.contains("2 exact source paths (quoted)"));
        assert!(notice.contains("\" app /source.rs\"") && notice.contains("\"src/a,b.rs\""));
        assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
        assert!(app.router.campaign().dispatcher_pid.is_none());
    }
}

#[test]
fn focused_context_narrows_paths_and_back_restores_scene_and_unsent_composer() {
    let (_root, mut app, _) = fixture();
    app.router.scene_mut().toggle_dfd_focus();
    app.router.scene_mut().cycle_dfd_context_selection(1, 2);
    let scene = app.router.scene().clone();
    let overlay = app.router.overlay_origin();
    app.set_input("unsent\noperator draft");
    app.set_cursor(4);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    assert_eq!(
        config(&app).study.scan_input.as_ref().unwrap()["paths"],
        json!(["src/a,b.rs"])
    );
    app.finish_closing_study();
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert_eq!(app.router.scene(), &scene);
    assert_eq!(app.router.overlay_origin(), overlay);
    assert_eq!((app.input(), app.cursor()), ("unsent\noperator draft", 4));
}

#[test]
fn prompt_and_modified_keys_cannot_open_scan_plans() {
    let (_root, mut app, _) = fixture();
    app.set_input_mode(InputMode::Prompt);
    app.set_input("draft");
    app.reduce_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    assert_eq!(app.input(), "drafts");
    assert!(app.router.campaign().batch_scan_config.is_none());
    app.set_input_mode(InputMode::Navigate);
    app.reduce_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::ALT));
    assert!(app.router.campaign().batch_scan_config.is_none());
}

#[test]
fn typing_a_scan_command_from_an_empty_prompt_keeps_composer_ownership() {
    let (_root, mut app, _) = fixture();
    app.set_input_mode(InputMode::Prompt);
    app.set_input("");
    for character in "scan batch".chars() {
        app.reduce_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
    }
    assert_eq!(app.input(), "scan batch");
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert!(app.router.campaign().batch_scan_config.is_none());
}

#[test]
fn missing_links_or_reference_keep_the_current_diagram_and_create_no_jobs() {
    let (root, mut app, reference) = fixture();
    let model = crate::ui_view_models::dfd_model(&app);
    app.open_dfd_scan_study(&model, 1, None, Ok(reference));
    assert!(app.router.campaign().batch_scan_config.is_none());
    app.open_dfd_scan_study(&model, 0, None, Err("Exact revision unavailable".into()));
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn invalid_mixed_or_excessive_evidence_does_not_drop_paths_or_open_a_plan() {
    let (root, mut app, reference) = fixture();
    for invalid in [
        "../outside.rs",
        "https://example.test/a.rs",
        "/elsewhere/a.rs",
        ".",
    ] {
        let mut document = graph();
        document["attackSurface"]["entryPoints"][1]["path"] = json!(invalid);
        let model = crate::ui_view_models::study_context::context_diagram_model(
            &document,
            Some(root.path()),
        );
        app.open_dfd_scan_study(&model, 0, None, Ok(reference.clone()));
        assert!(
            app.router.campaign().batch_scan_config.is_none(),
            "{invalid}"
        );
    }
    let mut document = graph();
    document["attackSurface"]["entryPoints"][0]["affectedFiles"] =
        json!((0..257).map(|i| format!("src/{i}.rs")).collect::<Vec<_>>());
    let model =
        crate::ui_view_models::study_context::context_diagram_model(&document, Some(root.path()));
    app.open_dfd_scan_study(&model, 0, None, Ok(reference));
    assert!(app.router.campaign().batch_scan_config.is_none());
}

#[test]
fn a_follow_up_cannot_open_another_nested_study_or_inherit_approval() {
    let (_root, mut app, reference) = fixture();
    let model = crate::ui_view_models::dfd_model(&app);
    app.open_selected_dfd_study();
    let checkpoint = config(&app).checkpoint_id.clone();
    app.open_dfd_scan_study(&model, 0, None, Ok(reference));
    assert_eq!(config(&app).checkpoint_id, checkpoint);
    assert!(config(&app).study.plan_identity().is_none());
    assert!(!config(&app).study.approved());
}

#[test]
fn approved_job_browser_returns_to_the_exact_diagram_without_launching() {
    let (_root, mut app, _) = fixture();
    let scene = app.router.scene().clone();
    app.open_selected_dfd_study();
    let child = config(&app).clone();
    app.retain_dfd_study_return(&child);
    app.router.campaign_mut().batch_scan_config = None;
    assert!(app.dfd_study_jobs_navigation_active());
    assert!(app
        .view_keybindings()
        .iter()
        .any(|binding| binding.label == "diagram"));
    app.router.campaign_mut().job_detail = true;
    assert!(!app.restore_dfd_study_jobs_origin());
    app.router.campaign_mut().job_detail = false;
    app.go_back();
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert_eq!(app.router.scene(), &scene);
    assert!(app.router.campaign().dfd_study_return.is_none());
    assert!(app.router.campaign().dispatcher_pid.is_none());
}

#[test]
fn changed_target_does_not_restore_the_previous_diagram_or_parent() {
    let (_root, mut app, _) = fixture();
    app.open_selected_dfd_study();
    let next = tempfile::tempdir().unwrap();
    app.set_target(Some(next.path().to_path_buf()));
    app.finish_closing_study();
    assert_ne!(app.shell_view(), ShellView::Scene);
    assert!(app.router.campaign().batch_scan_config.is_none());
}

#[test]
fn plan_compilation_uses_shared_prepared_dispatch_and_never_reintroduces_stored_scope() {
    let (root, mut app, reference) = fixture();
    app.option_store_mut().set_value(
        kuzushi_core::OptionScope::Session,
        kuzushi_core::OptionTarget::Tool("sast:scan".into()),
        "scanScopeRef",
        json!({"proposal":{"invalid":"old"},"scopeId":"old"}),
    );
    app.open_selected_dfd_study();
    let mut draft =
        super::super::launch::study_input(&app, root.path(), config(&app), "dfd-test").unwrap();
    draft["scanInput"]["taskMode"] = json!("manual");
    draft["scanInput"]["tasks"] = json!(["secret-scan"]);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let ctx = kuzushi_core::modules::ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = app
        .registry()
        .prepare_dispatch_input("campaign:study", draft, &ctx, None)
        .unwrap();
    let result = app
        .registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(result["data"]["jobCount"], 3);
    assert_eq!(
        result["data"]["scanInput"]["paths"],
        json!([" app /source.rs", "src/a,b.rs"])
    );
    assert_eq!(
        result["data"]["scanInput"]["threatModelRef"],
        json!(reference)
    );
    assert!(result["data"]["scanInput"].get("scanScopeRef").is_none());
    assert!(app.router.campaign().dispatcher_pid.is_none());
}

#[test]
fn returning_after_approval_reloads_shared_accounting_and_preserves_parent_choices() {
    let (root, mut app, _) = fixture();
    app.open_batch_scan_config(None);
    let parent = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    parent.trials = 5;
    parent.study.investigation_id = "shared-parent".into();
    parent.study.max_provider_calls = Some(9);
    parent.study.protected_review_calls = Some(3);
    app.open_selected_dfd_study();
    let mut draft =
        super::super::launch::study_input(&app, root.path(), config(&app), "return-accounting")
            .unwrap();
    draft["scanInput"]["taskMode"] = json!("manual");
    draft["scanInput"]["tasks"] = json!(["secret-scan"]);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let ctx = kuzushi_core::modules::ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    kuzushi_core::capabilities::campaign::execute_study_plan(&draft, &ctx).unwrap();
    let receipt = kuzushi_core::capabilities::campaign::load_study_plan_receipt(
        root.path(),
        "return-accounting",
    )
    .unwrap();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .record_receipt(receipt);
    let limiter = kuzushi_core::SpendLimiter::open(workspace.findings_db_path()).unwrap();
    limiter
        .approve_allowance(&kuzushi_core::allowance::AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: "shared-parent".into(),
            expected_revision: 0,
            model: "openai-codex:gpt-5.5".into(),
            limits: kuzushi_core::allowance::AllowanceLimits {
                max_provider_calls: 5,
                protected_review_calls: 2,
            },
            reason: "Synthetic local accounting only".into(),
            work_plan: None,
        })
        .unwrap();
    app.finish_closing_study();
    let parent = config(&app);
    assert_eq!(parent.trials, 5);
    assert_eq!(parent.study.max_provider_calls, Some(9));
    assert_eq!(parent.study.protected_review_calls, Some(3));
    let snapshot = parent.study.allowance.as_ref().unwrap();
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.limits.max_provider_calls, 5);
    assert!(!parent.study.approved());
}
