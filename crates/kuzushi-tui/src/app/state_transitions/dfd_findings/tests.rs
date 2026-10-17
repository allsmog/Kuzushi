use super::*;
use kuzushi_core::{ScopeRef, ThreatModelCommit, ThreatModelRevisionSource, V2Config};
use serde_json::json;

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let target = tempfile::tempdir().unwrap();
    let document = json!({"version":"1","methodology":"stride","summary":{},"threats":[],
        "dfd":{"nodes":[
            {"id":"api","name":"API","type":"process","trustZone":"application"},
            {"id":"store","name":"Store","type":"data_store","trustZone":"data"}],
            "flows":[{"id":"record","sourceId":"api","targetId":"store","description":"Stored input","trustBoundaryIds":["edge"]}],
            "trustBoundaries":[{"id":"edge","name":"Storage boundary","outerZone":"application","innerZone":"data","crossingFlowIds":["record"]}]},
        "attackSurface":{"entryPoints":[
            {"id":"EP-a","name":"First source","path":"src/a b.rs","targetElementIds":["api","record","edge"]},
            {"id":"EP-b","name":"Second source","path":"src/a,b.rs","targetElementIds":["api","record","edge"]}],
            "roleGates":[],"externalSinks":[],"trustedCallers":[]}});
    kuzushi_core::capabilities::commit_threat_model_revision(
        target.path(),
        &document,
        ThreatModelCommit {
            model_id: None,
            new_model: true,
            label: "Owned diagram".into(),
            scope: ScopeRef::legacy_root(target.path(), &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(),
            source: ThreatModelRevisionSource::Import,
            source_revision_id: None,
            run_id: None,
            activate: Some(true),
            actor: "fixture".into(),
        },
    )
    .unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.hydrate_all_view_data_for_test();
    app.open_map_scene_to_page(crate::scene3d::VizPage::Dfd);
    app.set_input_mode(crate::InputMode::Navigate);
    assert_eq!(
        crate::ui_view_models::dfd_model(&app).link_state,
        crate::ui_view_models::DfdLinkState::Complete
    );
    (target, app)
}

fn filter(update: &InputUpdate) -> kuzushi_core::FindingListFilter {
    assert_eq!(update.effects.len(), 1);
    let ShellEffect::RefreshFindings(request) = &update.effects[0] else {
        panic!("DFD navigation may only request a ledger read");
    };
    kuzushi_core::FindingListFilter::from_filter_expression(request.filter.as_deref().unwrap())
        .unwrap()
}

fn settle(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while app.findings_refresh_status().is_some() {
        app.apply_view_hydration_results();
        assert!(
            std::time::Instant::now() < deadline,
            "ledger refresh settles: {:?}",
            app.findings_refresh_status()
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn nodes_flows_and_boundaries_open_all_evidence_paths_without_work() {
    for selected in [0, 2, 3] {
        let (_target, mut app) = fixture();
        app.router.scene_mut().set_dfd_selection(selected, 4);
        let update = app.open_selected_dfd_findings();
        assert_eq!(filter(&update).file_paths, ["src/a b.rs", "src/a,b.rs"]);
        assert_eq!(app.shell_view(), ShellView::Workbench);
        assert_eq!(
            app.router.workbench().page(),
            Some(crate::app::WorkbenchPage::Review)
        );
        assert!(app.activity().is_none());
    }
}

#[test]
fn focused_context_row_narrows_the_file_selection() {
    let (_target, mut app) = fixture();
    app.router.scene_mut().toggle_dfd_focus();
    app.router.scene_mut().cycle_dfd_context_selection(1, 2);
    let update = app.open_selected_dfd_findings();
    assert_eq!(filter(&update).file_paths, ["src/a,b.rs"]);
}

#[test]
fn back_restores_graph_mode_selection_and_original_workflow_origin() {
    let (_target, mut app) = fixture();
    app.router.scene_mut().set_dfd_selection(2, 4);
    app.router.scene_mut().toggle_dfd_focus();
    app.set_input("unsent operator draft");
    app.set_cursor(4);
    app.set_active_findings_filter(Some("rank:critical".into()));
    let overlay = app.router.overlay_origin();
    let workbench = app.router.workbench().clone();
    app.open_selected_dfd_findings();
    app.go_back();
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert_eq!(app.router.overlay_origin(), overlay);
    assert_eq!(app.router.workbench(), &workbench);
    assert_eq!(app.router.scene().dfd_selection(), 2);
    assert!(app.router.scene().dfd_focused());
    assert_eq!(app.input(), "unsent operator draft");
    assert_eq!(app.cursor(), 4);
    assert_eq!(
        app.active_findings_filter().as_deref(),
        Some("rank:critical")
    );
    app.go_back();
    assert_eq!(Some(app.shell_view()), overlay);
}

#[test]
fn embedded_map_returns_to_its_existing_projection() {
    let (_target, mut app) = fixture();
    app.set_shell_view(ShellView::Workbench);
    app.set_workbench_page(crate::app::WorkbenchPage::Map);
    let before = app.router.workbench().clone();
    app.open_selected_dfd_findings();
    assert!(app.restore_dfd_review_origin());
    assert_eq!(app.router.workbench(), &before);
    assert_eq!(app.shell_view(), ShellView::Workbench);
}

#[test]
fn absent_evidence_and_changed_target_do_not_redirect_to_old_context() {
    let (_target, mut app) = fixture();
    app.router.scene_mut().set_dfd_selection(1, 4);
    let update = app.open_selected_dfd_findings();
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Scene);
    app.router.scene_mut().set_dfd_selection(0, 4);
    app.open_selected_dfd_findings();
    app.set_target(None);
    assert!(!app.restore_dfd_review_origin());
}

#[test]
fn prompt_text_owns_f_while_a_draft_is_present() {
    let (_target, mut app) = fixture();
    app.set_input_mode(crate::InputMode::Prompt);
    app.set_input("draft");
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert_eq!(app.input(), "draftf");
}

#[test]
fn evidence_paths_are_literal_contained_and_deduplicated() {
    let target = Path::new("/owned");
    let paths = [
        "src/a b.rs:3-8",
        "./src/a,b.rs#L7",
        "/owned/src/a b.rs:3-8",
        "../outside.rs",
        "/elsewhere/outside.rs",
        "src/../outside.rs",
        "https://example.test/a.rs",
    ];
    assert_eq!(
        evidence_finding_paths(target, paths.into_iter().map(str::to_string).collect()),
        ["src/a b.rs:3-8", "src/a,b.rs#L7"]
    );
}

#[test]
fn structured_paths_and_text_citations_keep_distinct_exact_file_queries() {
    let (_target, mut app) = fixture();
    let document = json!({
        "dfd":{"nodes":[{"id":"api","name":"API","type":"process","trustZone":"app"}],"flows":[],"trustBoundaries":[]},
        "attackSurface":{"entryPoints":[{"id":"EP-literal","name":"Literal paths","path":"src/a.rs:7","affectedFiles":["src/a  b.rs#L9","src/`code`.rs"],"evidenceRefs":[{"source":"src/a.rs:7"}],"targetElementIds":["api"]}]}
    });
    let model = crate::ui_view_models::study_context::context_diagram_model(&document, None);
    let update = app.open_dfd_finding_query(&model, 0, None);
    assert_eq!(
        filter(&update).file_paths,
        ["src/`code`.rs", "src/a  b.rs#L9", "src/a.rs", "src/a.rs:7"]
    );
}

#[test]
fn navigate_q_returns_to_the_diagram_and_prompt_q_remains_text() {
    let (_target, mut app) = fixture();
    app.set_input("preserved draft");
    let update = app.open_selected_dfd_findings();
    crate::app::EffectRuntime::execute(&mut app, update.effects);
    settle(&mut app);
    assert!(app.dfd_review_return_is_available());
    assert!(app.dfd_path_query_is_active());
    app.set_input_mode(crate::InputMode::Prompt);
    app.reduce_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(app.input().contains('q'));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    app.set_input_mode(crate::InputMode::Navigate);
    app.reduce_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert!(!app.dfd_review_return_is_available());
}

#[test]
fn revision_disclosure_tracks_the_link_query_but_return_survives_filter_edits() {
    let (_target, mut app) = fixture();
    let update = app.open_selected_dfd_findings();
    crate::app::EffectRuntime::execute(&mut app, update.effects);
    settle(&mut app);
    assert!(
        crate::ui_view_models::review_queue_model(
            &app,
            crate::ui_view_models::ReviewQueueMode::All
        )
        .path_history
    );
    app.set_active_findings_filter(Some("severity:high".into()));
    assert!(app.dfd_review_return_is_available());
    assert!(!app.dfd_path_query_is_active());
}

#[test]
fn returning_from_a_new_query_restores_the_prior_ledger_page() {
    let (target, mut app) = fixture();
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("owned-page", workspace.root(), "completed")
        .unwrap();
    let rows = (0..7)
        .map(|index| {
            kuzushi_core::Finding::new_tool(
                "fixture",
                &format!("case.{index}"),
                "src/a b.rs",
                1,
                None,
                kuzushi_core::Severity::High,
                &format!("Synthetic page reader observation {index}"),
            )
        })
        .collect::<Vec<_>>();
    store.insert_findings("owned-page", &rows).unwrap();
    app.option_store_mut().set_value(
        kuzushi_core::OptionScope::Session,
        kuzushi_core::OptionTarget::Tool("sast:scan".into()),
        "identityFold",
        json!("legacy"),
    );
    app.set_shell_view(ShellView::Workbench);
    app.set_workbench_page(crate::app::WorkbenchPage::Review);
    app.refresh_findings_filtered("limit:2");
    app.move_findings_page(true);
    assert_eq!(app.domain().findings_page().unwrap().offset, 2);
    let before = app
        .findings()
        .iter()
        .map(|finding| finding.fingerprint.clone())
        .collect::<Vec<_>>();
    app.open_map_scene_to_page(crate::scene3d::VizPage::Dfd);
    app.hydrate_all_view_data_for_test();
    let update = app.open_selected_dfd_findings();
    assert_eq!(filter(&update).file_paths.len(), 2);
    crate::app::EffectRuntime::execute(&mut app, update.effects);
    settle(&mut app);
    assert_eq!(app.findings().len(), 7);
    app.go_back();
    settle(&mut app);
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert_eq!(app.active_findings_filter().as_deref(), Some("limit:2"));
    assert_eq!(app.domain().findings_page().unwrap().offset, 2);
    assert_eq!(
        app.findings()
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect::<Vec<_>>(),
        before
    );
}
