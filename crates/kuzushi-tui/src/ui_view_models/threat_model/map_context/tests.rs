use super::*;
use crate::test_support::{append_typed_attempt, record_indexed_run, select_typed_attempt};
use crate::ui_view_models::{dfd_model, threat_model_doc, threat_model_freshness};
use kuzushi_core::capabilities::threat_model::{
    commit_threat_model_revision, load_active_threat_model, threat_model_object_path, ScopeRef,
    ThreatModelCommit, ThreatModelRevisionSource,
};
use kuzushi_core::workflow_attempts::*;
use serde_json::json;

fn model(root: &std::path::Path, label: &str) -> (ThreatModelRef, serde_json::Value) {
    let document = json!({"version":"1", "methodology":"stride", "title":label,
        "dfd":{"nodes":[{"id":"caller","type":"external_entity","name":format!("{label} caller"),"trustZone":"external"},
            {"id":"app","type":"process","name":format!("{label} receiver"),"trustZone":"internal"}],
            "flows":[{"id":"request","sourceId":"caller","targetId":"app","description":"Selected request"}],"trustBoundaries":[]},
        "threats":[], "summary":{}});
    let reference = commit_threat_model_revision(
        root,
        &document,
        ThreatModelCommit {
            model_id: None,
            new_model: true,
            label: label.into(),
            scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(),
            source: ThreatModelRevisionSource::Import,
            source_revision_id: None,
            run_id: None,
            activate: Some(true),
            actor: "test".into(),
        },
    )
    .unwrap()
    .model_ref;
    (reference, document)
}

fn bind(app: &mut ShellApp, root: &std::path::Path, run: &str, selected: bool) {
    let completed = append_typed_attempt(
        root,
        WorkflowPhase::Map,
        run,
        PhaseAttemptOutcome::Completed,
    );
    if selected {
        select_typed_attempt(root, &completed);
    }
    app.refresh_phase_attempt_projection();
}

fn fixture(selected: bool) -> (tempfile::TempDir, ShellApp, ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("reader.py"), "print('Offline fixture')\n").unwrap();
    let (alpha, document) = model(root.path(), "Alpha");
    record_indexed_run(
        root.path(),
        "alpha-map",
        "threat-model:build",
        json!({"ok":true,"status":"completed","data":{"document":document,"modelRef":alpha}}),
    );
    model(root.path(), "Beta");
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.set_workbench_page(crate::app::WorkbenchPage::Map);
    bind(&mut app, root.path(), "alpha-map", selected);
    app.hydrate_all_view_data_for_test();
    (root, app, alpha)
}

#[test]
fn accepted_map_and_reviewing_map_keep_exact_context_without_activation() {
    for selected in [false, true] {
        let (root, app, alpha) = fixture(selected);
        assert_eq!(displayed_threat_model_ref(&app).unwrap(), alpha);
        assert_eq!(threat_model_doc(&app).unwrap()["title"], "Alpha");
        assert!(dfd_model(&app)
            .nodes
            .iter()
            .any(|node| node.name == "Alpha receiver"));
        let freshness = threat_model_freshness(&app);
        assert_eq!(freshness.document_sha256, Some(alpha.sha256));
        assert!(freshness.verdict.contains(if selected {
            "accepted"
        } else {
            "awaiting review"
        }));
        assert_eq!(
            super::super::threat_summary_review(&app).status,
            if selected {
                "accepted Map context"
            } else {
                "Map context awaiting review"
            }
        );
        let project = crate::ui_view_models::project_model(&app);
        let row = project
            .rows
            .iter()
            .find(|row| row.section == "threat model")
            .unwrap();
        assert_eq!(row.state, "present");
        assert_eq!(row.origin, crate::ui_view_models::ProjectModelOrigin::Local);
        assert!(row.summary.contains("assumptions 0"));
        assert_eq!(
            load_active_threat_model(root.path())
                .unwrap()
                .unwrap()
                .document["title"],
            "Beta"
        );
    }
}

#[test]
fn reference_loading_or_absent_map_never_falls_back_to_another_active_revision() {
    assert!(recorded_context_ref(ViewDataState::Loading).is_err());
    assert!(recorded_context_ref(ViewDataState::Ready(Ok(None))).is_err());
    assert_eq!(
        recorded_context_ref(ViewDataState::Ready(Err("missing recorded Map".into()))).unwrap_err(),
        "missing recorded Map"
    );
}

#[test]
fn recorded_map_context_without_global_context_artifacts_never_claims_no_model_exists() {
    for selected in [false, true] {
        let (root, app, _) = fixture(selected);
        assert!(!root.path().join(".kuzushi/context.md").exists());
        let cockpit =
            crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Map);
        let crate::ui_view_models::PhaseCockpitBody::Map(map) = cockpit.body else {
            panic!("Map projection required")
        };
        assert!(map.empty_hint.is_none(), "{:?}", map.empty_hint);
        assert!(map
            .dfd
            .nodes
            .iter()
            .any(|node| node.name == "Alpha receiver"));
        assert_eq!(
            load_active_threat_model(root.path())
                .unwrap()
                .unwrap()
                .document["title"],
            "Beta"
        );
        let plain = crate::renderer::render_plain_app(&app, 120);
        assert!(!plain.contains("No threat model detected"), "{plain}");
        assert!(
            !plain.contains("This attempt carried no map evidence"),
            "{plain}"
        );
    }
}

#[test]
fn source_change_labels_recorded_context_as_historical() {
    let (root, mut app, _) = fixture(true);
    std::fs::write(root.path().join("reader.py"), "print('Changed source')\n").unwrap();
    app.refresh_phase_attempt_projection();
    app.hydrate_all_view_data_for_test();
    assert_eq!(
        super::super::threat_summary_review(&app).status,
        "historical Map context"
    );
    assert!(threat_model_freshness(&app)
        .verdict
        .contains("historical source"));
    assert_eq!(threat_model_doc(&app).unwrap()["title"], "Alpha");
}

#[test]
fn explicit_global_editor_keeps_the_active_model() {
    let (_, mut app, _) = fixture(true);
    app.set_shell_view(ShellView::ThreatEditor);
    assert_eq!(threat_model_doc(&app).unwrap()["title"], "Beta");
    app.set_shell_view(ShellView::Scene);
    assert_eq!(threat_model_doc(&app).unwrap()["title"], "Alpha");
}

#[test]
fn disappeared_map_object_and_loading_never_display_an_unrelated_model() {
    let (root, mut app, alpha) = fixture(true);
    std::fs::remove_file(threat_model_object_path(root.path(), &alpha.sha256).unwrap()).unwrap();
    app.workbench_cache()
        .borrow_mut()
        .invalidate_threat_model(root.path());
    assert!(threat_model_doc(&app).is_none());
    assert!(dfd_model(&app)
        .empty_hint
        .unwrap()
        .contains("Checking recorded Map context"));
    app.hydrate_all_view_data_for_test();
    assert!(threat_model_doc(&app).is_none());
    assert!(dfd_model(&app)
        .empty_hint
        .unwrap()
        .contains("Recorded Map context unavailable"));
    assert!(threat_model_freshness(&app).requires_attention);
    let plain = crate::renderer::render_plain_app(&app, 80);
    assert!(
        plain.contains("Recorded Map context unavailable"),
        "{plain}"
    );
    assert!(!plain.contains("Beta receiver"), "{plain}");
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        app.set_workbench_page(crate::WorkbenchPage::Map);
        app.set_input_mode(crate::InputMode::Navigate);
        app.router
            .workbench_mut()
            .set_focus(crate::ui_view_models::PhaseSurfaceId::MapReadiness);
        assert_recovery_action_visible(&app, width, height);
        app.reduce_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Enter,
            crossterm::event::KeyModifiers::NONE,
        ));
        assert_eq!(app.shell_view(), ShellView::Jobs, "{width}x{height}");
    }
}

fn assert_recovery_action_visible(app: &ShellApp, width: u16, height: u16) {
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| crate::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let text = (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("Enter inspect Map runs"),
        "{width}x{height}\n{text}"
    );
    assert!(text.contains("Recorded Map context unavailable"), "{text}");
    assert!(!text.contains("Beta receiver"), "{text}");
}

#[test]
fn map_receipt_change_requests_a_new_context_without_focus_change() {
    let (root, mut app, _) = fixture(true);
    let original_view = app.shell_view();
    record_indexed_run(
        root.path(),
        "different-map",
        "threat-model:import",
        json!({"ok":true,"status":"completed","data":{"snapshot":{"filesIndexed":1}}}),
    );
    bind(&mut app, root.path(), "different-map", true);
    assert!(threat_model_doc(&app).is_none());
    assert!(dfd_model(&app).empty_hint.unwrap().contains("Checking"));
    app.hydrate_all_view_data_for_test();
    assert!(threat_model_doc(&app).is_none());
    assert_eq!(app.shell_view(), original_view);
}

#[test]
fn exact_map_is_available_in_plain_output_at_all_viewports() {
    let (_, mut app, _) = fixture(true);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let plain = crate::renderer::render_plain_app(&app, width as usize);
        assert!(plain.contains("Alpha receiver"), "{plain}");
        assert!(!plain.contains("Beta receiver"), "{plain}");
    }
}
