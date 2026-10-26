use super::*;
use crate::app::{ProgramScopeState, ReviewMode};
use crate::ScanPanelState;
use kuzushi_core::{
    incremental_index::{ReindexPlan, WorkspaceChange},
    Finding, Severity, V2Config,
};
use std::path::PathBuf;

fn setup_fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.open_setup();
    (root, app)
}

fn assert_investigation_chrome(app: &ShellApp, visible: bool) {
    assert_eq!(journey_footer_segment(app).is_some(), visible);
    assert_eq!(autonomy_footer_segment(app).is_some(), visible);
    assert_eq!(
        crate::ui_view_models::screen_context_model(app)
            .active_phase
            .is_some(),
        visible
    );
    assert_eq!(
        crate::ui_view_models::context_strip_model(app)
            .phase
            .is_some(),
        visible
    );
    assert_eq!(
        crate::ui_view_models::rail_sections(app, 33)
            .iter()
            .any(|section| section.title == "JOURNEY"),
        visible
    );
    let model = status_footer_model(app);
    assert_eq!(
        model.left_segments.iter().any(|s| s.contains("autonomy:")),
        visible
    );
    assert_eq!(
        crate::ui_view_models::rail_sections(app, 33)[0].title,
        if visible { "ENGAGEMENT" } else { "TARGET" }
    );
}

#[test]
fn uncommitted_setup_hides_investigation_chrome_across_other_views() {
    let (_root, mut app) = setup_fixture();
    for view in [
        ShellView::Logs,
        ShellView::QuitConfirm,
        ShellView::Config,
        ShellView::FailureHandoff,
    ] {
        app.set_shell_view(view);
        assert_investigation_chrome(&app, false);
        assert!(crate::ui_view_models::journey_model(&app).is_some());
        assert!(app.engagement.current_phase().is_none());
    }
}

#[test]
fn committed_setup_shows_investigation_chrome_and_reopening_hides_it() {
    let (_root, mut app) = setup_fixture();
    app.engagement.planning_picker_mut().selected_mut().clear();
    app.router.setup_mut().set_cursor(7);
    assert!(crate::ui_view_models::setup_readiness_model(&app).can_start);
    let update = app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::empty(),
    ));
    assert!(update.handled);
    assert!(!app.engagement.planning_picker().returns_to_setup());
    for view in [
        ShellView::Logs,
        ShellView::QuitConfirm,
        ShellView::Workbench,
    ] {
        app.set_shell_view(view);
        assert_investigation_chrome(&app, true);
    }
    app.open_setup();
    app.set_shell_view(ShellView::Logs);
    assert_investigation_chrome(&app, false);
}

#[test]
fn status_footer_model_reports_idle_shell_segments() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = status_footer_model(&app);
    assert_eq!(
        crate::ui_view_models::rail_sections(&app, 33)[0].title,
        "TARGET"
    );

    // Routing + view only: target/ctx/model are the top cockpit strip's job,
    // so each session fact is stated once per screen.
    assert_eq!(
        model.left_segments,
        ["Commands", "Desktop alerts unavailable", "capabilities"]
    );
    assert_eq!(model.right_segments, ["0 findings"]);
}

#[test]
fn replay_footer_names_the_workspace_count_instead_of_the_selected_result() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Replay);
    *app.findings_mut() = vec![engagement_duplicate_semgrep_finding()];

    let model = status_footer_model(&app);

    assert_eq!(model.right_segments, ["Workspace 1 finding / 1 med"]);
    assert_eq!(model.compact_right_segments, ["Workspace 1 finding · 1 M"]);
}

/// The rail renders unfiltered ledger truth on the same frame as this footer,
/// so a bare projection count here reads as a second, contradicting ledger
/// total. The projection stays the headline; the ledger it narrows is named.
#[test]
fn workbench_findings_segment_discloses_the_ledger_it_narrows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    *app.findings_mut() = vec![
        engagement_duplicate_semgrep_finding(),
        engagement_duplicate_systems_finding(),
    ];

    let model = status_footer_model(&app);

    assert_eq!(model.right_segments, ["1/2 findings shown / 1 high"]);
    assert_eq!(
        crate::ui_view_models::rail_sections(&app, 33)
            .iter()
            .find(|section| section.title == "FINDINGS")
            .expect("findings rail section")
            .rows[0]
            .to_string(),
        "2 findings · 1 H · 1 M"
    );
}

/// A projection that hides nothing must not manufacture a narrowing.
#[test]
fn workbench_findings_segment_stays_bare_when_nothing_is_hidden() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    *app.findings_mut() = vec![engagement_duplicate_semgrep_finding()];

    let model = status_footer_model(&app);

    assert_eq!(model.right_segments, ["1 finding / 1 med"]);
}

fn engagement_duplicate_semgrep_finding() -> Finding {
    let mut semgrep = Finding::new_semgrep(
        "demo.sql",
        "src/search.ts",
        12,
        None,
        Severity::Medium,
        "SQL injection CWE-89 reaches db.query",
    );
    semgrep.scan_id = Some("scan-a".to_string());
    semgrep
}

fn engagement_duplicate_systems_finding() -> Finding {
    let mut systems = Finding::new_tool(
        "systems-hunt",
        "systems/cwe-89",
        "src/search.ts",
        14,
        None,
        Severity::High,
        "SQL injection CWE-89 reaches db.query",
    );
    systems.scan_id = Some("scan-b".to_string());
    systems
}

#[test]
fn malformed_context_snapshot_surfaces_in_the_cockpit_strip() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().context_view_mut().status =
        "malformed context snapshot. Next: context build".to_string();

    // The bottom bar no longer carries ctx; the malformed signal must still
    // reach the operator through the top cockpit strip.
    let strip = crate::ui_view_models::context_strip_model(&app);
    assert!(strip
        .compact_segments()
        .contains(&"repo index malformed".to_string()));
}

#[test]
fn status_footer_shows_scope_chip_when_program_scope_loaded() {
    // M2 §2.1: when `.kuzushi/scope.toml` is loaded, the footer carries a
    // `scope: on` chip so operators know recon and import calls will be
    // gated. Absence of scope keeps the footer compact.
    let mut app = ShellApp::new(V2Config::default(), None);
    let scope = kuzushi_core::ProgramScope::parse(
        r#"
        [in_scope]
        hosts = ["*.example.com"]
        "#,
    )
    .unwrap();
    app.domain_mut()
        .set_program_scope_state(ProgramScopeState::Loaded(scope));

    let model = status_footer_model(&app);

    assert!(
        model.left_segments.iter().any(|s| s == "scope: on"),
        "expected scope: on chip, got {:?}",
        model.left_segments
    );

    app.domain_mut()
        .set_program_scope_state(ProgramScopeState::Unconfigured);
    let model = status_footer_model(&app);
    assert!(
        !model.left_segments.iter().any(|s| s.starts_with("scope:")),
        "no scope chip expected when no scope file is configured, got {:?}",
        model.left_segments
    );
}

#[test]
fn status_footer_separates_an_unloadable_scope_from_an_absent_one() {
    // The scope-gated dispatchers refuse an unloadable `scope.toml` and run
    // unrestricted without one, so the footer must not present the first as
    // the second. An empty scope is a documented no-op and stays chipless.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut()
        .set_program_scope_state(ProgramScopeState::Unavailable);

    let model = status_footer_model(&app);

    assert!(
        model
            .left_segments
            .iter()
            .any(|s| s == "scope: load failed"),
        "expected scope: load failed chip, got {:?}",
        model.left_segments
    );

    app.domain_mut()
        .set_program_scope_state(ProgramScopeState::Loaded(
            kuzushi_core::ProgramScope::default(),
        ));
    let model = status_footer_model(&app);
    assert!(
        !model.left_segments.iter().any(|s| s.starts_with("scope:")),
        "an empty scope is a no-op and carries no chip, got {:?}",
        model.left_segments
    );
}

#[test]
fn status_footer_shows_active_project_scope_chip() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_active_scope(Some(crate::app::TargetCandidateScope {
        id: "submodule-libs-parser".to_string(),
        kind: kuzushi_core::NestedProjectKind::Submodule,
        rel_path: "libs/parser".to_string(),
    }));

    let model = status_footer_model(&app);

    assert!(
        model
            .left_segments
            .iter()
            .any(|segment| segment == "project-scope:libs/parser"),
        "expected active project scope chip, got {:?}",
        model.left_segments
    );
}

#[test]
fn status_footer_shows_workspace_stale_chip_from_watcher_changes() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.apply_workspace_changes(&[WorkspaceChange::FileChanged(PathBuf::from(
        "src/routes/users.rs",
    ))]);

    let model = status_footer_model(&app);

    assert!(
        model
            .left_segments
            .iter()
            .any(|segment| segment == "workspace:stale routes"),
        "expected stale route chip, got {:?}",
        model.left_segments
    );
    let stale = app.workspace_stale().expect("stale summary");
    assert_eq!(stale.change_count(), 1);
    assert_eq!(
        stale.strongest_plan(),
        ReindexPlan::FileFactsAndLocalAttackSurface
    );
    assert!(model
        .compact_left_segments
        .iter()
        .any(|segment| segment.contains("⚠ stale")));
}

#[test]
fn dirty_history_requests_source_check_without_inventing_inventory_changes() {
    let (_root, mut app) = setup_fixture();
    app.domain_mut().set_returning_source_unverified(true);
    let model = status_footer_model(&app);
    assert!(model.left_segments.contains(&"Source unchecked".into()));
    assert!(model
        .compact_left_segments
        .iter()
        .any(|s| s.contains("source unchecked")));
    assert!(app.workspace_stale().is_none());
    assert!(app.workspace_pending_changes().is_empty());

    app.apply_workspace_changes(&[WorkspaceChange::GitIndexChanged]);
    let model = status_footer_model(&app);
    assert!(model
        .left_segments
        .contains(&"Workspace changed (inventory)".into()));
    assert!(!model.left_segments.contains(&"Source unchecked".into()));
    assert!(model
        .compact_left_segments
        .iter()
        .any(|s| s.contains("⚠ stale")));
    let next_root = tempfile::tempdir().unwrap();
    let next = kuzushi_core::WorkspaceTarget::new(next_root.path()).unwrap();
    app.domain_mut().reset_for_target(&next);
    assert!(!app.domain().returning_source_unverified());
    assert!(app.workspace_stale().is_none());
}

#[test]
fn status_footer_shows_review_conflict_chip() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.workbench_mut().review_mut().mode = ReviewMode::Conflict {
        message: "finding fp changed after read watermark 1 at event seq(s) 2".to_string(),
        target_fp: "fp".to_string(),
    };

    let model = status_footer_model(&app);

    assert!(
        model
            .left_segments
            .iter()
            .any(|segment| segment == "review:conflict"),
        "expected review conflict chip, got {:?}",
        model.left_segments
    );
}

#[test]
fn workspace_stale_summary_keeps_strongest_plan_across_batches() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.apply_workspace_changes(&[WorkspaceChange::PromptOrHouseRuleChanged]);
    app.apply_workspace_changes(&[WorkspaceChange::GitHeadChanged]);

    let stale = app.workspace_stale().expect("stale summary");
    assert_eq!(stale.change_count(), 2);
    assert_eq!(stale.strongest_plan(), ReindexPlan::FullSnapshot);
    assert!(status_footer_model(&app)
        .left_segments
        .contains(&"workspace:stale snapshot".to_string()));

    app.clear_workspace_stale();
    assert!(app.workspace_stale().is_none());
}

#[test]
fn status_footer_model_prefers_active_scan_status() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.config_mut().model = Some("openai:gpt-5.2".to_string());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: None,
        target: PathBuf::from("."),
        stage: "semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    let model = status_footer_model(&app);

    assert_eq!(
        model.left_segments,
        [
            "Run active",
            "running: semgrep",
            "Desktop alerts unavailable",
            "capabilities",
            "openai:gpt-5.2",
        ]
    );
}

#[test]
fn status_footer_model_reflects_active_tool_model_override() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.config_mut().model = Some("anthropic:claude-default".to_string());
    app.set_running_tool_for_test("triage:run");
    app.set_active_model_override_for_test("openai:gpt-tool");

    let model = status_footer_model(&app);

    assert_eq!(
        model.left_segments,
        [
            "Run active",
            "triage:run: active",
            "Desktop alerts unavailable",
            "capabilities",
            "openai:gpt-tool (tool)",
        ]
    );
}

#[test]
fn status_footer_hides_notification_warning_when_focus_is_known_or_alerts_are_off() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ui_mut()
        .set_terminal_focus(crate::app::FocusState::Focused);
    assert!(!status_footer_model(&app)
        .left_segments
        .iter()
        .any(|segment| segment.to_lowercase().contains("desktop alerts")));

    app.ui_mut()
        .set_terminal_focus(crate::app::FocusState::Unknown);
    app.ui_mut().set_notify_enabled(false);
    assert!(!status_footer_model(&app)
        .left_segments
        .iter()
        .any(|segment| segment.to_lowercase().contains("desktop alerts")));
}

#[test]
fn operator_ceiling_leads_full_and_compact_footers() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(PathBuf::from("/tmp/footer-policy-fixture")));
    app.config_mut().autonomy = kuzushi_core::modules::autonomy::AutonomyPosture::Review;
    app.set_shell_view(ShellView::Report);
    let model = status_footer_model(&app);
    for (segments, expected) in [
        (model.left_segments, "⛭ autonomy:review"),
        (model.compact_left_segments, "⛭ review"),
    ] {
        assert_eq!(segments.first().map(String::as_str), Some(expected));
        assert_eq!(segments.iter().filter(|s| s.starts_with('⛭')).count(), 1);
    }
}

#[test]
fn report_footer_never_substitutes_loaded_workspace_severity_for_a_study() {
    let (_root, mut app) = setup_fixture();
    app.set_findings(vec![Finding::new_tool(
        "owned-unrelated",
        "old-rule",
        "notes.txt",
        1,
        None,
        Severity::High,
        "Unrelated history",
    )]);
    app.set_shell_view(ShellView::Report);
    let model = status_footer_model(&app);
    for segments in [model.right_segments, model.compact_right_segments] {
        let text = segments.join(" ");
        assert!(!text.contains("high"), "{text}");
        assert!(text.to_lowercase().contains("loading"), "{text}");
    }
}
