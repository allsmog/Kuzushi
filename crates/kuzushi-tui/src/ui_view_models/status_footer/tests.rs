use super::*;
use crate::app::ReviewMode;
use crate::ScanPanelState;
use kuzushi_core::{
    incremental_index::{ReindexPlan, WorkspaceChange},
    Finding, Severity, V2Config,
};
use std::path::PathBuf;

#[test]
fn status_footer_model_reports_idle_shell_segments() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = status_footer_model(&app);

    // Routing + view only: target/ctx/model are the top cockpit strip's job,
    // so each session fact is stated once per screen.
    assert_eq!(
        model.left_segments,
        [
            "shell route",
            "notify:unavailable · focus unknown",
            "capabilities"
        ]
    );
    assert_eq!(model.right_segments, ["0 findings"]);
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
        .contains(&"context malformed".to_string()));
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
    app.domain_mut().set_program_scope(Some(scope));

    let model = status_footer_model(&app);

    assert!(
        model.left_segments.iter().any(|s| s == "scope: on"),
        "expected scope: on chip, got {:?}",
        model.left_segments
    );

    app.domain_mut().set_program_scope(None);
    let model = status_footer_model(&app);
    assert!(
        !model.left_segments.iter().any(|s| s.starts_with("scope:")),
        "no scope chip expected when scope is None, got {:?}",
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
            "run route",
            "running: semgrep",
            "notify:unavailable · focus unknown",
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
            "run route",
            "triage:run: active",
            "notify:unavailable · focus unknown",
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
        .any(|segment| segment.starts_with("notify:")));

    app.ui_mut()
        .set_terminal_focus(crate::app::FocusState::Unknown);
    app.ui_mut().set_notify_enabled(false);
    assert!(!status_footer_model(&app)
        .left_segments
        .iter()
        .any(|segment| segment.starts_with("notify:")));
}

#[test]
fn operator_ceiling_leads_full_and_compact_footers() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(PathBuf::from("/tmp/footer-policy-fixture")));
    app.config_mut().autonomy = kuzushi_core::modules::autonomy::AutonomyPosture::Review;
    app.set_shell_view(ShellView::Report);
    let model = status_footer_model(&app);
    for segments in [model.left_segments, model.compact_left_segments] {
        assert_eq!(
            segments.first().map(String::as_str),
            Some("⛭ autonomy:review")
        );
        assert_eq!(
            segments.iter().filter(|s| s.contains("autonomy:")).count(),
            1
        );
    }
}
