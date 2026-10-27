use super::*;
use crate::{InputMode, WorkbenchPage};
use kuzushi_core::{incremental_index::WorkspaceChange, V2Config};

fn app() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.set_shell_view(ShellView::Workbench);
    app.set_focused_module(Some("context".into()));
    app.set_input("Held investigation draft\nsecond line");
    app.set_cursor(4);
    (root, app)
}

#[test]
fn phase_readers_keep_operator_state_without_diagnostics_or_duplicate_orientation() {
    let (_root, mut app) = app();
    for page in [
        WorkbenchPage::Map,
        WorkbenchPage::Scan,
        WorkbenchPage::Review,
    ] {
        app.router.workbench_mut().set_page(Some(page));
        for view in [ShellView::Workbench, ShellView::Report] {
            app.set_shell_view(view);
            for mode in [InputMode::Prompt, InputMode::Navigate] {
                app.set_input_mode(mode);
                let model = status_footer_model(&app);
                assert_eq!(model.left_segments, ["⛭ autonomy:fix"]);
                assert_eq!(model.compact_left_segments, ["⛭ fix"]);
                let config = super::super::super::config_model(&app);
                assert!(config.summary_rows.iter().any(|row| {
                    row.cells[0] == "notifications"
                        && row.cells[1].contains("desktop alerts unavailable")
                }));
                assert_eq!(
                    (app.input(), app.cursor()),
                    ("Held investigation draft\nsecond line", 4)
                );
            }
        }
    }
}

#[test]
fn source_attention_distinguishes_unchecked_history_from_observed_changes() {
    let (_root, mut app) = app();
    app.domain_mut().set_returning_source_unverified(true);
    let model = status_footer_model(&app);
    assert!(model.left_segments.contains(&"Source unchecked".into()));
    assert!(model.compact_left_segments[0].contains("⚠ source unchecked"));
    assert!(compact_segments(&app, true).unwrap()[0].contains("⚠ source"));
    app.apply_workspace_changes(&[WorkspaceChange::GitIndexChanged]);
    let model = status_footer_model(&app);
    assert!(model
        .left_segments
        .contains(&"Workspace changed (inventory)".into()));
    assert!(!model.left_segments.contains(&"Source unchecked".into()));
    assert!(model.compact_left_segments[0].contains("⚠ stale"));
}

#[test]
fn changed_prompts_do_not_claim_that_target_source_changed() {
    let (_root, mut app) = app();
    app.apply_workspace_changes(&[WorkspaceChange::PromptOrHouseRuleChanged]);
    let model = status_footer_model(&app);
    assert!(model
        .left_segments
        .contains(&"Workspace changed (prompts)".into()));
    assert!(model
        .left_segments
        .iter()
        .all(|label| !label.contains("Source changed")));
    assert!(model.compact_left_segments[0].contains("⚠ stale"));
}

#[test]
fn work_and_real_model_override_remain_visible_without_changing_routing() {
    let (_root, mut app) = app();
    app.set_running_tool_for_test("triage:run");
    app.set_active_model_override_for_test("operator:chosen-model");
    let model = status_footer_model(&app);
    assert!(model.left_segments.contains(&"triage:run: active".into()));
    assert!(model
        .left_segments
        .contains(&"operator:chosen-model (tool)".into()));
    assert!(model
        .compact_left_segments
        .contains(&"triage:run: active".into()));
    assert_eq!(routing_mode_segment(&app), "Run active");
    assert!(model
        .left_segments
        .iter()
        .all(|label| !label.contains("route")));
}

#[test]
fn decision_conflicts_and_pending_cancellation_stay_in_the_status_model() {
    let (_root, mut app) = app();
    app.router.workbench_mut().review_mut().mode = ReviewMode::Conflict {
        message: "Changed while the operator reviewed it".into(),
        target_fp: "owned".into(),
    };
    app.set_scan_panel(Some(crate::ScanPanelState {
        run_id: None,
        target: app.target_owned().unwrap(),
        stage: "owned inspection".into(),
        findings_count: 0,
        running: true,
        abort_requested: true,
        error: None,
    }));
    let model = status_footer_model(&app);
    for segments in [model.left_segments, model.compact_left_segments] {
        assert!(segments.contains(&"review:conflict".into()));
        assert!(segments
            .iter()
            .any(|label| label.contains("abort requested")));
    }
}

#[test]
fn other_shell_surfaces_keep_their_existing_routing_and_diagnostic_contract() {
    let (_root, mut app) = app();
    for view in [ShellView::Module, ShellView::Logs, ShellView::Config] {
        app.set_shell_view(view);
        assert!(full_segments(&app).is_none());
        assert!(compact_segments(&app, false).is_none());
        assert!(status_footer_model(&app)
            .left_segments
            .contains(&"Module selected".into()));
    }
    app.set_shell_view(ShellView::Workbench);
    for page in [WorkbenchPage::Prove, WorkbenchPage::Fix] {
        app.router.workbench_mut().set_page(Some(page));
        assert!(full_segments(&app).is_none());
    }
}

#[test]
fn investigation_readers_prioritize_source_and_decisions_over_shell_diagnostics() {
    let (_root, mut app) = app();
    app.domain_mut().set_returning_source_unverified(true);
    app.router.workbench_mut().review_mut().mode = ReviewMode::Conflict {
        message: "An operator decision changed".into(),
        target_fp: "owned".into(),
    };
    for view in [
        ShellView::Lessons,
        ShellView::Relationships,
        ShellView::Scene,
        ShellView::RunDiff,
        ShellView::Replay,
        ShellView::Activity,
    ] {
        app.set_shell_view(view);
        let model = status_footer_model(&app);
        assert!(
            model.left_segments.contains(&"Source unchecked".into()),
            "{view:?}: {model:?}"
        );
        assert!(
            model.left_segments.contains(&"review:conflict".into()),
            "{view:?}: {model:?}"
        );
        assert!(model.left_segments[0].contains("autonomy:fix"));
        for segments in [model.left_segments, model.compact_left_segments] {
            assert!(
                segments.iter().all(|s| !s.contains("route")
                    && !s.contains("notify:")
                    && !s.contains("focus unknown")
                    && !s.to_lowercase().contains("desktop alerts")),
                "{view:?}: {segments:?}"
            );
        }
        assert_eq!(
            (app.input(), app.cursor()),
            ("Held investigation draft\nsecond line", 4)
        );
        assert_eq!(app.shell_view(), view);
    }
}

fn study_snapshot(
    kind: Option<&str>,
) -> kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot {
    kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot {
        campaign_id: "owned-study".into(),
        kind: kind.map(str::to_string),
        requested_workers: Some(1),
        effective_workers: Some(1),
        parallel_safety_reason: None,
        tool: None,
        created_at_ms: None,
        paused_until_ms: None,
        budget_usd: None,
        job_budget_usd: None,
        fill_gaps: false,
        skipped_covered_cells: None,
        total_cost_usd: 0.0,
        provider_spend_unresolved: true,
        jobs: vec![],
    }
}

#[test]
fn fixed_study_readers_use_the_investigation_footer_and_legacy_campaigns_keep_diagnostics() {
    let (_root, mut app) = app();
    app.set_shell_view(ShellView::Campaign);
    for kind in [
        "scan-batch",
        "context-study",
        "review-study",
        "context-matrix",
        "scope-study",
    ] {
        app.router.campaign_mut().campaigns = vec![study_snapshot(Some(kind))];
        let model = status_footer_model(&app);
        assert!(
            !model
                .left_segments
                .iter()
                .any(|s| s.contains("route") || s.contains("notify:")),
            "{kind}: {model:?}"
        );
        assert!(model.left_segments[0].contains("autonomy:fix"));
    }
    for kind in [None, Some("legacy-campaign")] {
        app.router.campaign_mut().campaigns = vec![study_snapshot(kind)];
        assert!(full_segments(&app).is_none());
        assert!(status_footer_model(&app)
            .left_segments
            .contains(&"Module selected".into()));
    }
}

#[test]
fn fresh_setup_keeps_orientation_and_draft_without_terminal_diagnostics() {
    let (_root, mut app) = app();
    app.open_setup();
    app.set_input("Held Setup draft\nsecond line");
    app.set_cursor(4);
    for mode in [InputMode::Prompt, InputMode::Navigate] {
        app.set_input_mode(mode);
        let model = status_footer_model(&app);
        assert_eq!(model.left_segments, ["Setup"]);
        assert_eq!(model.compact_left_segments, ["Setup"]);
        assert!(app.engagement.planning_picker().returns_to_setup());
        assert_eq!(
            (app.input(), app.cursor()),
            ("Held Setup draft\nsecond line", 4)
        );
        assert_eq!(app.shell_view(), ShellView::Setup);
        let config = super::super::super::config_model(&app);
        assert!(config
            .summary_rows
            .iter()
            .any(|row| row.cells[0] == "notifications"
                && row.cells[1].contains("desktop alerts unavailable")));
    }
}

#[test]
fn setup_retains_active_tool_identity_and_model_without_reviving_diagnostics() {
    let (_root, mut app) = app();
    app.open_setup();
    app.set_running_tool_for_test("triage:run");
    app.set_active_model_override_for_test("openai-oauth:gpt-5.5");
    let model = status_footer_model(&app);
    assert!(model
        .left_segments
        .iter()
        .any(|label| label.contains("triage:run: active")));
    assert!(model
        .left_segments
        .iter()
        .any(|label| label.contains("openai-oauth:gpt-5.5 (tool)")));
    assert!(model
        .compact_left_segments
        .iter()
        .any(|label| label.contains("triage:run: active")));
    assert!(model
        .left_segments
        .iter()
        .all(|label| !label.contains("route")
            && !label.contains("notify:")
            && !label.contains("focus unknown")
            && !label.to_lowercase().contains("desktop alerts")));
}

#[test]
fn setup_retains_source_attention_before_investigation_chrome_is_committed() {
    let (_root, mut app) = app();
    app.open_setup();
    app.apply_workspace_changes(&[WorkspaceChange::GitIndexChanged]);
    let model = status_footer_model(&app);
    assert!(model
        .left_segments
        .iter()
        .any(|label| label.contains("Workspace changed (inventory)")));
    assert!(model
        .compact_left_segments
        .iter()
        .any(|label| label.contains("stale")));
    assert!(model
        .left_segments
        .iter()
        .all(|label| !label.contains("autonomy:")));
    assert!(model.left_segments.iter().any(|label| label == "Setup"));
}
