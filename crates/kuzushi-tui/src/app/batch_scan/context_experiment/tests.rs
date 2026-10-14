use super::*;
use crate::app::{ShellEffect, ViewDataState};
use kuzushi_core::{
    allowance::ProviderRunUsage, capabilities::campaign::ScanResourceEvidence, V2Config,
};

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned fixture, never executed\nfn main() {}\n",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.open_batch_scan_config(None);
    (root, app)
}

fn select_baseline(app: &mut ShellApp, investigation: &str) {
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.prior_run_id = Some("baseline".into());
    config.prior_runs.push(super::super::config::BatchPriorRun {
        run_id: "baseline".into(),
        evidence: ViewDataState::Ready(Ok(ScanResourceEvidence {
            run_id: "baseline".into(),
            cost_usd: None,
            equivalence: None,
            calibration_limitation: None,
            provider_usage: Some(ProviderRunUsage {
                run_id: "baseline".into(),
                investigation_id: investigation.into(),
                model: "openai-codex:gpt-5.5".into(),
                tool: "sast:scan".into(),
                source_identity: "source".into(),
                config_sha256: "config".into(),
                committed_calls: 3,
                unresolved_calls: 0,
            }),
        })),
    });
}

#[test]
fn context_comparison_requires_named_loaded_baseline_and_reads_existing_accounting() {
    let (_root, mut app) = fixture();
    assert!(app.toggle_context_experiment().effects.is_empty());
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .context_baseline_run_id
        .is_none());
    select_baseline(&mut app, "baseline-accounting");
    let update = app.toggle_context_experiment();
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("read-only allowance action expected")
    };
    assert_eq!(request.tool_name, "campaign:allowance");
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.investigation_id, "baseline-accounting");
    assert_eq!(
        config.study.context_baseline_run_id.as_deref(),
        Some("baseline")
    );
    assert!(config.study.ensure_accounting_ready().is_err());
    assert!(config.study.receipt.is_none());
}

#[test]
fn changed_usage_choice_never_silently_replaces_the_context_baseline() {
    let (_root, mut app) = fixture();
    select_baseline(&mut app, "accounting");
    app.toggle_context_experiment();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.prior_run_id = Some("other-usage".into());
    assert_eq!(
        config.study.context_baseline_run_id.as_deref(),
        Some("baseline")
    );
    config.study.accounting_error = None;
    app.toggle_context_experiment();
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.context_baseline_run_id.is_none());
    assert_eq!(config.study.investigation_id, "accounting");
}

#[test]
fn mode_and_recovery_guidance_are_readable_in_all_viewports_without_starting_jobs() {
    use ratatui::{backend::TestBackend, Terminal};
    let (_root, mut app) = fixture();
    select_baseline(&mut app, "accounting");
    app.toggle_context_experiment();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.cursor = BatchScanConfigRow::ALL
        .iter()
        .position(|row| *row == BatchScanConfigRow::ContextComparison)
        .unwrap();
    config.notice = None;
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert!(
            screen.contains("Context comparison") && screen.contains("Esc back"),
            "{width}x{height}: {screen}"
        );
    }
}

#[test]
fn allowance_read_requires_matching_target_and_preserves_existing_commitments() {
    let (_root, mut app) = fixture();
    select_baseline(&mut app, "accounting");
    app.toggle_context_experiment();
    let snapshot = kuzushi_core::allowance::AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "accounting".into(),
        revision: 1,
        model: "openai-codex:gpt-5.5".into(),
        limits: kuzushi_core::allowance::AllowanceLimits {
            max_provider_calls: 8,
            protected_review_calls: 2,
        },
        committed_calls: 3,
        review_calls: 0,
        unresolved_calls: 0,
        cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    };
    let mut data = serde_json::json!({"target":"/foreign","allowance":snapshot});
    app.cache_study_result("campaign:allowance", &data);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .allowance
        .is_none());
    data["target"] = serde_json::to_value(app.target()).unwrap();
    app.cache_study_result("campaign:allowance", &data);
    let study = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study;
    assert_eq!(study.allowance.as_ref().unwrap().committed_calls, 3);
    assert_eq!(study.max_provider_calls, Some(8));
    assert_eq!(study.protected_review_calls, Some(2));
    assert!(study.ensure_accounting_ready().is_ok());
    assert!(study.receipt.is_none());
}

#[test]
fn failed_allowance_read_can_retry_after_clearing_comparison_without_resetting_accounting() {
    let (_root, mut app) = fixture();
    select_baseline(&mut app, "accounting");
    app.toggle_context_experiment();
    app.context_baseline_allowance_failed("campaign:allowance", "owned read failure");
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.ensure_accounting_ready().is_err());
    assert!(config.notice.as_ref().unwrap().contains("r retries"));
    let update = app
        .apply_batch_scan_hotkey(crate::app::state_transitions::ViewHotkeyAction::CampaignRefresh);
    assert_allowance_read(&update, "accounting");
    app.context_baseline_allowance_failed("campaign:allowance", "second read failure");
    let update = app.toggle_context_experiment();
    assert_allowance_read(&update, "accounting");
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.context_baseline_run_id.is_none());
    assert_eq!(config.study.investigation_id, "accounting");
    assert!(config.study.ensure_accounting_ready().is_err());
    assert!(config.study.receipt.is_none());
    assert!(config.study.allowance.is_none());
}

fn assert_allowance_read(update: &crate::app::state_transitions::InputUpdate, id: &str) {
    let request = update
        .effects
        .iter()
        .find_map(|effect| match effect {
            ShellEffect::PrepareRunTool(request) => Some(request),
            _ => None,
        })
        .expect("a read-only retry is required");
    assert_eq!(request.tool_name, "campaign:allowance");
    let input: Value = serde_json::from_str(request.input.as_ref().unwrap()).unwrap();
    assert_eq!(input["investigationId"], id);
}

#[test]
fn malformed_matching_study_receipt_preserves_selected_baseline_and_draft() {
    let (_root, mut app) = fixture();
    select_baseline(&mut app, "accounting");
    app.toggle_context_experiment();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.campaign_id = Some("candidate".into());
    config.study.scan_input = Some(serde_json::json!({"owned":"draft"}));
    let before = config.study.clone();
    app.cache_study_result(
        "campaign:study",
        &serde_json::json!({
            "campaignId":"candidate", "contextExperiment":null
        }),
    );
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study, before);
    assert!(config
        .notice
        .as_ref()
        .unwrap()
        .contains("Study receipt unavailable"));
}

fn candidate_choices(app: &mut ShellApp, root: &std::path::Path) {
    let workspace = kuzushi_core::WorkspaceTarget::new(root).unwrap();
    let ctx = kuzushi_core::modules::ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let output = kuzushi_core::capabilities::campaign::execute_study_plan(
        &serde_json::json!({"campaignId":"choices","trials":12,
            "scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null}}),
        &ctx,
    )
    .unwrap();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.campaign_id = Some("choices".into());
    app.cache_study_result("campaign:study", &output["data"]);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.context_baseline_run_id = Some("named-baseline".into());
    config.context_result_cursor = Some(0);
    config.notice = None;
    let mut snapshot =
        kuzushi_core::capabilities::campaign::snapshot::load_campaign_snapshot(root, "choices")
            .unwrap();
    snapshot.jobs[11].state = "partial".into();
    snapshot.jobs[11].run_id = Some("candidate-partial-run".into());
    app.router.campaign_mut().campaigns = vec![snapshot];
}

#[test]
fn candidate_selection_pages_actual_jobs_and_returns_to_the_same_partial_pass_without_work() {
    use crossterm::event::KeyCode;
    let (root, mut app) = fixture();
    candidate_choices(&mut app, root.path());
    let before = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    assert!(app
        .handle_context_result_key(KeyCode::Enter)
        .unwrap()
        .effects
        .is_empty());
    assert_ne!(app.shell_view(), crate::app::ShellView::RunDiff);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("no recorded run yet"));
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .notice = None;
    for _ in 0..20 {
        assert!(app
            .handle_context_result_key(KeyCode::Down)
            .unwrap()
            .effects
            .is_empty());
    }
    let lines = crate::ui_view_models::study_config::context_result_lines(&app, 36, 6);
    assert!(lines.iter().any(|line| line == "▸ Pass 12 · partial"));
    assert!(lines.len() <= 6);
    assert!(app
        .handle_context_result_key(KeyCode::Enter)
        .unwrap()
        .effects
        .is_empty());
    assert_eq!(app.shell_view(), crate::app::ShellView::RunDiff);
    assert_eq!(app.router.run_diff().left(), "named-baseline");
    assert_eq!(app.router.run_diff().right(), "candidate-partial-run");
    assert!(app.restore_contextual_surface_origin());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.context_result_cursor, Some(11));
    assert_eq!(config.study, before);
    assert!(app.router.campaign().dispatcher_pid.is_none());
}
