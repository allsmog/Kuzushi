use super::*;
use crate::app::{InputMode, ShellEffect, ShellView};
use crossterm::event::{KeyEvent, KeyModifiers};
use kuzushi_core::{
    Finding, FindingStore, Severity, ToolExecutionContext, V2Config, WorkspaceTarget,
};
use ratatui::{backend::TestBackend, Terminal};
mod source_evidence;

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("note.md"), "Owned inert review fixture\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("observed", root.path(), "running")
        .unwrap();
    store
        .insert_finding(
            "observed",
            &Finding::new_tool(
                "audit",
                "owned",
                "note.md",
                1,
                None,
                Severity::Low,
                "Labeled observation needing review",
            ),
        )
        .unwrap();
    store
        .record_run_finished("observed", "completed", 1)
        .unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai:gpt-5.5".into()),
            ..Default::default()
        },
        None,
    );
    app.set_target(Some(root.path().to_path_buf()));
    app.set_shell_view(ShellView::Workbench);
    app.set_input_mode(InputMode::Prompt);
    app.plan_review_step(PlanningRunStep {
        task: crate::PlanningTaskId::TriageFindings,
        tool_name: "triage:run".into(),
        input: json!({"threatModelRef":null}),
    })
    .unwrap();
    (root, app)
}

fn prepare(app: &mut ShellApp, root: &std::path::Path) -> Value {
    let update = app.handle_review_study_key(KeyCode::Enter);
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("shared planning dispatch required")
    };
    assert_eq!(request.tool_name, "campaign:review-study");
    let workspace = WorkspaceTarget::new(root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let input = serde_json::from_str(request.input.as_ref().unwrap()).unwrap();
    let prepared = app
        .registry()
        .prepare_dispatch_input(&request.tool_name, input, &ctx, None)
        .unwrap();
    let output = app
        .registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    output
}

#[test]
fn prepared_review_retains_new_call_limits_until_explicit_discard() {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:review-study", &result);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.max_provider_calls = Some(5);
    config.study.protected_review_calls = Some(2);
    let receipt = config.study.review_receipt.clone();
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        super::super::StudyDraftRecovery::Discard
    );
    app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.review_receipt, receipt);
    assert_eq!(
        (
            config.study.max_provider_calls,
            config.study.protected_review_calls
        ),
        (Some(5), Some(2))
    );
    assert!(config.study.allowance.is_none());
    assert!(!app.has_running_work());
}

#[test]
fn review_prepare_and_completion_preserve_focus_draft_and_require_limits() {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("held\nreview draft");
    app.set_cursor(3);
    let mut foreign = result.clone();
    foreign["data"]["campaignId"] = json!("other");
    assert!(!app.cache_review_study_result(&foreign["data"]));
    assert!(app.cache_review_study_result(&result["data"]));
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!((app.input(), app.cursor()), ("held\nreview draft", 3));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(review_action(config, app.config().model.as_deref()).is_err());
    assert!(!config.study.approved());
    assert!(app.router.campaign().dispatcher_pid.is_none());
}

#[test]
fn approval_and_named_recovery_open_jobs_without_starting_or_losing_accounting() {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.cache_review_study_result(&result["data"]);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.max_provider_calls = Some(4);
    config.study.protected_review_calls = Some(2);
    let (tool, input) = review_action(config, Some("openai:gpt-5.5")).unwrap();
    assert_eq!(input["maxJobAttempts"], 1);
    assert_eq!(input["campaignJobs"], 1);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = app
        .registry()
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let approved = app
        .registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    app.cache_study_result("campaign:approve-allowance", &approved["data"]);
    let receipt = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .review_receipt
        .clone()
        .unwrap();
    app.router.campaign_mut().batch_scan_config = None;
    app.restore_review_study(root.path(), &receipt.campaign_id);
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.approved());
    assert_eq!(config.study.allowance.as_ref().unwrap().committed_calls, 0);
    let update = app.handle_review_study_key(KeyCode::Enter);
    assert!(update.effects.is_empty());
    assert!(app.router.campaign().dispatcher_pid.is_none());
    assert!(app.router.campaign().batch_scan_config.is_none());
}

#[test]
fn review_layout_controls_and_paging_work_across_all_six_sizes() {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.cache_review_study_result(&result["data"]);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        for action in [
            "t total",
            "r protect",
            "M model",
            "s strategy",
            "n new",
            "e source",
            "v evidence",
            "Tab input",
            "PgUp/Dn",
            "Home/End",
            "Enter next",
            "Esc",
        ] {
            assert!(
                rendered.contains(action),
                "{width}x{height} missing {action}"
            );
        }
        for _ in 0..30 {
            app.handle_review_study_key(KeyCode::PageDown);
        }
        let previous = app
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .review_plan
            .as_ref()
            .unwrap()
            .scroll;
        app.handle_review_study_key(KeyCode::PageUp);
        let current = app
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .review_plan
            .as_ref()
            .unwrap()
            .scroll;
        assert!(current <= previous);
        app.handle_review_study_key(KeyCode::Tab);
        assert!(
            app.router
                .campaign()
                .batch_scan_config
                .as_ref()
                .unwrap()
                .review_plan
                .as_ref()
                .unwrap()
                .show_options
        );
        app.handle_review_study_key(KeyCode::Tab);
    }
}

#[test]
fn cancel_restores_origin_and_held_composer_and_keeps_the_selected_task() {
    let (_, mut app) = fixture();
    app.set_input("held multiline\ndraft");
    app.set_cursor(4);
    app.handle_review_study_key(KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!((app.input(), app.cursor()), ("held multiline\ndraft", 4));
    assert_eq!(
        app.engagement.pop_expanded_step().unwrap().tool_name,
        "triage:run"
    );
}

#[test]
fn explicit_strategy_and_model_changes_require_new_review_approval() {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.cache_review_study_result(&result["data"]);
    app.handle_review_study_key(KeyCode::Char('s'));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.review_receipt.is_none());
    assert_eq!(
        config.review_plan.as_ref().unwrap().input["strategy"],
        "deep"
    );
    app.handle_study_form_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .number_edit
        .is_some());
}

#[test]
fn review_failure_is_readable_and_dismissal_preserves_the_plan() {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.cache_review_study_result(&result["data"]);
    let before = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .review_receipt
        .clone();
    app.study_preparation_failed("campaign:approve-allowance", "Owned approval mismatch");
    let lines = crate::ui_view_models::review_study::review_study_lines(
        app.router.campaign().batch_scan_config.as_ref().unwrap(),
        app.config().model.as_deref(),
        36,
    );
    assert!(lines.join("\n").contains("Owned approval mismatch"));
    app.handle_review_study_key(KeyCode::Esc);
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.preparation_error.is_none());
    assert_eq!(config.study.review_receipt, before);
}

#[test]
fn guided_triage_prepares_before_credentials_and_keeps_other_selected_work_paused() {
    let (_, mut app) = fixture();
    app.close_batch_config();
    app.engagement.clear_planning_queue();
    let tasks = [
        crate::app::PlanningTaskId::GatherRepoContext,
        crate::app::PlanningTaskId::TriageFindings,
        crate::app::PlanningTaskId::DedupeFindings,
    ];
    let update = app.review_selected_triage_plan(&tasks).unwrap();
    assert!(update.effects.is_empty());
    assert!(app.review_study_is_open());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.review_plan.as_ref().unwrap().input["concurrency"], 1);
    assert!(app.engagement.pending_credential_continuation().is_none());
    assert!(app.router.campaign().dispatcher_pid.is_none());
    app.handle_review_study_key(KeyCode::Esc);
    assert_eq!(
        app.engagement.pop_expanded_step().unwrap().task,
        crate::app::PlanningTaskId::TriageFindings
    );
    assert_eq!(
        app.engagement.pop_queued_task(),
        Some(crate::app::PlanningTaskId::GatherRepoContext)
    );
    assert_eq!(
        app.engagement.pop_queued_task(),
        Some(crate::app::PlanningTaskId::DedupeFindings)
    );
}

#[test]
fn guided_review_preserves_explicit_worker_and_strategy_choices() {
    let (_, mut app) = fixture();
    app.close_batch_config();
    app.engagement.clear_planning_queue();
    app.option_store_mut().set_value(
        kuzushi_core::OptionScope::Session,
        kuzushi_core::OptionTarget::Tool("triage:run".into()),
        "concurrency",
        json!(3),
    );
    app.option_store_mut().set_value(
        kuzushi_core::OptionScope::Session,
        kuzushi_core::OptionTarget::Tool("triage:run".into()),
        "strategy",
        json!("deep"),
    );
    app.review_selected_triage_plan(&[crate::app::PlanningTaskId::TriageFindings])
        .unwrap();
    let input = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .review_plan
        .as_ref()
        .unwrap()
        .input;
    assert_eq!(input["concurrency"], 3);
    assert_eq!(input["strategy"], "deep");
}

#[test]
fn guided_review_keeps_active_work_and_its_queue_unchanged() {
    let (_, mut app) = fixture();
    app.close_batch_config();
    app.engagement.clear_planning_queue();
    app.engagement
        .queue_plan(vec![crate::app::PlanningTaskId::DedupeFindings]);
    app.set_running_tool_for_test("findings:list");
    let update = app
        .review_selected_triage_plan(&[crate::app::PlanningTaskId::TriageFindings])
        .unwrap();
    assert!(update.effects.is_empty());
    assert!(!app.review_study_is_open());
    assert_eq!(
        app.running_tool_name_owned().as_deref(),
        Some("findings:list")
    );
    assert_eq!(
        app.engagement.pop_queued_task(),
        Some(crate::app::PlanningTaskId::DedupeFindings)
    );
}

#[test]
fn actual_picker_acceptance_opens_review_planning_without_an_authentication_continuation() {
    let (_, mut app) = fixture();
    app.close_batch_config();
    app.engagement.clear_planning_queue();
    app.open_phase_picker(crate::app::WorkflowPhase::Review);
    app.hydrate_all_view_data_for_test();
    let (selected, rebuild) = app.engagement.planning_picker_mut().outcome_sets_mut();
    selected.clear();
    rebuild.clear();
    selected.insert(crate::app::PlanningTaskId::TriageFindings);
    app.set_viewport(crate::TerminalViewport::new(160, 48));
    let mut terminal = Terminal::new(TestBackend::new(160, 48)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("Enter prepares bounded Review"));
    assert!(text.contains("plan review; no calls yet"));
    app.set_input("held review draft");
    app.set_cursor(5);
    let update = app.accept_planning_picker();
    assert!(update.effects.is_empty());
    assert!(app.review_study_is_open());
    assert!(app.engagement.pending_credential_continuation().is_none());
    assert_eq!((app.input(), app.cursor()), ("held review draft", 5));
    let input = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .review_plan
        .as_ref()
        .unwrap()
        .input;
    assert_eq!(input["concurrency"], 1);
    app.handle_review_study_key(KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!((app.input(), app.cursor()), ("held review draft", 5));
}
