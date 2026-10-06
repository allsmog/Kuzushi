use super::*;
use crate::app::{InputMode, ShellEffect, ShellView};
use crossterm::event::{KeyEvent, KeyModifiers};
use kuzushi_core::{ToolExecutionContext, V2Config, WorkspaceTarget};
use ratatui::{backend::TestBackend, Terminal};

mod diagnosis;
mod recovery;

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..Default::default()
        },
        None,
    );
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.open_study_context_picker();
    app.open_context_generation();
    (root, app)
}

fn dispatch(
    app: &ShellApp,
    root: &std::path::Path,
    tool: &str,
    input: Value,
    authorize: bool,
) -> Value {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let mut prepared = app
        .registry()
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap();
    if authorize {
        prepared = prepared.authorize_explicit_headless();
    }
    app.registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

fn prepare(app: &mut ShellApp, root: &std::path::Path) -> Value {
    let update = app.handle_context_generation_key(KeyCode::Enter);
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("shared prepared dispatch required")
    };
    assert_eq!(request.tool_name, "campaign:context-study");
    dispatch(
        app,
        root,
        &request.tool_name,
        serde_json::from_str(request.input.as_ref().unwrap()).unwrap(),
        false,
    )
}

#[test]
fn context_generation_requires_limits_and_approval_before_opening_its_single_job() {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &result);
    let study = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    assert!(
        context_action_input(app.router.campaign().batch_scan_config.as_ref().unwrap()).is_err()
    );
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.max_provider_calls = Some(5);
    config.study.protected_review_calls = Some(2);
    config.context_generation.as_mut().unwrap().scroll = 100;
    config.context_generation.as_mut().unwrap().show_options = true;
    let (tool, input) = context_action_input(config).unwrap();
    assert_eq!(input["maxJobAttempts"], 1);
    assert_eq!(input["campaignJobs"], 1);
    let result = dispatch(&app, root.path(), tool, input, true);
    app.cache_tool_snapshot(tool, &result);
    assert_eq!(app.context_generation().unwrap().scroll, 0);
    assert!(!app.context_generation().unwrap().show_options);
    app.handle_context_generation_key(KeyCode::Enter);
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert!(app.router.campaign().dispatcher_pid.is_none());
    let campaign = app.router.campaign().selected_campaign().unwrap();
    let id = campaign.campaign_id.clone();
    assert_eq!(campaign.jobs.len(), 1);
    assert_eq!(campaign.jobs[0].state, "planned");
    app.review_selected_study();
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.investigation_id, study.investigation_id);
    assert_eq!(
        config
            .context_generation
            .as_ref()
            .unwrap()
            .campaign_id
            .as_deref(),
        Some(id.as_str())
    );
    assert_eq!(config.study.allowance.as_ref().unwrap().committed_calls, 0);
}

#[test]
fn context_generation_background_completion_and_cancel_preserve_the_operator_draft() {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("unsent\noperator draft");
    app.set_cursor(4);
    app.cache_tool_snapshot("campaign:context-study", &result);
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!((app.input(), app.cursor()), ("unsent\noperator draft", 4));
    app.set_shell_view(ShellView::Campaign);
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.cache_tool_snapshot("campaign:context-study", &result);
    assert!(app.context_generation().is_none());
    assert!(app.study_context_picker().is_some());
    assert_eq!((app.input(), app.cursor()), ("unsent\noperator draft", 4));
}

#[test]
fn context_generation_budget_editor_and_paged_terms_work_at_all_viewports() {
    let (_, mut app) = fixture();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert!(
            screen.contains("GENERATE STUDY CONTEXT") && screen.contains("Esc back"),
            "{screen}"
        );
        app.handle_context_generation_key(KeyCode::Char('t'));
        app.capture_batch_number_paste("5");
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Enter save"));
        app.handle_batch_number_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        for _ in 0..40 {
            app.handle_context_generation_key(KeyCode::PageDown);
        }
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert!(
            screen.contains("remain") && screen.contains("recorded."),
            "{screen}"
        );
    }
    let plain = crate::renderer::render_plain_app(&app, 80);
    assert!(plain.contains("Dollar estimate: unavailable"));
    assert!(plain.contains("Enter freezes source"));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .max_provider_calls,
        Some(5)
    );
}

#[test]
fn setup_preserves_selected_work_options_allowance_and_composer_across_back() {
    use crate::app::PlanningTaskId::*;
    let (root, mut app) = fixture();
    app.router.campaign_mut().batch_scan_config = None;
    app.open_setup();
    app.set_input("unsent\noperator draft");
    app.set_cursor(4);
    let plan = [GatherRepoContext, MapEntryPoints, BuildThreatModel];
    app.engagement.planning_picker_mut().selected_mut().clear();
    app.engagement
        .planning_picker_mut()
        .selected_mut()
        .extend(plan);
    let spec = app
        .planning_option_spec(BuildThreatModel, "methodology")
        .unwrap();
    app.set_planning_option_override(BuildThreatModel, &spec, json!("pasta"))
        .unwrap();
    let selected = app.engagement.planning_picker().selected().clone();
    let update = app.review_setup_allowance().unwrap();
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Campaign);
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &result);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.max_provider_calls = Some(5);
    config.study.protected_review_calls = Some(2);
    let generation = config.context_generation.as_ref().unwrap();
    assert_eq!(generation.receipt.as_ref().unwrap().job_count(), 3);
    assert_eq!(
        generation.receipt.as_ref().unwrap().input["methodology"],
        "pasta"
    );
    let (_, terms) = context_action_input(config).unwrap();
    assert_eq!(terms["campaignJobs"], 3);
    let investigation = config.study.investigation_id.clone();
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.input(), "unsent\noperator draft");
    assert_eq!(app.cursor(), 4);
    assert_eq!(app.engagement.planning_picker().selected(), &selected);
    app.review_setup_allowance();
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.investigation_id, investigation);
    assert_eq!(config.study.max_provider_calls, Some(5));
    assert!(config
        .context_generation
        .as_ref()
        .unwrap()
        .receipt
        .is_some());
    app.handle_context_generation_key(KeyCode::Char('n'));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.investigation_id, investigation);
    let generation = config.context_generation.as_ref().unwrap();
    assert!(generation.receipt.is_none());
    assert_eq!(generation.preparation_count(), 2);
    assert_eq!(generation.context_input["methodology"], "pasta");
}

#[test]
fn unsupported_model_map_never_enters_the_legacy_execution_queue() {
    use crate::app::PlanningTaskId::*;
    let (_root, mut app) = fixture();
    app.router.campaign_mut().batch_scan_config = None;
    app.open_setup();
    let update = app
        .review_model_backed_map(&[BuildThreatModel, BuildCodeQlDatabase])
        .unwrap();
    assert!(update.effects.is_empty());
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert!(!app.has_running_work());
    assert!(app
        .review_model_backed_map(&[GatherRepoContext, MapEntryPoints])
        .is_none());
}

#[test]
fn completed_draft_after_back_is_recovered_without_stealing_focus() {
    let (root, mut app) = fixture();
    app.router.campaign_mut().batch_scan_config = None;
    app.open_setup();
    app.review_model_backed_map(&[crate::app::PlanningTaskId::BuildThreatModel]);
    let result = prepare(&mut app, root.path());
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.set_input("still editing");
    app.cache_tool_snapshot("campaign:context-study", &result);
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.input(), "still editing");
    app.review_model_backed_map(&[crate::app::PlanningTaskId::BuildThreatModel]);
    assert_eq!(
        app.context_generation()
            .unwrap()
            .receipt
            .as_ref()
            .unwrap()
            .campaign_id,
        result["data"]["campaignId"].as_str().unwrap()
    );
}
