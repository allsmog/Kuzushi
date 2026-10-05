use super::*;
use crate::app::{InputMode, ShellEffect, ShellView};
use kuzushi_core::{modules::ToolExecutionContext, V2Config, WorkspaceTarget};

fn app_at(root: &std::path::Path) -> ShellApp {
    std::fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    let mut config = V2Config::default();
    config.model = Some("openai-codex:gpt-5.5".into());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(root.to_path_buf()));
    app.open_batch_scan_config(None);
    app
}

fn compile_draft(app: &mut ShellApp, root: &std::path::Path) -> Value {
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    let mut input = study_input(app, root, config, "study-test").unwrap();
    input["scanInput"]["taskMode"] = json!("manual");
    input["scanInput"]["tasks"] = json!(["secret-scan"]);
    let workspace = WorkspaceTarget::new(root).unwrap();
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let result = kuzushi_core::capabilities::campaign::execute_study_plan(&input, &ctx).unwrap();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .campaign_id = Some("study-test".into());
    result
}

#[test]
fn first_action_prepares_shared_study_dispatch_without_compiling_or_launching_jobs() {
    let root = tempfile::tempdir().unwrap();
    let mut app = app_at(root.path());
    let update = app.launch_batch_from_config();
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("expected prepared tool dispatch");
    };
    assert_eq!(request.tool_name, "campaign:study");
    let input: Value = serde_json::from_str(request.input.as_ref().unwrap()).unwrap();
    assert_eq!(input["trials"], 3);
    assert_eq!(input["workers"], 1);
    assert_eq!(input["scanInput"]["triage"], false);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
    assert!(app.router.campaign().dispatcher_pid.is_none());
}

#[test]
fn receipt_completion_preserves_focus_and_approval_requires_explicit_limits() {
    let root = tempfile::tempdir().unwrap();
    let mut app = app_at(root.path());
    let result = compile_draft(&mut app, root.path());
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("my multiline\ndraft");
    app.set_cursor(3);
    let mut foreign = result.clone();
    foreign["data"]["campaignId"] = json!("other-study");
    app.cache_tool_snapshot("campaign:study", &foreign);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .receipt
        .is_none());
    app.cache_tool_snapshot("campaign:study", &result);
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!((app.input(), app.cursor()), ("my multiline\ndraft", 3));
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    assert!(allowance_input(config, Some("openai-codex:gpt-5.5")).is_err());
    config.study.max_provider_calls = Some(9);
    config.study.protected_review_calls = Some(10);
    assert!(allowance_input(config, Some("openai-codex:gpt-5.5")).is_err());
    config.study.protected_review_calls = Some(3);
    let approval = allowance_input(config, Some("openai-codex:gpt-5.5")).unwrap();
    assert_eq!(approval["campaignJobs"], 3);
    assert_eq!(approval["maxJobAttempts"], 1);
    assert_eq!(approval["expectedRevision"], 0);
}

#[test]
fn approved_study_restores_from_disk_and_open_jobs_does_not_launch() {
    let root = tempfile::tempdir().unwrap();
    let mut app = app_at(root.path());
    let result = compile_draft(&mut app, root.path());
    app.cache_tool_snapshot("campaign:study", &result);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.max_provider_calls = Some(9);
    config.study.protected_review_calls = Some(3);
    let approval = allowance_input(config, Some("openai-codex:gpt-5.5")).unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let result =
        kuzushi_core::capabilities::campaign::execute_approve_allowance(&approval, &ctx).unwrap();
    app.cache_tool_snapshot("campaign:approve-allowance", &result);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .approved());
    app.router.campaign_mut().batch_scan_config = None;
    app.open_campaign_view(Some("study-test".into()));
    app.review_selected_study();
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.approved());
    assert_eq!(config.study.allowance.as_ref().unwrap().committed_calls, 0);
    let update = app.launch_batch_from_config();
    assert!(update.effects.is_empty());
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert!(app.router.campaign().dispatcher_pid.is_none());
    assert_eq!(
        app.router
            .campaign()
            .selected_campaign()
            .unwrap()
            .campaign_id,
        "study-test"
    );
}

#[test]
fn study_back_restores_the_scan_page_zoom_and_composer() {
    let root = tempfile::tempdir().unwrap();
    let mut app = app_at(root.path());
    app.router.campaign_mut().batch_scan_config = None;
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Scan));
    app.router
        .workbench_mut()
        .show_zoomed_focus(crate::ui_view_models::PhaseSurfaceId::ScanScope);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("keep this\nmultiline draft");
    app.set_cursor(4);
    let route = app.router.workbench().clone();
    app.open_batch_scan_config(None);
    app.close_batch_config();
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench(), &route);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(
        (app.input(), app.cursor()),
        ("keep this\nmultiline draft", 4)
    );
}

#[test]
fn revising_work_preserves_frozen_options_when_session_defaults_change() {
    use kuzushi_core::{OptionScope, OptionTarget};
    let root = tempfile::tempdir().unwrap();
    let mut app = app_at(root.path());
    let result = compile_draft(&mut app, root.path());
    app.cache_tool_snapshot("campaign:study", &result);
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".into()),
        "tasks",
        json!(["agentic"]),
    );
    let mut config = app.router.campaign().batch_scan_config.clone().unwrap();
    config.study.invalidate_plan();
    config.requested_workers = 2;
    let revised = study_input(&app, root.path(), &config, "revised-study").unwrap();
    assert_eq!(revised["scanInput"]["tasks"], json!(["secret-scan"]));
    assert_eq!(revised["scanInput"]["threatModelRef"], Value::Null);
    assert_eq!(
        revised["investigationId"],
        result["data"]["investigationId"]
    );
}
