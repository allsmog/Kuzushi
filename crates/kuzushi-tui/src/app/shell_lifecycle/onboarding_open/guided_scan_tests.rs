use super::*;
use crate::app::PlanningTaskId;
use crate::app::{InputMode, ShellView};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{OptionScope, OptionTarget, V2Config, WorkflowPhase, WorkspaceTarget};
use serde_json::json;

fn key(app: &mut ShellApp, code: KeyCode) {
    crate::app::update_and_execute_effects(
        app,
        crate::Msg::Term(crate::TermEvent::Key(KeyEvent::new(
            code,
            KeyModifiers::NONE,
        ))),
    );
}

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    (root, ShellApp::new(config, Some(&workspace)))
}

#[test]
fn guided_scan_opens_three_pass_review_before_credentials_or_work() {
    let (root, mut app) = fixture();
    assert!(app.try_open_guided_phase_planner(WorkflowPhase::Scan));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.trials, 3);
    assert_eq!(config.requested_workers, 1);
    assert!(config.study.plan_identity().is_none());
    assert!(config.study.allowance.is_none());
    assert!(app.engagement.pending_credential_continuation().is_none());
    assert!(app.router.campaign().dispatcher_pid.is_none());
    assert!(!app.has_running_work());
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn guided_scan_retains_canonical_options_and_navigation_origin() {
    let (_root, mut app) = fixture();
    app.set_shell_view(ShellView::Catalog);
    app.set_input_mode(InputMode::Prompt);
    for (name, value) in [
        ("taskMode", json!("manual")),
        ("tasks", json!(["agentic"])),
        ("agenticMaxModelTurns", json!(2)),
    ] {
        app.option_store_mut().set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".into()),
            name,
            value,
        );
    }
    app.open_requested_phase_picker(WorkflowPhase::Scan);
    let preview = app
        .registry()
        .prepare_tool_input("sast:scan", json!({}), Some(app.option_store()))
        .unwrap();
    assert_eq!(preview["tasks"], json!(["agentic"]));
    assert_eq!(preview["agenticMaxModelTurns"], 2);
    let origin = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .origin
        .as_ref()
        .unwrap();
    assert_eq!(origin.view, ShellView::Catalog);
    assert_eq!(origin.mode, InputMode::Prompt);
}

#[test]
fn targetless_guided_scan_cannot_create_a_study() {
    let mut app = ShellApp::new(V2Config::default(), None);
    assert!(!app.try_open_guided_phase_planner(WorkflowPhase::Scan));
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert!(!app.has_running_work());
}

#[test]
fn setup_typed_scan_plan_returns_without_rebuilding_setup() {
    let (_root, mut app) = fixture();
    app.open_setup();
    app.engagement
        .planning_picker_mut()
        .selected_mut()
        .insert(PlanningTaskId::BuildThreatModel);
    app.router.setup_mut().set_cursor(6);
    let selected = app.engagement.planning_picker().selected().clone();
    for character in "plan scan".chars() {
        key(&mut app, KeyCode::Char(character));
    }
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.input(), "plan scan");
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.shell_view(), ShellView::Campaign);
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.engagement.current_phase(), None);
    assert_eq!(app.router.setup().cursor(), 6);
    assert_eq!(app.engagement.planning_picker().selected(), &selected);
    assert!(!app.has_running_work());
}

#[test]
fn map_phase_navigation_and_back_keep_selection_cursor_and_phase() {
    let (_root, mut app) = fixture();
    app.open_phase_picker(WorkflowPhase::Map);
    app.engagement
        .planning_picker_mut()
        .selected_mut()
        .insert(PlanningTaskId::GatherRepoContext);
    app.engagement.planning_picker_mut().set_cursor(2);
    let selected = app.engagement.planning_picker().selected().clone();
    app.set_warn_notice("planning", "Owned prior Map warning");
    key(&mut app, KeyCode::Right);
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert!(!app.notice_captures_escape());
    assert_eq!(
        app.engagement.planning_picker().phase(),
        Some(WorkflowPhase::Map)
    );
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
    assert_eq!(app.engagement.planning_picker().selected(), &selected);
    assert_eq!(app.engagement.planning_picker().cursor(), 2);
    assert!(!app.has_running_work());
}

#[test]
fn completed_map_handoff_opens_finite_study_without_rebuilding_the_picker() {
    let (_root, mut app) = fixture();
    app.open_phase_picker(WorkflowPhase::Map);
    let selected = app.engagement.planning_picker().selected().clone();
    let _effects = app.advance_to_next_phase();
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .trials,
        3
    );
    assert_eq!(app.engagement.planning_picker().selected(), &selected);
    assert!(app.engagement.pending_credential_continuation().is_none());
    assert!(!app.has_running_work());
}
