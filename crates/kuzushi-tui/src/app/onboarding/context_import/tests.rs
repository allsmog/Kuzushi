use super::*;
use crate::app::{PlanningTaskRow, ShellView, WorkflowPhase};
use crate::ui_view_models::{setup_readiness_model, CredentialReadiness};
use serde_json::json;

fn setup() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut config = kuzushi_core::V2Config::default();
    config.model = None;
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(root.path().into()));
    let rows = PlanningTaskId::in_phase(WorkflowPhase::Map)
        .into_iter()
        .map(|task| PlanningTaskRow::for_task(task, root.path()))
        .collect();
    app.engagement.planning_picker_mut().open(
        rows,
        [
            PlanningTaskId::GatherRepoContext,
            PlanningTaskId::ImportThreatModel,
        ]
        .into_iter()
        .collect(),
    );
    app.set_shell_view(ShellView::Setup);
    app.set_input("retained draft");
    (root, app)
}

#[test]
fn missing_source_blocks_start_without_requiring_a_model_or_credential() {
    let (_root, app) = setup();
    let readiness = setup_readiness_model(&app);
    assert!(!readiness.can_start);
    assert_eq!(readiness.selected_model_tasks, 0);
    assert_eq!(
        readiness.credential_readiness,
        CredentialReadiness::NotRequired
    );
    assert!(readiness
        .rows
        .iter()
        .any(|row| row.label == "Context import"
            && row.detail.contains("Choose a context JSON path")));
    assert!(!app.has_running_work());
}

#[test]
fn an_explicit_source_is_inactive_and_keeps_the_import_options_visible() {
    let (_root, mut app) = setup();
    app.engagement.set_option_override(
        PlanningTaskId::ImportThreatModel,
        "path".into(),
        json!("owned-context.json"),
    );
    let input = app.validated_context_import_input().unwrap();
    assert_eq!(input["activate"], false);
    assert!(setup_readiness_model(&app).can_start);
    let update = app.open_setup_import_options();
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(
        app.engagement.planning_picker().current_row().unwrap().id,
        PlanningTaskId::ImportThreatModel
    );
    assert_eq!(
        app.engagement.planning_picker().focus(),
        PickerFocus::OptionsPane
    );
    assert_eq!(app.selected_planning_option_spec().unwrap().1.name, "path");
    assert!(app.engagement.planning_picker().returns_to_setup());
    assert_eq!(app.input(), "retained draft");
    assert!(!app.has_running_work());
}

#[test]
fn generation_and_import_need_separate_map_review() {
    let (_root, app) = setup();
    let error = app
        .validate_context_import_plan(&[
            PlanningTaskId::BuildThreatModel,
            PlanningTaskId::ImportThreatModel,
        ])
        .unwrap_err();
    assert!(error.to_string().contains("each has its own review"));
    assert!(!app.has_running_work());
}

#[test]
fn import_is_never_preselected_from_history_or_model_recommendations() {
    let (_root, app) = setup();
    let mut row = app
        .engagement
        .planning_picker()
        .tasks()
        .iter()
        .find(|row| row.id == PlanningTaskId::ImportThreatModel)
        .unwrap()
        .clone();
    row.last_attempt = Some(crate::app::LastAttempt::Failed {
        resumable: false,
        resume_from: None,
    });
    let profile = crate::app::TargetProfile::conservative();
    assert!(
        !crate::app::recommended_tasks_for_phase(WorkflowPhase::Map, profile, &[row.clone()])
            .contains(&PlanningTaskId::ImportThreatModel)
    );
    assert!(crate::app::model_recommended_in_phase(
        &[PlanningTaskId::ImportThreatModel].into_iter().collect(),
        &[row],
        WorkflowPhase::Map
    )
    .is_empty());
}

#[test]
fn direct_planning_confirmation_refuses_a_missing_source_before_queueing_work() {
    let (_root, mut app) = setup();
    app.set_shell_view(ShellView::PlanningPicker);
    app.engagement
        .planning_picker_mut()
        .set_return_to_setup(false);
    let update = app.accept_planning_picker();
    assert!(update.handled && update.effects.is_empty());
    assert!(!app.has_running_work());
    assert!(app
        .log_lines()
        .iter()
        .any(|entry| entry.body.contains("No jobs started")));
}
