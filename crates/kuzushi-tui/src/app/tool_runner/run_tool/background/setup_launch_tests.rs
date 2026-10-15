use super::*;
use crate::app::{PlanningRunStep, PlanningTaskId, PlanningTaskRow};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn planned_setup() -> (tempfile::TempDir, WorkspaceTarget, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let task = PlanningTaskId::GatherRepoContext;
    app.engagement.planning_picker_mut().open(
        vec![PlanningTaskRow::for_task(task, root.path())],
        [task].into_iter().collect(),
    );
    app.engagement.queue_plan(vec![task]);
    app.router.setup_mut().set_cursor(7);
    app.set_shell_view(ShellView::Setup);
    (root, workspace, app)
}

#[test]
fn setup_launch_artifact_failure_pauses_and_preserves_the_plan_for_explicit_retry() {
    let (_root, workspace, mut app) = planned_setup();
    let runs = kuzushi_core::runs_root(workspace.root());
    std::fs::create_dir_all(runs.parent().unwrap()).unwrap();
    std::fs::write(&runs, "owned path collision").unwrap();
    let selected = app.engagement.planning_picker().selected().clone();

    assert!(app.dispatch_next_planning_task(workspace).is_empty());

    assert!(!app.has_running_work());
    assert!(app.engagement.planning_paused());
    assert_eq!(app.engagement.pending_planning_step_count(), 1);
    assert!(!app.engagement.has_running_tool());
    assert!(!app.engagement.has_failed_tasks());
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.router.setup().cursor(), 7);
    assert_eq!(app.engagement.planning_picker().selected(), &selected);
    let readiness = crate::ui_view_models::setup_readiness_model(&app);
    assert!(readiness.can_start);
    assert_eq!(readiness.rows[7].status, "RETRY");
    assert!(readiness.rows[7].detail.contains("run artifacts"));
    std::fs::remove_file(runs).unwrap();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(
        update.effects.as_slice(),
        [ShellEffect::DispatchNextPlanningTask(_)]
    ));
    assert!(!app.engagement.planning_paused());
    assert_eq!(app.engagement.pending_planning_step_count(), 1);
    assert_eq!(app.engagement.planning_picker().selected(), &selected);
    assert!(app.router.setup().launch_failure().is_none());
}

fn mark_running(app: &mut ShellApp) {
    app.engagement
        .set_running_planning_run_step(PlanningRunStep {
            task: PlanningTaskId::GatherRepoContext,
            tool_name: "context:build".into(),
            input: serde_json::json!({}),
        });
}

#[test]
fn background_or_other_target_refusal_never_changes_setup_or_focus() {
    let (_root, workspace, mut app) = planned_setup();
    mark_running(&mut app);
    app.set_shell_view(ShellView::Workbench);
    app.retain_failed_setup_launch(&workspace, "context:build", "background failure");
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(app.router.setup().launch_failure().is_none());
    assert!(app.engagement.has_running_tool());

    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    app.set_shell_view(ShellView::Setup);
    app.retain_failed_setup_launch(&workspace, "context:build", "old target failure");
    assert!(app.router.setup().launch_failure().is_none());
    assert!(!app.engagement.planning_paused());
}

#[test]
fn launch_failure_survives_editors_but_clears_on_target_change() {
    let (_root, _workspace, mut app) = planned_setup();
    app.router
        .setup_mut()
        .record_launch_failure("owned failure".into());
    app.router.setup_mut().begin_budget_edit(Some(2.0));
    app.router.setup_mut().finish_editor();
    app.router.setup_mut().open();
    assert_eq!(app.router.setup().launch_failure(), Some("owned failure"));
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    assert!(app.router.setup().launch_failure().is_none());
}
