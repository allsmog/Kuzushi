use super::*;
use kuzushi_core::run_lifecycle::{
    RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemStatus, RunItemV1, RunTaskId,
    SafeText,
};

fn apply_active_task(session: &mut ActivitySession, task_id: RunTaskId) {
    let item = RunItemEnvelopeV1::new(
        1,
        RunId::parse(&session.run_id).unwrap(),
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::TaskUpdated {
            title: SafeText::operator_visible("Build context"),
            status: RunItemStatus::Running,
            detail: None,
        },
        None,
    )
    .unwrap()
    .with_task(task_id)
    .unwrap();
    session.apply_run_item(item).unwrap();
}

#[test]
fn ad_hoc_completion_keeps_the_live_task_and_its_start_time() {
    let app = ShellApp::new(V2Config::default(), None);
    let mut session = ActivitySession::new("run-context-binding");
    let task_id = RunTaskId::new();
    app.bind_background_session_task(&mut session, task_id, "context:build");
    apply_active_task(&mut session, task_id);
    let started = session.tasks["context:build"].started_at.unwrap();

    session.mark_task_done("context:build");

    assert_eq!(session.tasks.len(), 1);
    assert_eq!(session.tasks["context:build"].started_at, Some(started));
    assert_eq!(session.tasks["context:build"].state, DagTaskState::Done);
    assert!(!session.tasks.contains_key(&task_id.to_string()));
}

#[test]
fn unplanned_launch_retains_a_unique_seeded_row() {
    let app = ShellApp::new(V2Config::default(), None);
    let mut session = ActivitySession::new("run-context-seed");
    session.seed_task_sequence(["context:build[baseline]".to_string()]);
    let task_id = RunTaskId::new();
    app.bind_background_session_task(&mut session, task_id, "context:build");
    apply_active_task(&mut session, task_id);

    assert_eq!(session.tasks.len(), 1);
    assert_eq!(
        session.tasks["context:build[baseline]"].state,
        DagTaskState::Active
    );
    assert_eq!(
        session.task_id_for_bound_tool("context:build").as_deref(),
        Some("context:build[baseline]")
    );
}

#[test]
fn unplanned_launch_does_not_claim_an_ambiguous_seeded_row() {
    let app = ShellApp::new(V2Config::default(), None);
    let mut session = ActivitySession::new("run-context-ambiguous");
    session.seed_task_sequence([
        "context:build[a]".to_string(),
        "context:build[b]".to_string(),
    ]);
    let task_id = RunTaskId::new();
    app.bind_background_session_task(&mut session, task_id, "context:build");
    apply_active_task(&mut session, task_id);

    assert_eq!(session.tasks.len(), 3);
    assert_eq!(session.tasks["context:build"].state, DagTaskState::Active);
    assert_eq!(
        session.tasks["context:build[a]"].state,
        DagTaskState::Queued
    );
    assert_eq!(
        session.tasks["context:build[b]"].state,
        DagTaskState::Queued
    );
}

#[test]
fn planned_launch_keeps_its_exact_row_among_shared_tools() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.engagement.set_running_planning_step(
        PlanningTaskId::BuildPastaThreatModel,
        "threat-model:build".to_string(),
    );
    let mut session = ActivitySession::new("run-context-planned");
    session.seed_task_sequence([
        "threat-model:build[stride]".to_string(),
        "threat-model:build[pasta]".to_string(),
    ]);
    let task_id = RunTaskId::new();
    app.bind_background_session_task(&mut session, task_id, "threat-model:build");
    apply_active_task(&mut session, task_id);

    assert_eq!(session.tasks.len(), 2);
    assert_eq!(
        session.tasks["threat-model:build[pasta]"].state,
        DagTaskState::Active
    );
    assert_eq!(
        session.tasks["threat-model:build[stride]"].state,
        DagTaskState::Queued
    );
}
