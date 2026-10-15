use super::*;
use crate::app::view_state::DagTaskRow;
use std::time::{Duration, Instant};

fn completed_session() -> ActivitySession {
    let mut session = ActivitySession::new("run-completion-timing");
    let end = Instant::now();
    session.started_at = end - Duration::from_secs(20);
    session.completed_at = Some(end);
    session
}

fn completed_row(id: &str, secs: u64) -> DagTaskRow {
    let mut row = DagTaskRow::queued(id.to_string(), "context".to_string(), Vec::new());
    let end = Instant::now();
    row.started_at = Some(end - Duration::from_secs(secs));
    row.completed_at = Some(end);
    row.state = DagTaskState::Done;
    row
}

#[test]
fn notice_timing_uses_the_exact_bound_task_instead_of_a_decorated_neighbor() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut session = completed_session();
    session.bind_tool_task("context:build", "context:build[selected]".into());
    session.tasks.insert(
        "context:build[selected]".into(),
        completed_row("context:build[selected]", 7),
    );
    session
        .tasks
        .insert("context:build".into(), completed_row("context:build", 0));
    app.set_activity(Some(session));

    assert_eq!(app.completed_tool_secs("context:build"), Some(7));
}

#[test]
fn missing_task_timing_uses_the_frozen_session_duration() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_activity(Some(completed_session()));
    assert_eq!(app.completed_tool_secs("context:build"), Some(20));
}

#[test]
fn missing_activity_has_no_invented_elapsed_time() {
    let app = ShellApp::new(V2Config::default(), None);
    assert_eq!(app.completed_tool_secs("context:build"), None);
}

#[test]
fn undecorated_completed_row_retains_a_known_subsecond_duration() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut session = completed_session();
    session
        .tasks
        .insert("context:build".into(), completed_row("context:build", 0));
    app.set_activity(Some(session));
    assert_eq!(app.completed_tool_secs("context:build"), Some(0));
}
