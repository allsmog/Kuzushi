//! The ambient progress chip: a one-line live summary of background work
//! (`⠏ cpg:build · 6m19s · 1/2 · ~4m left`) shown in the status footer of
//! every view, so the operator can leave /activity and keep working without
//! losing sight of a long build. ETA comes from the workspace's persisted
//! per-task duration history (median of recent runs).

use crate::app::compact_secs;
use crate::{ActivitySession, DagTaskState, ShellApp};

pub(crate) fn ambient_progress_chip(app: &ShellApp) -> Option<String> {
    let session = app.activity()?;
    let subject = live_subject(app, session)?;
    let background = if session.run_focus_backgrounded || app.tool_is_ambient(&subject.name) {
        " (background)"
    } else {
        ""
    };
    let mut segments = vec![
        format!("{} {}{}", app.spinner_glyph(), subject.name, background),
        compact_secs(subject.elapsed_secs),
    ];
    if let Some(progress) = task_progress(session) {
        segments.push(progress);
    }
    if let Some(eta) = eta_segment(app, &subject) {
        segments.push(eta);
    }
    Some(segments.join(" · "))
}

/// What's actually executing right now: the active DAG task when one
/// exists, otherwise the single tool behind a taskless run.
struct LiveSubject {
    name: String,
    elapsed_secs: u64,
}

fn live_subject(app: &ShellApp, session: &ActivitySession) -> Option<LiveSubject> {
    if let Some(row) = active_task(session) {
        return Some(LiveSubject {
            name: row.operator_name().to_string(),
            elapsed_secs: row
                .started_at
                .map(|started| started.elapsed().as_secs())
                .unwrap_or(0),
        });
    }
    let tool = app.running_tool_name()?;
    Some(LiveSubject {
        name: tool.to_string(),
        elapsed_secs: session.started_at.elapsed().as_secs(),
    })
}

fn active_task(session: &ActivitySession) -> Option<&crate::DagTaskRow> {
    session
        .tasks
        .values()
        .find(|row| row.state == DagTaskState::Active)
}

fn task_progress(session: &ActivitySession) -> Option<String> {
    let total = session.tasks.len();
    if total == 0 {
        return None;
    }
    let done = session
        .tasks
        .values()
        .filter(|row| row.state == DagTaskState::Done)
        .count();
    Some(format!("{done}/{total}"))
}

fn eta_segment(app: &ShellApp, subject: &LiveSubject) -> Option<String> {
    let estimate = app.estimate_task_duration_secs(&subject.name)?;
    let remaining = estimate.saturating_sub(subject.elapsed_secs);
    if remaining == 0 {
        return Some("~any moment".to_string());
    }
    Some(format!("~{} left", compact_secs(remaining)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn chip_shows_active_task_progress_and_eta() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut session = ActivitySession::new("r-1");
        let mut active = crate::DagTaskRow::queued("cpg:build".into(), "cpg".into(), Vec::new());
        active.state = DagTaskState::Active;
        active.started_at = Some(std::time::Instant::now());
        session.tasks.insert("cpg:build".into(), active);
        let mut done = crate::DagTaskRow::queued("x:run".into(), "x".into(), Vec::new());
        done.state = DagTaskState::Done;
        session.tasks.insert("x:run".into(), done);
        app.set_activity(Some(session));
        app.record_task_duration_secs("cpg:build", 379);

        let chip = ambient_progress_chip(&app).expect("chip while a task is active");
        assert!(chip.contains("cpg:build"), "{chip}");
        assert!(chip.contains("1/2"), "{chip}");
        assert!(chip.contains("left"), "eta from history: {chip}");
    }

    #[test]
    fn chip_absent_without_live_work() {
        let mut app = ShellApp::new(V2Config::default(), None);
        assert_eq!(ambient_progress_chip(&app), None);
        // A session whose tasks are all done and with no running tool is
        // finished work — the chip must clear.
        app.set_activity(Some(ActivitySession::new("r-1")));
        assert_eq!(ambient_progress_chip(&app), None);
    }

    #[test]
    fn chip_names_the_tool_for_taskless_runs() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_activity(Some(ActivitySession::new("tool-1")));
        app.set_running_tool_for_test("threat-model:build");
        let chip = ambient_progress_chip(&app).expect("chip while a tool runs");
        assert!(chip.contains("threat-model:build"), "{chip}");
        assert!(!chip.contains("(background)"), "{chip}");
    }

    #[test]
    fn chip_labels_shell_initiated_work_as_background() {
        // The recommender is shell work, not operator work — the chip says so
        // instead of presenting it like a run the operator started.
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_activity(Some(ActivitySession::new("tool-1")));
        app.set_running_tool_for_test("module-recommender:recommend");
        app.set_ambient_tool_for_test("module-recommender:recommend");
        let chip = ambient_progress_chip(&app).expect("chip while a tool runs");
        assert!(
            chip.contains("module-recommender:recommend (background)"),
            "{chip}"
        );
    }

    #[test]
    fn compact_secs_formats_minutes_and_seconds() {
        assert_eq!(compact_secs(379), "6m19s");
        assert_eq!(compact_secs(42), "42s");
        assert_eq!(compact_secs(60), "1m00s");
    }

    #[test]
    fn task_progress_counts_done_over_total() {
        let mut session = ActivitySession::new("r-1");
        assert_eq!(task_progress(&session), None);
        let mut done = crate::DagTaskRow::queued("a".into(), "a".into(), Vec::new());
        done.state = DagTaskState::Done;
        session.tasks.insert("a".into(), done);
        session.tasks.insert(
            "b".into(),
            crate::DagTaskRow::queued("b".into(), "b".into(), Vec::new()),
        );
        assert_eq!(task_progress(&session), Some("1/2".to_string()));
    }
}
