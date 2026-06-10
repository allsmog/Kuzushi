use crate::{ActivitySession, DagTaskState, PaneFocus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityHeaderModel {
    pub(crate) detailed_title: String,
    pub(crate) summary_title: String,
    pub(crate) focus_label: &'static str,
}

/// Terminal outcome of the run behind the Activity view. While work is in
/// flight there is no outcome; once it ends, a failure replaces the
/// done/running counters so the operator never stares at an eternal
/// "0/30 done · 0 running" wall wondering whether anything is still alive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActivityRunOutcome {
    Failed { subject: String },
}

pub(crate) fn activity_header_model(
    session: &ActivitySession,
    outcome: Option<ActivityRunOutcome>,
) -> ActivityHeaderModel {
    let total = session.tasks.len();
    let done = task_count(session, DagTaskState::Done);
    let running = task_count(session, DagTaskState::Active);
    let cost_usd = session.tasks.values().map(|row| row.cost_usd).sum::<f64>();
    let progress = progress_segment(&outcome, total, done, running);
    ActivityHeaderModel {
        detailed_title: detailed_title(session, &progress, cost_usd),
        summary_title: format!(
            "ACTIVITY  run {run_id}  ·  {progress}",
            run_id = session.run_id
        ),
        focus_label: pane_focus_label(session.pane_focus),
    }
}

fn progress_segment(
    outcome: &Option<ActivityRunOutcome>,
    total: usize,
    done: usize,
    running: usize,
) -> String {
    match outcome {
        Some(ActivityRunOutcome::Failed { subject }) => {
            format!("✗ run failed — {subject} · see error banner")
        }
        None => format!("{done}/{total} done  ·  {running} running"),
    }
}

fn task_count(session: &ActivitySession, state: DagTaskState) -> usize {
    session
        .tasks
        .values()
        .filter(|row| row.state == state)
        .count()
}

fn detailed_title(session: &ActivitySession, progress: &str, cost_usd: f64) -> String {
    format!(
        "ACTIVITY  run {run}  ·  {progress}  ·  cost ${cost_usd:.4}{paused}{verbose}",
        run = compact_activity_run_id(&session.run_id),
        paused = paused_segment(session.paused),
        verbose = verbose_segment(session.verbose_subsystems),
    )
}

fn compact_activity_run_id(run_id: &str) -> String {
    if run_id.len() <= 12 {
        return run_id.to_string();
    }
    let tail: String = run_id.chars().rev().take(8).collect();
    format!("…{}", tail.chars().rev().collect::<String>())
}

fn paused_segment(paused: bool) -> &'static str {
    paused.then_some("  ·  ⏸ paused").unwrap_or("")
}

fn verbose_segment(verbose: bool) -> &'static str {
    verbose.then_some("  ·  V verbose").unwrap_or("")
}

fn pane_focus_label(focus: PaneFocus) -> &'static str {
    match focus {
        PaneFocus::Left => "[tasks focused]",
        PaneFocus::Right => "[output focused]",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DagTaskRow;

    #[test]
    fn activity_header_model_counts_tasks_and_cost() {
        let mut session = ActivitySession::new("tool-1778354160-e1b1d602a576");
        session.tasks.insert(
            "context:build".to_string(),
            task("context:build", DagTaskState::Done, 0.125),
        );
        session.tasks.insert(
            "triage:run".to_string(),
            task("triage:run", DagTaskState::Active, 0.25),
        );
        session.paused = true;
        session.verbose_subsystems = true;
        session.pane_focus = PaneFocus::Right;

        let model = activity_header_model(&session, None);

        assert_eq!(
            model.summary_title,
            "ACTIVITY  run tool-1778354160-e1b1d602a576  ·  1/2 done  ·  1 running"
        );
        assert!(model.detailed_title.contains("…d602a576"));
        assert!(model.detailed_title.contains("cost $0.3750"));
        assert!(model.detailed_title.contains("paused"));
        assert_eq!(model.focus_label, "[output focused]");
    }

    #[test]
    fn failed_run_replaces_progress_counters_with_the_failure() {
        let mut session = ActivitySession::new("run-1");
        session.tasks.insert(
            "semgrep:scan".to_string(),
            task("semgrep:scan", DagTaskState::Queued, 0.0),
        );

        let model = activity_header_model(
            &session,
            Some(ActivityRunOutcome::Failed {
                subject: "sast:scan".to_string(),
            }),
        );

        assert!(
            model.detailed_title.contains("✗ run failed — sast:scan"),
            "{}",
            model.detailed_title
        );
        assert!(model.detailed_title.contains("see error banner"));
        assert!(!model.detailed_title.contains("done"));
        assert!(model.summary_title.contains("✗ run failed"));
    }

    fn task(id: &str, state: DagTaskState, cost_usd: f64) -> DagTaskRow {
        let mut row = DagTaskRow::queued(id.to_string(), id.to_string(), Vec::new());
        row.state = state;
        row.cost_usd = cost_usd;
        row
    }
}
