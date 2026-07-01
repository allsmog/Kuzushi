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

/// The tool currently executing behind a taskless (single-tool) run, with
/// the liveness signals the header shows in place of DAG counters: the
/// shared spinner glyph and a ticking elapsed-seconds counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityLiveTool {
    pub(crate) name: String,
    pub(crate) spinner: &'static str,
    pub(crate) elapsed_secs: u64,
    /// Shell-initiated background work (the session-model recommender), not
    /// something the operator triggered — the header labels it so the view
    /// never presents ambient work as the operator's run.
    pub(crate) ambient: bool,
    /// Steps of a confirmed planning queue waiting for this tool to finish.
    /// Non-zero exactly when the operator's plan is stalled behind it.
    pub(crate) queued_plan_steps: usize,
}

pub(crate) fn activity_header_model(
    session: &ActivitySession,
    outcome: Option<ActivityRunOutcome>,
    live_tool: Option<&ActivityLiveTool>,
) -> ActivityHeaderModel {
    let total = session.tasks.len();
    let done = task_count(session, DagTaskState::Done);
    let running = task_count(session, DagTaskState::Active);
    let cost_usd = session.tasks.values().map(|row| row.cost_usd).sum::<f64>();
    let progress = progress_segment(&outcome, total, done, running, live_tool);
    ActivityHeaderModel {
        detailed_title: detailed_title(session, &progress, cost_usd),
        summary_title: format!(
            "ACTIVITY  run {run_id}  ·  {progress}",
            run_id = session.run_id
        ),
        focus_label: pane_focus_label(session.effective_pane_focus()),
    }
}

fn progress_segment(
    outcome: &Option<ActivityRunOutcome>,
    total: usize,
    done: usize,
    running: usize,
    live_tool: Option<&ActivityLiveTool>,
) -> String {
    match outcome {
        Some(ActivityRunOutcome::Failed { subject }) => {
            format!("✗ run failed — {subject} · see error banner")
        }
        // "0/0 done · 0 running" reads as a broken pipeline; a single-tool
        // run has no DAG tasks — name the tool and tick instead.
        None if total == 0 => taskless_progress(live_tool),
        None => format!("{done}/{total} done  ·  {running} running"),
    }
}

fn taskless_progress(live_tool: Option<&ActivityLiveTool>) -> String {
    match live_tool {
        Some(tool) => format!(
            "{} {}{} · running {}s{}",
            tool.spinner,
            tool.name,
            ambient_marker(tool),
            tool.elapsed_secs,
            queued_plan_segment(tool),
        ),
        None => "no DAG tasks — streaming tool output".to_string(),
    }
}

fn ambient_marker(tool: &ActivityLiveTool) -> &'static str {
    if tool.ambient {
        " (background)"
    } else {
        ""
    }
}

fn queued_plan_segment(tool: &ActivityLiveTool) -> String {
    if tool.queued_plan_steps == 0 {
        return String::new();
    }
    format!(
        " · your plan ({} step(s)) starts after it",
        tool.queued_plan_steps
    )
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
    paused.then_some("  ·  ⏸ feed paused").unwrap_or("")
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

        let model = activity_header_model(&session, None, None);

        assert_eq!(
            model.summary_title,
            "ACTIVITY  run tool-1778354160-e1b1d602a576  ·  1/2 done  ·  1 running"
        );
        assert!(model.detailed_title.contains("…d602a576"));
        assert!(model.detailed_title.contains("cost $0.3750"));
        assert!(model.detailed_title.contains("feed paused"));
        assert_eq!(model.focus_label, "[output focused]");
    }

    #[test]
    fn taskless_run_says_so_instead_of_zero_over_zero() {
        // Single-tool runs never register DAG tasks; "0/0 done · 0 running"
        // reads as a broken pipeline rather than a normal tool run.
        let session = ActivitySession::new("tool-1");
        let model = activity_header_model(&session, None, None);
        assert!(model
            .summary_title
            .contains("no DAG tasks — streaming tool output"));
        assert!(!model.summary_title.contains("0/0 done"));
        // With no TASKS pane on screen the stored Left focus is meaningless;
        // the label must follow the only visible pane.
        assert_eq!(model.focus_label, "[output focused]");
    }

    #[test]
    fn taskless_run_with_live_tool_ticks_spinner_name_and_elapsed() {
        let session = ActivitySession::new("tool-1");
        let live = ActivityLiveTool {
            name: "threat-model:build".to_string(),
            spinner: "⠷",
            elapsed_secs: 42,
            ambient: false,
            queued_plan_steps: 0,
        };
        let model = activity_header_model(&session, None, Some(&live));
        assert!(model
            .summary_title
            .contains("⠷ threat-model:build · running 42s"));
        assert!(!model.summary_title.contains("no DAG tasks"));
        assert!(!model.summary_title.contains("(background)"));
    }

    #[test]
    fn ambient_tool_is_labelled_background_with_the_stalled_plan() {
        // Seed disconnect: the recommender ran in the Activity view exactly as
        // if it were the plan the operator just confirmed. The header must say
        // it's ambient and that the plan is queued behind it.
        let session = ActivitySession::new("tool-1");
        let live = ActivityLiveTool {
            name: "module-recommender:recommend".to_string(),
            spinner: "⠷",
            elapsed_secs: 3,
            ambient: true,
            queued_plan_steps: 4,
        };
        let model = activity_header_model(&session, None, Some(&live));
        assert!(
            model
                .summary_title
                .contains("module-recommender:recommend (background)"),
            "{}",
            model.summary_title
        );
        assert!(
            model
                .summary_title
                .contains("your plan (4 step(s)) starts after it"),
            "{}",
            model.summary_title
        );
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
            None,
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
