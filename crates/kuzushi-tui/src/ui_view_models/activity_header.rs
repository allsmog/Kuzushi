use crate::{ActivityRouteState, ActivitySession, DagTaskState};
use kuzushi_core::WorkflowPhase;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityHeaderModel {
    pub(crate) origin_phase: Option<WorkflowPhase>,
    pub(crate) detailed_title: String,
    pub(crate) summary_title: String,
    pub(crate) compact_title: String,
}

/// Terminal outcome of the run behind the Activity view. While work is in
/// flight there is no outcome; once it ends, a failure replaces the
/// done/running counters so the operator never stares at an eternal
/// "0/30 done · 0 running" wall wondering whether anything is still alive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActivityRunOutcome {
    WaitingForOperator,
    Terminal {
        status: String,
        findings: Option<u64>,
        reason: Option<String>,
    },
    Failed {
        subject: String,
    },
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
    /// Operator steer-queue depth waiting behind this tool. Rendered as
    /// pending, never running — only one live Run exists at a time.
    pub(crate) queued_steer_steps: usize,
}

#[cfg(test)]
pub(crate) fn activity_header_model(
    session: &ActivitySession,
    route: &ActivityRouteState,
    outcome: Option<ActivityRunOutcome>,
    live_tool: Option<&ActivityLiveTool>,
) -> ActivityHeaderModel {
    activity_header_model_with_queue(
        session,
        route,
        outcome,
        live_tool,
        live_tool.map_or(0, |tool| tool.queued_steer_steps),
        None,
    )
}

pub(crate) fn activity_header_model_with_queue(
    session: &ActivitySession,
    route: &ActivityRouteState,
    outcome: Option<ActivityRunOutcome>,
    live_tool: Option<&ActivityLiveTool>,
    queued_steer_steps: usize,
    active_task_eta_secs: Option<u64>,
) -> ActivityHeaderModel {
    let counts = ActivityTaskCounts::from_session(session);
    let cost = activity_cost_label(session);
    let mut progress = progress_segment(&outcome, counts, live_tool, queued_steer_steps);
    if outcome.is_none() && counts.total > 0 {
        progress.push_str(&active_task_extras(session, active_task_eta_secs));
    }
    ActivityHeaderModel {
        origin_phase: session.origin_phase,
        detailed_title: detailed_title(session, route, &progress, &cost),
        summary_title: format!(
            "RUN FOCUS{phase}  run {run_id}  ·  {progress}",
            phase = origin_phase_segment(session.origin_phase),
            run_id = session.run_id
        ),
        compact_title: format!(
            "RUN FOCUS{phase}  {progress}",
            phase = origin_phase_segment(session.origin_phase)
        ),
    }
}

fn activity_cost_label(session: &ActivitySession) -> String {
    match session.runtime_cost_report() {
        Err(_) => "cost accounting error".to_string(),
        Ok(cost) if cost.is_unavailable() => "cost unavailable".to_string(),
        Ok(cost) if cost.is_complete() => format!("cost ${:.4}", cost.observed_usd()),
        Ok(cost) => format!("cost >=${:.4} (incomplete)", cost.observed_usd()),
    }
}

fn progress_segment(
    outcome: &Option<ActivityRunOutcome>,
    counts: ActivityTaskCounts,
    live_tool: Option<&ActivityLiveTool>,
    queued_steer_steps: usize,
) -> String {
    match outcome {
        Some(ActivityRunOutcome::WaitingForOperator) => {
            "? waiting for operator input · run paused safely".to_string()
        }
        Some(ActivityRunOutcome::Terminal {
            status,
            findings,
            reason,
        }) => terminal_outcome_segment(status, *findings, reason.as_deref()),
        Some(ActivityRunOutcome::Failed { subject }) => {
            format!("✗ run failed — {subject} · see error banner")
        }
        // "0/0 done · 0 running" reads as a broken pipeline; a single-tool
        // run has no DAG tasks — name the tool and tick instead.
        None if counts.total == 0 => taskless_progress(live_tool),
        None => task_progress(counts, live_tool, queued_steer_steps),
    }
}

fn terminal_outcome_segment(status: &str, findings: Option<u64>, reason: Option<&str>) -> String {
    let mut parts = vec![
        terminal_status_segment(status),
        finding_count_segment(findings),
    ];
    if let Some(reason) = reason.map(str::trim).filter(|reason| !reason.is_empty()) {
        parts.push(format!("reason: {reason}"));
    }
    parts.join(" · ")
}

fn terminal_status_segment(status: &str) -> String {
    match status {
        "completed" => "✓ run completed".to_string(),
        "partial" => "⚠ run partial".to_string(),
        "failed" => "✗ run failed".to_string(),
        "interrupted" => "× run interrupted".to_string(),
        "canceled" | "cancelled" => "× run canceled".to_string(),
        "skipped" => "⊘ run skipped".to_string(),
        other => format!("run {other}"),
    }
}

fn finding_count_segment(findings: Option<u64>) -> String {
    match findings {
        Some(1) => "1 finding".to_string(),
        Some(count) => format!("{count} findings"),
        None => "run findings not recorded".to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActivityTaskCounts {
    total: usize,
    done: usize,
    running: usize,
    canceling: usize,
    partial: usize,
    failing: usize,
    blocked: usize,
    canceled: usize,
    skipped: usize,
}

impl ActivityTaskCounts {
    /// Counts cover ONLY the focused run's rows. A prior run in the same
    /// Run Focus sequence keeps its rows visible for history, but its
    /// failures/skips must never be attributed to the run on screen.
    fn from_session(session: &ActivitySession) -> Self {
        Self {
            total: session
                .tasks
                .values()
                .filter(|row| row.prior_run_ref.is_none())
                .count(),
            done: task_count(session, DagTaskState::Done),
            running: task_count(session, DagTaskState::Active),
            canceling: task_count(session, DagTaskState::Canceling),
            partial: task_count(session, DagTaskState::Partial),
            failing: task_count(session, DagTaskState::Failing),
            blocked: task_count(session, DagTaskState::Blocked),
            canceled: task_count(session, DagTaskState::Canceled),
            skipped: task_count(session, DagTaskState::Skipped),
        }
    }
}

fn task_progress(
    counts: ActivityTaskCounts,
    live_tool: Option<&ActivityLiveTool>,
    queued_steer_steps: usize,
) -> String {
    let mut parts = vec![
        format!("{}/{} done", counts.done, counts.total),
        format!("{} running", counts.running),
    ];
    append_terminal_count(&mut parts, counts.partial, "⚠ partial");
    append_terminal_count(&mut parts, counts.failing, "! failed");
    append_terminal_count(&mut parts, counts.blocked, "▣ blocked");
    append_terminal_count(&mut parts, counts.canceling, "× canceling");
    append_terminal_count(&mut parts, counts.canceled, "× canceled");
    append_terminal_count(&mut parts, counts.skipped, "⊘ skipped");
    let mut progress = parts.join("  ·  ");
    if let Some(tool) = live_tool {
        progress.push_str(&queued_plan_segment(tool));
    }
    if queued_steer_steps > 0 {
        progress.push_str(&format!(" · queued: {queued_steer_steps} pending"));
    }
    progress
}

fn append_terminal_count(parts: &mut Vec<String>, count: usize, label: &str) {
    if count > 0 {
        parts.push(format!("{count} {label}"));
    }
}

/// Honest progress extras for the active task: a "stage N/M" fraction when
/// the producer reports one, and an ETA only when duration history exists —
/// never a fabricated estimate.
fn active_task_extras(session: &ActivitySession, eta_secs: Option<u64>) -> String {
    let mut extras = String::new();
    if let Some((done, total)) = active_stage_fraction(session) {
        extras.push_str(&format!("  ·  stage {done}/{total}"));
    }
    match eta_secs {
        Some(0) => extras.push_str("  ·  ~any moment"),
        Some(remaining) => extras.push_str(&format!("  ·  ~{} left", compact_secs(remaining))),
        None => {}
    }
    extras
}

fn active_stage_fraction(session: &ActivitySession) -> Option<(u64, u64)> {
    let row = session
        .tasks
        .values()
        .find(|row| row.state == DagTaskState::Active && row.prior_run_ref.is_none())?;
    stage_fraction(&row.last_label)
}

/// Parse a "stage N/M" marker out of a producer label like
/// "research · stage 2/4". Rejects nonsense fractions instead of guessing.
fn stage_fraction(label: &str) -> Option<(u64, u64)> {
    let rest = &label[label.find("stage ")? + "stage ".len()..];
    let fraction: String = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '/')
        .collect();
    let (done, total) = fraction.split_once('/')?;
    let done: u64 = done.parse().ok()?;
    let total: u64 = total.parse().ok()?;
    (total > 0 && done <= total).then_some((done, total))
}

fn compact_secs(seconds: u64) -> String {
    if seconds < 60 {
        return format!("{seconds}s");
    }
    format!("{}m{:02}s", seconds / 60, seconds % 60)
}

fn taskless_progress(live_tool: Option<&ActivityLiveTool>) -> String {
    match live_tool {
        Some(tool) => format!(
            "{} {}{} · running {}s{}{}",
            tool.spinner,
            tool.name,
            ambient_marker(tool),
            tool.elapsed_secs,
            queued_plan_segment(tool),
            queued_steer_segment(tool),
        ),
        None => "no task rows — streaming tool output".to_string(),
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

fn queued_steer_segment(tool: &ActivityLiveTool) -> String {
    if tool.queued_steer_steps == 0 {
        return String::new();
    }
    format!(" · queued: {} pending", tool.queued_steer_steps)
}

fn task_count(session: &ActivitySession, state: DagTaskState) -> usize {
    session
        .tasks
        .values()
        .filter(|row| row.prior_run_ref.is_none() && row.state == state)
        .count()
}

fn detailed_title(
    session: &ActivitySession,
    route: &ActivityRouteState,
    progress: &str,
    cost: &str,
) -> String {
    format!(
        "RUN FOCUS{phase}  run {run}  ·  {progress}  ·  {cost}{paused}{verbose}",
        phase = origin_phase_segment(session.origin_phase),
        run = compact_activity_run_id(&session.run_id),
        paused = paused_segment(route.paused),
        verbose = verbose_segment(route.verbose_subsystems),
    )
}

fn origin_phase_segment(phase: Option<WorkflowPhase>) -> String {
    phase.map_or_else(String::new, |phase| format!(" · {}", phase.label()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DagTaskRow;

    #[test]
    fn waiting_operator_question_overrides_terminal_looking_progress() {
        let session = ActivitySession::new("waiting-run");

        let model = activity_header_model(
            &session,
            &ActivityRouteState::default(),
            Some(ActivityRunOutcome::WaitingForOperator),
            None,
        );

        assert!(model.summary_title.contains("waiting for operator input"));
        assert!(!model.summary_title.contains("run completed"));
    }

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
        session.settle_runtime_cost(kuzushi_core::runtime::RuntimeCostReport::known(
            kuzushi_core::runtime::RuntimeCost::from_usd(0.375, "test").unwrap(),
        ));
        let mut route = ActivityRouteState::default();
        route.paused = true;
        route.verbose_subsystems = true;

        let model = activity_header_model(&session, &route, None, None);

        assert_eq!(
            model.summary_title,
            "RUN FOCUS  run tool-1778354160-e1b1d602a576  ·  1/2 done  ·  1 running"
        );
        assert!(model.detailed_title.contains("…d602a576"));
        assert!(model.detailed_title.contains("cost $0.3750"));
        assert!(model.detailed_title.contains("feed paused"));
    }

    /// C2: the header shows a producer-reported stage fraction and an ETA
    /// derived from real duration history — and neither without its source.
    #[test]
    fn header_progress_carries_stage_fraction_and_history_backed_eta() {
        let mut session = ActivitySession::new("run-eta");
        let mut active = task("threat-model:build", DagTaskState::Active, 0.0);
        active.last_label = "synthesis · stage 2/4".to_string();
        session
            .tasks
            .insert("threat-model:build".to_string(), active);

        let model = activity_header_model_with_queue(
            &session,
            &ActivityRouteState::default(),
            None,
            None,
            0,
            Some(190),
        );
        assert!(
            model.summary_title.contains("stage 2/4"),
            "{}",
            model.summary_title
        );
        assert!(
            model.summary_title.contains("~3m10s left"),
            "{}",
            model.summary_title
        );

        let no_history = activity_header_model_with_queue(
            &session,
            &ActivityRouteState::default(),
            None,
            None,
            0,
            None,
        );
        assert!(
            !no_history.summary_title.contains("left"),
            "no fabricated ETA without duration history: {}",
            no_history.summary_title
        );
    }

    #[test]
    fn stage_fraction_parses_labels_and_rejects_nonsense() {
        assert_eq!(stage_fraction("research · stage 2/4"), Some((2, 4)));
        assert_eq!(stage_fraction("stage 10/12 · gapfill"), Some((10, 12)));
        assert_eq!(stage_fraction("no marker here"), None);
        assert_eq!(stage_fraction("stage 5/4"), None);
        assert_eq!(stage_fraction("stage 1/0"), None);
    }

    #[test]
    fn activity_header_surfaces_missing_provider_usage_as_incomplete() {
        let mut session = ActivitySession::new("tool-incomplete");
        session.settle_runtime_cost(kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO);

        let model = activity_header_model(&session, &ActivityRouteState::default(), None, None);

        assert!(model.detailed_title.contains("cost >=$0.0000 (incomplete)"));
    }

    #[test]
    fn taskless_run_says_so_instead_of_zero_over_zero() {
        // Single-tool runs never register DAG tasks; "0/0 done · 0 running"
        // reads as a broken pipeline rather than a normal tool run.
        let session = ActivitySession::new("tool-1");
        let route = ActivityRouteState::default();
        let model = activity_header_model(&session, &route, None, None);
        assert!(model
            .summary_title
            .contains("no task rows — streaming tool output"));
        assert!(!model.summary_title.contains("0/0 done"));
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
            queued_steer_steps: 0,
        };
        let route = ActivityRouteState::default();
        let model = activity_header_model(&session, &route, None, Some(&live));
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
            queued_steer_steps: 0,
        };
        let route = ActivityRouteState::default();
        let model = activity_header_model(&session, &route, None, Some(&live));
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
    fn queued_steer_items_render_as_pending_behind_the_live_tool() {
        let session = ActivitySession::new("tool-1");
        let live = ActivityLiveTool {
            name: "taint-iris:hunt".to_string(),
            spinner: "⠷",
            elapsed_secs: 7,
            ambient: false,
            queued_plan_steps: 0,
            queued_steer_steps: 2,
        };
        let route = ActivityRouteState::default();
        let model = activity_header_model(&session, &route, None, Some(&live));
        assert!(
            model.summary_title.contains("queued: 2 pending"),
            "{}",
            model.summary_title
        );
        assert!(
            !model.summary_title.contains("running 7s · running"),
            "queued items must not read as a second running job: {}",
            model.summary_title
        );
    }

    #[test]
    fn queued_steer_items_remain_visible_for_dag_runs() {
        let mut session = ActivitySession::new("scan-1");
        session.tasks.insert(
            "sast:scan".to_string(),
            task("sast:scan", DagTaskState::Active, 0.0),
        );
        let model = activity_header_model_with_queue(
            &session,
            &ActivityRouteState::default(),
            None,
            None,
            1,
            None,
        );

        assert!(model.summary_title.contains("1 running"));
        assert!(model.summary_title.contains("queued: 1 pending"));
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
            &ActivityRouteState::default(),
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

    #[test]
    fn terminal_completed_zero_result_reports_status_and_count() {
        let session = ActivitySession::new("run-1");

        let model = activity_header_model(
            &session,
            &ActivityRouteState::default(),
            Some(ActivityRunOutcome::Terminal {
                status: "completed".to_string(),
                findings: Some(0),
                reason: None,
            }),
            None,
        );

        assert!(
            model.summary_title.contains("✓ run completed · 0 findings"),
            "{}",
            model.summary_title
        );
        assert!(!model.summary_title.contains("clean"));
    }

    #[test]
    fn terminal_completed_status_uses_completed_wording() {
        let session = ActivitySession::new("run-1");

        let model = activity_header_model(
            &session,
            &ActivityRouteState::default(),
            Some(ActivityRunOutcome::Terminal {
                status: "completed".to_string(),
                findings: Some(3),
                reason: None,
            }),
            None,
        );

        assert!(
            model.summary_title.contains("✓ run completed · 3 findings"),
            "{}",
            model.summary_title
        );
    }

    #[test]
    fn terminal_partial_result_reports_reason_without_clean_language() {
        let session = ActivitySession::new("run-1");

        let model = activity_header_model(
            &session,
            &ActivityRouteState::default(),
            Some(ActivityRunOutcome::Terminal {
                status: "partial".to_string(),
                findings: Some(7),
                reason: Some("semgrep timed out".to_string()),
            }),
            None,
        );

        assert!(
            model
                .summary_title
                .contains("⚠ run partial · 7 findings · reason: semgrep timed out"),
            "{}",
            model.summary_title
        );
        assert!(!model.summary_title.contains("clean"));
    }

    #[test]
    fn terminal_cancelled_result_scopes_an_unrecorded_finding_count_to_the_run() {
        let session = ActivitySession::new("run-1");

        let model = activity_header_model(
            &session,
            &ActivityRouteState::default(),
            Some(ActivityRunOutcome::Terminal {
                status: "cancelled".to_string(),
                findings: None,
                reason: None,
            }),
            None,
        );

        assert!(
            model
                .summary_title
                .contains("× run canceled · run findings not recorded"),
            "{}",
            model.summary_title
        );
        assert!(!model.summary_title.contains("reason:"));
    }

    #[test]
    fn terminal_problem_counts_stay_visible_in_progress_summary() {
        let mut session = ActivitySession::new("run-1");
        session.tasks.insert(
            "context:build".to_string(),
            task("context:build", DagTaskState::Done, 0.0),
        );
        session.tasks.insert(
            "triage:run".to_string(),
            task("triage:run", DagTaskState::Canceled, 0.0),
        );
        session.tasks.insert(
            "verify:finding".to_string(),
            task("verify:finding", DagTaskState::Failing, 0.0),
        );
        session.tasks.insert(
            "patch:finding".to_string(),
            task("patch:finding", DagTaskState::Skipped, 0.0),
        );

        let model = activity_header_model(&session, &ActivityRouteState::default(), None, None);

        assert!(
            model
                .summary_title
                .contains("1/4 done  ·  0 running  ·  1 ! failed  ·  1 × canceled  ·  1 ⊘ skipped"),
            "{}",
            model.summary_title
        );
    }

    fn task(id: &str, state: DagTaskState, cost_usd: f64) -> DagTaskRow {
        let mut row = DagTaskRow::queued(id.to_string(), id.to_string(), Vec::new());
        row.state = state;
        row.cost_usd = cost_usd;
        row
    }

    /// Item 5c: rows inherited from an earlier run in the sequence stay
    /// visible but never count against the focused run's header.
    #[test]
    fn header_counts_exclude_prior_run_rows() {
        let mut session = ActivitySession::new("run-current");
        session
            .tasks
            .insert("current".into(), task("current", DagTaskState::Done, 0.0));
        let mut inherited = task("prior-failed", DagTaskState::Failing, 0.0);
        inherited.prior_run_ref = Some("run-prior".to_string());
        session.tasks.insert("prior-failed".into(), inherited);

        let counts = ActivityTaskCounts::from_session(&session);

        assert_eq!(counts.total, 1);
        assert_eq!(counts.done, 1);
        assert_eq!(
            counts.failing, 0,
            "prior run's failure leaked into the header"
        );
    }
}
