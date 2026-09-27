use super::activity_dag_rows::{
    activity_dag_pane_rows, activity_dag_preferred_width, ActivityDagPaneRow,
};
use super::activity_empty_state::{activity_empty_state_model, ActivityEmptyStateModel};
use super::activity_feed_rows::{
    activity_feed_pane_rows, activity_feed_viewport_rows, ActivityFeedPaneRow,
};
use super::activity_footer::{
    activity_footer_model, push_run_focus_leave_hint, resolve_activity_footer_bindings,
    ActivityFooterModel,
};
use super::activity_header::{
    activity_header_model_with_queue, ActivityHeaderModel, ActivityLiveTool, ActivityRunOutcome,
};
use super::activity_layout::{
    activity_frame_layout, activity_pane_layout, ActivityFrameLayout, ActivityPaneLayout,
    ActivityPaneMetrics, ACTIVITY_WIDE_MIN_WIDTH,
};
use super::activity_observability::{activity_heartbeat_model, ActivityHeartbeatModel};
use super::activity_pane_chrome::{activity_pane_chrome_model, ActivityPaneChromeModel};
use super::activity_scroll::activity_task_scroll_offset;
use crate::app::PendingOperatorQuestion;
use crate::renderer::shared::text::{display_width, fit, wrap_text};
use crate::{ActivityRouteState, ActivitySession, DagTaskState, ShellApp, ViewDataState};
use kuzushi_core::RunSummary;
use std::time::Instant;

mod compact;

pub(crate) enum ActivityViewModel<'a> {
    Active(RunFocusModel<'a>),
    Inactive(ActivityEmptyStateModel),
}

pub(crate) struct RunFocusModel<'a> {
    app: &'a ShellApp,
    session: &'a ActivitySession,
    route: &'a ActivityRouteState,
    context_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperatorQuestionKeyHints {
    pub(crate) segments: Vec<String>,
    pub(crate) editor_segments: Vec<String>,
    pub(crate) other_binding: Option<String>,
}

pub(crate) fn activity_view_model(app: &ShellApp) -> ActivityViewModel<'_> {
    match app.activity() {
        Some(session) if manual_activity_session_is_idle(app, session) => {
            ActivityViewModel::Inactive(activity_empty_state_model())
        }
        Some(session) => ActivityViewModel::Active(RunFocusModel {
            app,
            session,
            route: app.activity_route(),
            context_line: activity_context_line(app),
        }),
        None => ActivityViewModel::Inactive(activity_empty_state_model()),
    }
}

fn manual_activity_session_is_idle(app: &ShellApp, session: &ActivitySession) -> bool {
    session.run_id.starts_with("manual-")
        && app.running_tool_name().is_none()
        && !app.scan().is_some_and(|scan| scan.running)
        && session.event_count() == 0
        && session
            .tasks
            .values()
            .all(|row| row.state == DagTaskState::Queued)
        && session.subsystem_aggregate.hidden_task_states.is_empty()
}

/// The Activity run's terminal outcome, if any. Typed lifecycle state is
/// authoritative; persisted summaries and legacy live cards only fill gaps.
/// Without a typed terminal item, nothing is terminal while work is in flight.
/// Remaining seconds for the active DAG task, ONLY when duration history for
/// that tool exists (same estimator as the ambient footer chip). No history,
/// no ETA — never a fabricated countdown.
fn active_dag_task_eta_secs(app: &ShellApp, session: &ActivitySession) -> Option<u64> {
    let row = session
        .tasks
        .values()
        .find(|row| row.state == DagTaskState::Active && row.prior_run_ref.is_none())?;
    let estimate = task_duration_estimate(app, &row.task_id)?;
    let elapsed = row.started_at?.elapsed().as_secs();
    Some(estimate.saturating_sub(elapsed))
}

/// Duration history is recorded per tool, while planned rows carry a bound
/// variant id such as `threat-model:build[stride]`; fall back to the tool.
fn task_duration_estimate(app: &ShellApp, task_id: &str) -> Option<u64> {
    app.estimate_task_duration_secs(task_id)
        .or_else(|| bound_tool_name(task_id).and_then(|tool| app.estimate_task_duration_secs(tool)))
}

fn bound_tool_name(task_id: &str) -> Option<&str> {
    task_id
        .split_once('[')
        .map(|(tool, _)| tool)
        .filter(|tool| !tool.is_empty())
}

/// True when the Run Focus run reached the same terminal outcome the header
/// reports, so the run can no longer change on its own. A run still waiting on
/// an operator answer is not terminal. Backgrounding is deliberately not part
/// of this predicate: `run_focus_backgrounded` governs completion auto-return
/// and focus ownership, and a run the operator is looking at in Run Focus is
/// terminal whether or not it was ever handed to the background.
pub(crate) fn run_focus_is_terminal(app: &ShellApp) -> bool {
    app.activity()
        .is_some_and(|session| activity_outcome_is_terminal(app, session))
}

fn activity_outcome_is_terminal(app: &ShellApp, session: &ActivitySession) -> bool {
    matches!(
        activity_run_outcome(app, session),
        Some(ActivityRunOutcome::Terminal { .. } | ActivityRunOutcome::Failed { .. })
    )
}

fn activity_run_outcome(app: &ShellApp, session: &ActivitySession) -> Option<ActivityRunOutcome> {
    if let Some(outcome) = operator_owned_run_outcome(app, session) {
        return Some(outcome);
    }
    let summary = activity_run_summary(app, session);
    let findings = summary
        .as_ref()
        .and_then(|summary| summary.findings)
        .or_else(|| active_scan_findings(app, session));
    if let Some(outcome) = typed_activity_run_outcome(session, findings) {
        return Some(outcome);
    }
    if activity_session_still_running(app, session) {
        return None;
    }
    summary
        .and_then(activity_run_summary_outcome)
        .or_else(|| live_activity_run_outcome(app))
}

fn operator_owned_run_outcome(
    app: &ShellApp,
    session: &ActivitySession,
) -> Option<ActivityRunOutcome> {
    if activity_abort_pending(app) {
        return Some(ActivityRunOutcome::Canceling);
    }
    session
        .operator_question
        .is_some()
        .then_some(ActivityRunOutcome::WaitingForOperator)
}

fn typed_activity_run_outcome(
    session: &ActivitySession,
    findings: Option<u64>,
) -> Option<ActivityRunOutcome> {
    let presentation = kuzushi_core::run_lifecycle::present_projection_with_hydration_and_health(
        &session.run_projection,
        kuzushi_core::run_lifecycle::RunProjectionSource::TypedV1,
        &session.run_presentation_hydration,
        session.effective_run_lifecycle_health(),
    );
    let status = presentation.terminal_status?;
    let reason = (status != kuzushi_core::run_lifecycle::RunItemStatus::Completed)
        .then_some(session.run_projection.terminal.as_ref())
        .flatten()
        .map(|terminal| terminal.summary.as_str().to_string());
    Some(ActivityRunOutcome::Terminal {
        status: status.label().to_string(),
        findings,
        reason,
    })
}

fn active_scan_findings(app: &ShellApp, session: &ActivitySession) -> Option<u64> {
    let scan = app.scan()?;
    (scan.run_id.as_deref() == Some(session.run_id.as_str()))
        .then(|| u64::try_from(scan.findings_count).ok())
        .flatten()
}

fn live_activity_run_outcome(app: &ShellApp) -> Option<ActivityRunOutcome> {
    use crate::app::LiveActivityPhase;
    let activity = app.live_activity()?;
    match activity.phase {
        LiveActivityPhase::Partial | LiveActivityPhase::Skipped => {
            Some(ActivityRunOutcome::Terminal {
                status: activity.phase.label().to_string(),
                findings: None,
                reason: Some(activity.detail.clone()),
            })
        }
        LiveActivityPhase::Failed | LiveActivityPhase::Refused => {
            Some(ActivityRunOutcome::Failed {
                subject: activity.subject.clone(),
            })
        }
        _ => None,
    }
}

fn activity_session_still_running(app: &ShellApp, session: &ActivitySession) -> bool {
    session
        .tasks
        .values()
        .any(|row| row.state == DagTaskState::Active)
        || app.running_tool_name().is_some()
        || app.scan().is_some_and(|scan| scan.running)
}

fn activity_run_summary(app: &ShellApp, session: &ActivitySession) -> Option<RunSummary> {
    let target = app.target()?;
    let ViewDataState::Ready(index) = app
        .workbench_cache()
        .borrow()
        .cached_run_summary_index(Some(target))
    else {
        return None;
    };
    index.get(&session.run_id).cloned()
}

fn activity_run_summary_outcome(summary: RunSummary) -> Option<ActivityRunOutcome> {
    let status = summary.status.trim().to_ascii_lowercase();
    if matches!(status.as_str(), "running" | "queued" | "started") || status.is_empty() {
        return None;
    }
    Some(ActivityRunOutcome::Terminal {
        status,
        findings: summary.findings,
        reason: summary.error,
    })
}

/// Workspace context for the Activity header (target · ctx · model ·
/// findings). Composed explicitly — the Activity view suppresses the bottom
/// status bar, so findings must travel here even though the general top
/// strip no longer carries them.
fn activity_context_line(app: &ShellApp) -> String {
    let model = super::context_strip_model(app);
    let execution_model = activity_execution_model_label(app)
        .unwrap_or_else(|| format!("configured {}", model.model));
    [
        format!("target:{}", model.target),
        model.context_state_segment(),
        format!("execution:{execution_model}"),
        model.findings.clone(),
    ]
    .join("  ·  ")
}

pub(crate) fn activity_execution_model_label(app: &ShellApp) -> Option<String> {
    let session = app.activity()?;
    if let Some(summary) = activity_run_summary(app, session) {
        return Some(
            summary
                .model
                .as_deref()
                .map(crate::app::display_model_selector)
                .unwrap_or_else(|| "none · runtime-free".to_string()),
        );
    }
    let selected = app
        .active_model_override()
        .or(app.config().model.as_deref())
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "none".to_string());
    Some(format!("{selected} · receipt pending"))
}

impl<'a> RunFocusModel<'a> {
    pub(crate) fn operator_question(&self) -> Option<&PendingOperatorQuestion> {
        self.session.operator_question.as_ref()
    }

    pub(crate) fn operator_question_key_hints(&self) -> OperatorQuestionKeyHints {
        operator_question_key_hints(self.app)
    }

    pub(crate) fn header(&self) -> ActivityHeaderModel {
        let live_tool = self.live_tool();
        activity_header_model_with_queue(
            self.session,
            self.route,
            activity_run_outcome(self.app, self.session),
            live_tool.as_ref(),
            self.app.steer_queue().len(),
            active_dag_task_eta_secs(self.app, self.session),
        )
    }

    /// The tool executing behind this run, with the spinner + elapsed
    /// counter the header ticks for taskless runs. `None` once it ends.
    fn live_tool(&self) -> Option<ActivityLiveTool> {
        let name = self.app.running_tool_name()?.to_string();
        Some(ActivityLiveTool {
            ambient: self.app.tool_is_ambient(&name),
            queued_plan_steps: self.app.stalled_planning_steps(),
            queued_steer_steps: self.app.steer_queue().len(),
            name,
            spinner: self.app.spinner_glyph(),
            elapsed_secs: self.session.started_at.elapsed().as_secs(),
        })
    }

    pub(crate) fn context_line(&self) -> &str {
        &self.context_line
    }

    pub(crate) fn heartbeat(&self, now: Instant) -> ActivityHeartbeatModel {
        let outcome = activity_run_outcome(self.app, self.session);
        activity_heartbeat_model(
            self.session,
            self.app.running_tool_name(),
            activity_session_still_running(self.app, self.session),
            outcome.as_ref(),
            now,
        )
    }

    pub(crate) fn abort_banner(&self) -> Option<String> {
        activity_abort_banner(self.app)
    }

    /// Single-tool runs can still have live trace events. Keep TASKS visible
    /// whenever there is activity to show; collapse only for a fully empty
    /// session so OUTPUT can own the frame.
    pub(crate) fn collapse_dag_pane(&self) -> bool {
        self.session.tasks.is_empty()
            && self.session.event_count() == 0
            && self.app.running_tool_name().is_none()
    }

    pub(crate) fn pane_chrome(&self) -> ActivityPaneChromeModel {
        activity_pane_chrome_model(self.session, self.route)
    }

    pub(crate) fn dag_pane_rows(
        &self,
        inner_width: usize,
        now: Instant,
    ) -> Vec<ActivityDagPaneRow> {
        activity_dag_pane_rows(
            self.session,
            self.route,
            inner_width,
            now,
            self.app.running_tool_name(),
        )
    }

    /// The right pane is one live output window. Generated artifacts belong to
    /// the durable phase pages and contextual visualization decks; Run Focus
    /// does not compete with them for the same pane.
    pub(crate) fn feed_pane_rows(&self, inner_width: usize) -> Vec<ActivityFeedPaneRow> {
        activity_feed_pane_rows(
            self.session,
            self.route,
            inner_width,
            self.app.running_tool_name(),
            Instant::now(),
        )
    }

    pub(crate) fn feed_pane_viewport_rows(
        &self,
        inner_width: usize,
        inner_height: usize,
    ) -> Vec<ActivityFeedPaneRow> {
        activity_feed_viewport_rows(
            self.session,
            self.route,
            inner_width,
            inner_height,
            self.app.running_tool_name(),
            Instant::now(),
        )
    }

    pub(crate) fn task_scroll_offset(&self, rows: usize, viewport_rows: usize) -> usize {
        activity_task_scroll_offset(self.route, rows, viewport_rows)
    }

    pub(crate) fn pane_layout(&self, width: u16, height: u16, now: Instant) -> ActivityPaneLayout {
        activity_pane_layout(width, height, self.pane_metrics(width, now))
    }

    fn pane_metrics(&self, width: u16, now: Instant) -> ActivityPaneMetrics {
        let inner_width = width.saturating_sub(2) as usize;
        ActivityPaneMetrics {
            task_content_rows: self.dag_pane_rows(inner_width, now).len(),
            task_content_width: activity_dag_preferred_width(self.session, self.route),
            output_event_rows: self.session.event_count(),
        }
    }

    pub(crate) fn footer(&self, width: u16) -> ActivityFooterModel {
        let mut footer = activity_footer_model(
            self.session,
            self.route,
            width,
            self.app.running_tool_name(),
            activity_abort_pending(self.app),
            self.app.input_mode(),
        );
        if run_focus_is_terminal(self.app) {
            push_run_focus_leave_hint(&mut footer, self.app);
        }
        let footer = resolve_activity_footer_bindings(footer, self.app, width);
        if self.operator_question().is_some() {
            return operator_question_owned_footer(footer, width);
        }
        footer
    }

    pub(crate) fn heartbeat_rows(
        &self,
        width: u16,
        now: Instant,
    ) -> (ActivityHeartbeatModel, Vec<String>) {
        let heartbeat = self.heartbeat(now);
        let rows = activity_health_rows(&heartbeat.text, width);
        (heartbeat, rows)
    }

    pub(crate) fn frame_layout(&self, width: u16, heartbeat_rows: usize) -> ActivityFrameLayout {
        let footer = self.footer(width);
        let header_rows = 2
            + u16::try_from(heartbeat_rows).unwrap_or(u16::MAX)
            + u16::from(self.abort_banner().is_some());
        let footer_rows = 1
            + u16::try_from(footer.hint_rows.len().max(1)).unwrap_or(u16::MAX)
            + u16::from(footer.steer_line.is_some())
            + u16::from(footer.steer_error.is_some());
        activity_frame_layout(header_rows, footer_rows)
    }
}

fn activity_health_rows(text: &str, width: u16) -> Vec<String> {
    let width = width as usize;
    if width < usize::from(ACTIVITY_WIDE_MIN_WIDTH) || display_width(text) <= width {
        return vec![fit(text, width)];
    }
    let indent = text.strip_prefix(' ').map_or("", |_| " ");
    let body_width = width.saturating_sub(indent.len());
    let mut rows = wrap_text(text.trim_start(), body_width);
    if rows.len() > 2 {
        let overflow = rows[1..].join(" ");
        rows[1] = fit(&overflow, body_width);
        rows.truncate(2);
    }
    for row in &mut rows {
        row.insert_str(0, indent);
    }
    rows
}

fn operator_question_owned_footer(
    mut footer: ActivityFooterModel,
    width: u16,
) -> ActivityFooterModel {
    footer.body = " ? WAITING INPUT  question owns keyboard · controls below".to_string();
    footer.body_line = footer.body.chars().take(width as usize).collect();
    footer.hints.clear();
    footer.hint_rows = vec![Vec::new()];
    footer.steer_line = None;
    footer.steer_error = None;
    footer
}

fn operator_question_key_hints(app: &ShellApp) -> OperatorQuestionKeyHints {
    let mut segments = Vec::new();
    push_question_hint(&mut segments, app, "submit", &["Enter"], "submit");
    push_question_hint(&mut segments, app, "cancel", &["Esc"], "cancel");
    push_question_hint(&mut segments, app, "background", &["b"], "background");
    push_paired_question_hint(
        &mut segments,
        app,
        ("previous_question", &["←"]),
        ("next_question", &["→"]),
        "question",
    );
    push_paired_question_hint(
        &mut segments,
        app,
        ("previous_option", &["↑", "k"]),
        ("next_option", &["↓", "j"]),
        "choose",
    );
    segments.push("1–3 direct".to_string());
    let other_bindings = app
        .ui()
        .keymap_binding_labels("question", "other", &["Tab"]);
    if !other_bindings.is_empty() {
        segments.push(format!("{} Other", other_bindings.join("/")));
    }
    let mut editor_segments = Vec::new();
    push_question_hint(&mut editor_segments, app, "submit", &["Enter"], "submit");
    push_question_hint(&mut editor_segments, app, "cancel", &["Esc"], "return");
    editor_segments.push("Ctrl+W/Alt+Backspace delete word".to_string());
    editor_segments.push("←/→ cursor".to_string());
    OperatorQuestionKeyHints {
        segments,
        editor_segments,
        other_binding: other_bindings.first().cloned(),
    }
}

fn push_question_hint(
    hints: &mut Vec<String>,
    app: &ShellApp,
    action: &str,
    defaults: &[&str],
    label: &str,
) {
    let bindings = app.ui().keymap_binding_labels("question", action, defaults);
    if !bindings.is_empty() {
        hints.push(format!("{} {label}", bindings.join("/")));
    }
}

fn push_paired_question_hint(
    hints: &mut Vec<String>,
    app: &ShellApp,
    previous: (&str, &[&str]),
    next: (&str, &[&str]),
    label: &str,
) {
    let mut bindings = app
        .ui()
        .keymap_binding_labels("question", previous.0, previous.1);
    bindings.extend(app.ui().keymap_binding_labels("question", next.0, next.1));
    if !bindings.is_empty() {
        hints.push(format!("{} {label}", bindings.join("/")));
    }
}

fn activity_abort_banner(app: &ShellApp) -> Option<String> {
    let subjects = activity_abort_subjects(app);
    (!subjects.is_empty()).then(|| {
        format!(
            "⚠ abort requested for {} — waiting for cleanup; Ctrl+C will not exit while work is live",
            subjects.join(", ")
        )
    })
}

pub(super) fn activity_abort_pending(app: &ShellApp) -> bool {
    !activity_abort_subjects(app).is_empty()
}

fn activity_abort_subjects(app: &ShellApp) -> Vec<&'static str> {
    [
        (app.scan().is_some_and(|scan| scan.abort_requested), "scan"),
        (app.tool_abort_requested(), "tool"),
        (
            app.agent_chat().is_some_and(|agent| agent.abort_requested),
            "agent",
        ),
        (app.plan_abort_requested(), "plan"),
        (app.threat_abort_requested(), "threat model"),
    ]
    .into_iter()
    .filter_map(|(active, subject)| active.then_some(subject))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DagTaskRow;
    use kuzushi_core::{RunSummary, V2Config, WorkspaceTarget};

    #[test]
    fn a_bound_variant_row_falls_back_to_its_tool_history() {
        assert_eq!(
            bound_tool_name("threat-model:build[stride]"),
            Some("threat-model:build")
        );
        assert_eq!(bound_tool_name("context:build"), None);
        assert_eq!(bound_tool_name("[odd]"), None);
    }

    #[test]
    fn activity_view_model_projects_inactive_state() {
        let app = ShellApp::new(V2Config::default(), None);

        let ActivityViewModel::Inactive(empty) = activity_view_model(&app) else {
            panic!("expected inactive activity model");
        };

        assert_eq!(empty.title, "RUN FOCUS · idle");
        assert_eq!(empty.glyph_label, "no active run");
        assert!(empty.explanations.iter().any(|line| line.contains("logs")));
        assert!(empty.ctas.iter().any(|(command, _)| *command == "scan"));
    }

    #[test]
    fn activity_view_model_projects_active_session_chrome() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut session = ActivitySession::new("r-activity");
        session.tasks.insert(
            "context:build".to_string(),
            DagTaskRow::queued("context:build".into(), "context".into(), Vec::new()),
        );
        app.set_activity(Some(session));
        app.set_input_mode(crate::InputMode::Navigate);

        let ActivityViewModel::Active(model) = activity_view_model(&app) else {
            panic!("expected active activity model");
        };

        assert_eq!(
            model.header().summary_title,
            "RUN FOCUS  run r-activity  ·  0/1 done  ·  0 running"
        );
        assert_eq!(model.pane_chrome().dag.block_title, "── TASKS ──");
        assert!(!model.dag_pane_rows(36, Instant::now()).is_empty());
        assert!(model.footer(80).body.contains("[j/k] select"));
    }

    #[test]
    fn heartbeat_wraps_at_the_wide_layout_threshold() {
        let text = "status ".repeat(20);

        let rows = activity_health_rows(&text, ACTIVITY_WIDE_MIN_WIDTH);

        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn question_hints_use_the_runtime_keymap_contract() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "question".to_string(),
            action: "submit".to_string(),
            bindings: vec!["ctrl+s".to_string()],
        }];
        let app = ShellApp::new(config, None);

        let hints = operator_question_key_hints(&app).segments.join(" · ");

        assert!(hints.contains("ctrl+s submit"), "{hints}");
        assert!(!hints.contains("Enter submit"), "{hints}");
        assert!(hints.contains("Esc cancel"), "{hints}");
    }

    #[test]
    fn question_other_inline_hint_uses_the_runtime_binding() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "question".to_string(),
            action: "other".to_string(),
            bindings: vec!["ctrl+o".to_string()],
        }];
        let app = ShellApp::new(config, None);

        let hints = operator_question_key_hints(&app);

        assert_eq!(hints.other_binding.as_deref(), Some("ctrl+o"));
        assert!(hints.segments.join(" · ").contains("ctrl+o Other"));
    }

    #[test]
    fn question_other_editor_hints_only_advertise_editor_actions() {
        let app = ShellApp::new(V2Config::default(), None);

        let hints = operator_question_key_hints(&app)
            .editor_segments
            .join(" · ");

        assert!(hints.contains("Enter submit"), "{hints}");
        assert!(hints.contains("Esc return"), "{hints}");
        assert!(hints.contains("Alt+Backspace delete word"), "{hints}");
        assert!(!hints.contains("background"), "{hints}");
        assert!(!hints.contains("direct"), "{hints}");
    }

    #[test]
    fn question_owned_footer_suppresses_run_focus_shortcuts() {
        let session = ActivitySession::new("waiting-run");
        let footer = activity_footer_model(
            &session,
            &ActivityRouteState::default(),
            80,
            None,
            false,
            crate::InputMode::Navigate,
        );

        let footer = operator_question_owned_footer(footer, 80);

        assert!(footer.body.contains("question owns keyboard"));
        assert!(footer.hints.is_empty());
        assert_eq!(footer.hint_rows, vec![Vec::new()]);
    }

    #[test]
    fn run_focus_footer_uses_the_runtime_binding_contract() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "run_focus".to_string(),
            action: "background".to_string(),
            bindings: vec!["ctrl+b".to_string()],
        }];
        let mut app = ShellApp::new(config, None);
        app.set_activity(Some(ActivitySession::new("run-remapped")));

        let ActivityViewModel::Active(model) = activity_view_model(&app) else {
            panic!("expected active activity model");
        };
        let footer = model.footer(120);
        let hints = footer
            .hint_rows
            .iter()
            .flatten()
            .map(|hint| format!("{} {}", hint.plain_key_text, hint.plain_hint_text))
            .collect::<Vec<_>>();

        assert!(
            hints.contains(&"ctrl+b background".to_string()),
            "{hints:?}"
        );
        assert!(!hints.contains(&"b background".to_string()), "{hints:?}");
    }

    #[test]
    fn activity_header_uses_terminal_run_summary_status_and_findings() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        kuzushi_core::write_run_summary(
            workspace.root(),
            &RunSummary::running(
                "run-finished",
                "scan",
                None,
                workspace.root().display().to_string(),
            )
            .complete()
            .with_findings(Some(2)),
        )
        .unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();
        app.set_activity(Some(completed_terminal_session("run-finished")));

        let ActivityViewModel::Active(model) = activity_view_model(&app) else {
            panic!("expected active activity model");
        };

        assert!(
            model
                .header()
                .summary_title
                .contains("✓ run completed · 2 findings"),
            "{}",
            model.header().summary_title
        );
        assert!(!model.header().summary_title.contains("reason:"));
    }

    fn completed_terminal_session(run_id: &str) -> ActivitySession {
        use kuzushi_core::run_lifecycle::{
            RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemStatus, RunItemV1, SafeText,
            WorkflowContinuation,
        };

        let mut session = ActivitySession::new(run_id);
        let item = RunItemEnvelopeV1::new(
            1,
            RunId::parse(run_id).unwrap(),
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Completed,
                summary: SafeText::operator_visible("run completed"),
                cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("complete"),
                },
            },
            None,
        )
        .unwrap();
        session.apply_run_item(item).unwrap();
        session
    }

    #[test]
    fn typed_blocked_outcome_overrides_a_cached_completed_summary() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let run_id = "run-authoritative-blocked";
        kuzushi_core::write_run_summary(
            workspace.root(),
            &RunSummary::running(run_id, "tool", None, workspace.root().display().to_string())
                .complete(),
        )
        .unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();
        app.set_activity(Some(blocked_terminal_session(run_id)));

        let ActivityViewModel::Active(model) = activity_view_model(&app) else {
            panic!("expected active activity model");
        };
        let header = model.header().summary_title;
        let heartbeat = model.heartbeat(Instant::now()).text;
        assert!(header.contains("▣ run blocked"), "{header}");
        assert!(!header.contains("✓ run completed"), "{header}");
        assert!(heartbeat.contains("▣ BLOCKED"), "{heartbeat}");
        assert!(!heartbeat.contains("✓ COMPLETE"), "{heartbeat}");
    }

    fn blocked_terminal_session(run_id: &str) -> ActivitySession {
        use kuzushi_core::run_lifecycle::{
            RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemStatus, RunItemV1, SafeText,
            WorkflowContinuation,
        };

        let mut session = ActivitySession::new(run_id);
        let item = RunItemEnvelopeV1::new(
            1,
            RunId::parse(run_id).unwrap(),
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Blocked,
                summary: SafeText::operator_visible("authorization required"),
                cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("await authorization"),
                },
            },
            None,
        )
        .unwrap();
        session.apply_run_item(item).unwrap();
        session
    }

    #[test]
    fn scanner_only_activity_labels_execution_as_runtime_free() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        kuzushi_core::write_run_summary(
            workspace.root(),
            &RunSummary::running(
                "run-static",
                "scan",
                Some("sast:scan".to_string()),
                workspace.root().display().to_string(),
            )
            .complete(),
        )
        .unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-5.5".to_string());
        let mut app = ShellApp::new(config, Some(&workspace));
        app.hydrate_all_view_data_for_test();
        app.set_activity(Some(ActivitySession::new("run-static")));

        let ActivityViewModel::Active(model) = activity_view_model(&app) else {
            panic!("expected active activity model");
        };

        assert!(model
            .context_line()
            .contains("execution:none · runtime-free"));
        assert!(!model.context_line().contains("execution:openai"));
    }

    #[test]
    fn activity_header_uses_partial_run_reason_from_summary() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut summary = RunSummary::running(
            "run-partial",
            "tool",
            Some("sast:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .with_findings(Some(1));
        summary.status = "partial".to_string();
        summary.error = Some("triage stage did not complete".to_string());
        kuzushi_core::write_run_summary(workspace.root(), &summary).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();
        app.set_activity(Some(ActivitySession::new("run-partial")));

        let ActivityViewModel::Active(model) = activity_view_model(&app) else {
            panic!("expected active activity model");
        };

        let title = model.header().summary_title;
        assert!(title.contains("⚠ run partial · 1 finding"), "{title}");
        assert!(
            title.contains("reason: triage stage did not complete"),
            "{title}"
        );
    }

    #[test]
    fn run_focus_output_shows_live_lifecycle_instead_of_persisted_artifacts() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.domain_mut().set_taint_flows(vec![test_taint_flow()]);
        app.set_activity(Some(live_output_session()));
        let ActivityViewModel::Active(model) = activity_view_model(&app) else {
            panic!("expected active activity model");
        };
        let rows = model.feed_pane_rows(120);
        assert!(rows
            .iter()
            .any(|row| row.text.contains("Mapping live output")));
        assert!(!rows.iter().any(|row| row.text.contains("ATTACK PATH")));
        assert!(!rows.iter().any(|row| row.text.contains("CWE-89")));
    }

    fn live_output_session() -> ActivitySession {
        let mut session = ActivitySession::new("r-x");
        session.tasks.insert(
            "context:build".to_string(),
            DagTaskRow::queued("context:build".into(), "context".into(), Vec::new()),
        );
        session
            .apply_run_item(
                kuzushi_core::run_lifecycle::RunItemEnvelopeV1::new(
                    1,
                    kuzushi_core::run_lifecycle::RunId::parse("r-x").unwrap(),
                    kuzushi_core::run_lifecycle::RunItemId::new(),
                    kuzushi_core::run_lifecycle::RunItemSource::Workflow,
                    kuzushi_core::run_lifecycle::RunItemV1::DiagnosticNotice {
                        level: kuzushi_core::run_lifecycle::DiagnosticLevel::Info,
                        message: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                            "Mapping live output",
                        ),
                    },
                    None,
                )
                .unwrap(),
            )
            .unwrap();
        session
    }

    fn test_taint_flow() -> crate::TaintFlowSnapshot {
        crate::TaintFlowSnapshot {
            finding_fingerprint: None,
            finding_identity_id: None,
            cwe: "CWE-89".to_string(),
            severity: "critical".to_string(),
            stages: vec![crate::TaintStage {
                message: "order_id".to_string(),
                file: "orders.rs".to_string(),
                line: 1,
                snippet: None,
            }],
        }
    }
}
