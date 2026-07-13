use super::activity_dag_rows::{activity_dag_pane_rows, ActivityDagPaneRow};
use super::activity_empty_state::{activity_empty_state_model, ActivityEmptyStateModel};
use super::activity_feed_rows::ActivityFeedPaneRow;
use super::activity_footer::{activity_footer_model, ActivityFooterModel};
use super::activity_header::{
    activity_header_model_with_queue, ActivityHeaderModel, ActivityLiveTool, ActivityRunOutcome,
};
use super::activity_layout::{
    activity_frame_layout, activity_plain_pane_widths, ActivityFrameLayout, ActivityPaneWidths,
};
use super::activity_observability::{
    activity_heartbeat_model, activity_phase_strip_model, ActivityHeartbeatModel,
    ActivityPhaseStripModel,
};
use super::activity_pane_chrome::{
    activity_pane_chrome_model, activity_plain_pane_header_model, ActivityPaneChromeModel,
    ActivityPlainPaneHeaderModel,
};
use super::activity_plain_rows::{activity_plain_pane_rows, ActivityPlainPaneRow};
use super::activity_scroll::{activity_feed_scroll_offset, activity_task_scroll_offset};
use super::generated_views_feed::{activity_deck_plain_extra_rows, activity_deck_rows};
use crate::{ActivityRouteState, ActivitySession, DagTaskState, ShellApp, ViewDataState};
use kuzushi_core::RunSummary;
use std::time::Instant;

pub(crate) enum ActivityViewModel<'a> {
    Active(ActiveActivityViewModel<'a>),
    Inactive(ActivityEmptyStateModel),
}

pub(crate) struct ActiveActivityViewModel<'a> {
    app: &'a ShellApp,
    session: &'a ActivitySession,
    route: &'a ActivityRouteState,
    context_line: String,
}

pub(crate) fn activity_view_model(app: &ShellApp) -> ActivityViewModel<'_> {
    match app.activity() {
        Some(session) if manual_activity_session_is_idle(app, session) => {
            ActivityViewModel::Inactive(activity_empty_state_model())
        }
        Some(session) => ActivityViewModel::Active(ActiveActivityViewModel {
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
        && session.events.is_empty()
        && session
            .tasks
            .values()
            .all(|row| row.state == DagTaskState::Queued)
        && session.subsystem_aggregate.hidden_task_states.is_empty()
}

/// The Activity run's terminal failure, if any. Sourced from the live
/// activity card (set by both scan refusals and tool failures) and only once
/// nothing is still running, so an in-flight session never reads as failed.
fn activity_run_outcome(app: &ShellApp, session: &ActivitySession) -> Option<ActivityRunOutcome> {
    if activity_session_still_running(app, session) {
        return None;
    }
    activity_run_summary(app, session)
        .and_then(activity_run_summary_outcome)
        .or_else(|| live_activity_run_outcome(app))
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

impl<'a> ActiveActivityViewModel<'a> {
    pub(crate) fn header(&self) -> ActivityHeaderModel {
        let live_tool = self.live_tool();
        activity_header_model_with_queue(
            self.session,
            self.route,
            activity_run_outcome(self.app, self.session),
            live_tool.as_ref(),
            self.app.steer_queue().len(),
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

    pub(crate) fn phase_strip(&self) -> Option<ActivityPhaseStripModel> {
        activity_phase_strip_model(self.session, self.app.running_tool_name())
    }

    pub(crate) fn heartbeat(&self, now: Instant) -> ActivityHeartbeatModel {
        activity_heartbeat_model(
            self.session,
            self.app.running_tool_name(),
            activity_session_still_running(self.app, self.session),
            now,
        )
    }

    pub(crate) fn abort_banner(&self) -> Option<String> {
        activity_abort_banner(self.app)
    }

    pub(crate) fn frame_layout(&self) -> ActivityFrameLayout {
        activity_frame_layout()
    }

    /// Single-tool runs can still have live trace events. Keep TASKS visible
    /// whenever there is activity to show; collapse only for a fully empty
    /// session so OUTPUT can own the frame.
    pub(crate) fn collapse_dag_pane(&self) -> bool {
        self.session.tasks.is_empty()
            && self.session.events.is_empty()
            && self.app.running_tool_name().is_none()
    }

    pub(crate) fn pane_chrome(&self) -> ActivityPaneChromeModel {
        activity_pane_chrome_model(self.session, self.route)
    }

    pub(crate) fn plain_pane_widths(&self, width: u16) -> ActivityPaneWidths {
        activity_plain_pane_widths(width)
    }

    pub(crate) fn plain_pane_header(
        &self,
        widths: ActivityPaneWidths,
    ) -> ActivityPlainPaneHeaderModel {
        activity_plain_pane_header_model(self.session, self.route, widths.dag, widths.feed)
    }

    pub(crate) fn plain_pane_rows(
        &self,
        widths: ActivityPaneWidths,
        now: Instant,
    ) -> Vec<ActivityPlainPaneRow> {
        let output_rows = activity_deck_plain_extra_rows(
            self.app,
            self.session,
            self.route,
            widths.feed,
            self.app.running_tool_name(),
        );
        activity_plain_pane_rows(
            self.session,
            self.route,
            widths.dag,
            widths.feed,
            now,
            &output_rows,
            self.app.running_tool_name(),
        )
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

    /// The right pane is an output strip: one selected artifact/review page at
    /// a time. Live trace rows are integrated into the TASKS pane. Pages are pulled
    /// from persistent `ShellApp` state, so they persist across later phases and
    /// — via the on-disk snapshots — across sessions.
    pub(crate) fn feed_pane_rows(&self, inner_width: usize) -> Vec<ActivityFeedPaneRow> {
        activity_deck_rows(
            self.app,
            self.session,
            self.route,
            inner_width,
            self.app.running_tool_name(),
        )
    }

    pub(crate) fn task_scroll_offset(&self, rows: usize, viewport_rows: usize) -> usize {
        activity_task_scroll_offset(self.route, rows, viewport_rows)
    }

    pub(crate) fn feed_scroll_offset(&self, rows: usize, viewport_rows: usize) -> usize {
        activity_feed_scroll_offset(self.route, rows, viewport_rows)
    }

    pub(crate) fn footer(&self, width: u16) -> ActivityFooterModel {
        activity_footer_model(
            self.session,
            self.route,
            width,
            self.app.running_tool_name(),
            activity_abort_pending(self.app),
            self.app.input_mode(),
        )
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

fn activity_abort_pending(app: &ShellApp) -> bool {
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
    fn activity_view_model_projects_inactive_state() {
        let app = ShellApp::new(V2Config::default(), None);

        let ActivityViewModel::Inactive(empty) = activity_view_model(&app) else {
            panic!("expected inactive activity model");
        };

        assert_eq!(empty.title, "ACTIVITY · idle");
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

        let widths = model.plain_pane_widths(90);
        assert_eq!(
            model.header().summary_title,
            "ACTIVITY  run r-activity  ·  0/1 done  ·  0 running"
        );
        assert_eq!(model.pane_chrome().dag.block_title, "── TASKS ──");
        assert!(!model.plain_pane_rows(widths, Instant::now()).is_empty());
        assert!(model.footer(80).body.contains("[j/k] select"));
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
        app.set_activity(Some(ActivitySession::new("run-finished")));

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
    fn activity_deck_shows_selected_artifact_regardless_of_session_tasks() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.domain_mut()
            .set_taint_flows(vec![crate::TaintFlowSnapshot {
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
            }]);
        // The active session ran only an unrelated task — no taint-iris and no
        // threat-model — yet the persisted attack path must still pin to the
        // OUTPUT feed, since the views now persist across phases from app state.
        let mut session = ActivitySession::new("r-x");
        session.tasks.insert(
            "context:build".to_string(),
            DagTaskRow::queued("context:build".into(), "context".into(), Vec::new()),
        );
        app.set_activity(Some(session));
        app.activity_route_mut()
            .set_deck_page(crate::ActivityDeckPage::AttackPath);

        let ActivityViewModel::Active(model) = activity_view_model(&app) else {
            panic!("expected active activity model");
        };
        let rows = model.feed_pane_rows(120);
        assert!(rows.iter().any(|row| row.text.contains("ATTACK PATH")));
        assert!(rows.iter().any(|row| row.text.contains("CWE-89")));
    }
}
