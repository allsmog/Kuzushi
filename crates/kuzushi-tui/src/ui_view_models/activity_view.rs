use super::activity_dag_rows::{activity_dag_pane_rows, ActivityDagPaneRow};
use super::activity_empty_state::{activity_empty_state_model, ActivityEmptyStateModel};
use super::activity_feed_rows::ActivityFeedPaneRow;
use super::activity_footer::{activity_footer_model, ActivityFooterModel};
use super::activity_header::{
    activity_header_model, ActivityHeaderModel, ActivityLiveTool, ActivityRunOutcome,
};
use super::activity_layout::{
    activity_frame_layout, activity_plain_pane_widths, ActivityFrameLayout, ActivityPaneWidths,
};
use super::activity_pane_chrome::{
    activity_pane_chrome_model, activity_plain_pane_header_model, ActivityPaneChromeModel,
    ActivityPlainPaneHeaderModel,
};
use super::activity_plain_rows::{activity_plain_pane_rows, ActivityPlainPaneRow};
use super::activity_scroll::{activity_feed_scroll_offset, activity_task_scroll_offset};
use super::generated_views_feed::{activity_deck_plain_extra_rows, activity_deck_rows};
use crate::{ActivitySession, DagTaskState, ShellApp};
use std::time::Instant;

pub(crate) enum ActivityViewModel<'a> {
    Active(ActiveActivityViewModel<'a>),
    Inactive(ActivityEmptyStateModel),
}

pub(crate) struct ActiveActivityViewModel<'a> {
    app: &'a ShellApp,
    session: &'a ActivitySession,
    context_line: String,
}

pub(crate) fn activity_view_model(app: &ShellApp) -> ActivityViewModel<'_> {
    match app.activity.as_ref() {
        Some(session) if manual_activity_session_is_idle(app, session) => {
            ActivityViewModel::Inactive(activity_empty_state_model())
        }
        Some(session) => ActivityViewModel::Active(ActiveActivityViewModel {
            app,
            session,
            context_line: activity_context_line(app),
        }),
        None => ActivityViewModel::Inactive(activity_empty_state_model()),
    }
}

fn manual_activity_session_is_idle(app: &ShellApp, session: &ActivitySession) -> bool {
    session.run_id.starts_with("manual-")
        && app.running_tool_name().is_none()
        && !app.scan.as_ref().is_some_and(|scan| scan.running)
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
    use crate::app::{DagTaskState, LiveActivityPhase};
    let still_running = session
        .tasks
        .values()
        .any(|row| row.state == DagTaskState::Active);
    if still_running {
        return None;
    }
    let activity = app.live_activity.as_ref()?;
    matches!(activity.phase, LiveActivityPhase::Refused).then(|| ActivityRunOutcome::Failed {
        subject: activity.subject.clone(),
    })
}

/// Workspace context for the Activity header (target · ctx · model ·
/// findings). Composed explicitly — the Activity view suppresses the bottom
/// status bar, so findings must travel here even though the general top
/// strip no longer carries them.
fn activity_context_line(app: &ShellApp) -> String {
    let model = super::context_strip_model(app);
    [
        format!("target:{}", model.target),
        model.context_state_segment(),
        format!("model:{}", model.model),
        model.findings.clone(),
    ]
    .join("  ·  ")
}

impl<'a> ActiveActivityViewModel<'a> {
    pub(crate) fn header(&self) -> ActivityHeaderModel {
        activity_header_model(
            self.session,
            activity_run_outcome(self.app, self.session),
            self.live_tool().as_ref(),
        )
    }

    /// The tool executing behind this run, with the spinner + elapsed
    /// counter the header ticks for taskless runs. `None` once it ends.
    fn live_tool(&self) -> Option<ActivityLiveTool> {
        let name = self.app.running_tool_name()?.to_string();
        Some(ActivityLiveTool {
            ambient: self.app.tool_is_ambient(&name),
            queued_plan_steps: self.app.stalled_planning_steps(),
            name,
            spinner: self.app.spinner_glyph(),
            elapsed_secs: self.session.started_at.elapsed().as_secs(),
        })
    }

    pub(crate) fn context_line(&self) -> &str {
        &self.context_line
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
        activity_pane_chrome_model(self.session)
    }

    pub(crate) fn plain_pane_widths(&self, width: u16) -> ActivityPaneWidths {
        activity_plain_pane_widths(width)
    }

    pub(crate) fn plain_pane_header(
        &self,
        widths: ActivityPaneWidths,
    ) -> ActivityPlainPaneHeaderModel {
        activity_plain_pane_header_model(self.session, widths.dag, widths.feed)
    }

    pub(crate) fn plain_pane_rows(
        &self,
        widths: ActivityPaneWidths,
        now: Instant,
    ) -> Vec<ActivityPlainPaneRow> {
        let output_rows = activity_deck_plain_extra_rows(self.app, self.session, widths.feed);
        activity_plain_pane_rows(
            self.session,
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
        activity_dag_pane_rows(self.session, inner_width, now, self.app.running_tool_name())
    }

    /// The right pane is an output strip: one selected artifact/review page at
    /// a time. Live trace rows are integrated into the TASKS pane. Pages are pulled
    /// from persistent `ShellApp` state, so they persist across later phases and
    /// — via the on-disk snapshots — across sessions.
    pub(crate) fn feed_pane_rows(&self, inner_width: usize) -> Vec<ActivityFeedPaneRow> {
        activity_deck_rows(
            self.app,
            self.session,
            inner_width,
            self.app.running_tool_name(),
        )
    }

    pub(crate) fn task_scroll_offset(&self, rows: usize, viewport_rows: usize) -> usize {
        activity_task_scroll_offset(self.session, rows, viewport_rows)
    }

    pub(crate) fn feed_scroll_offset(&self, rows: usize, viewport_rows: usize) -> usize {
        activity_feed_scroll_offset(self.session, rows, viewport_rows)
    }

    pub(crate) fn footer(&self, width: u16) -> ActivityFooterModel {
        activity_footer_model(self.session, width, self.app.running_tool_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DagTaskRow;
    use kuzushi_core::V2Config;

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
        app.activity = Some(session);

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
        assert!(model.footer(80).body.contains("hover [j/k]"));
    }

    #[test]
    fn activity_deck_shows_selected_artifact_regardless_of_session_tasks() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.taint_flow = Some(crate::TaintFlowSnapshot {
            cwe: "CWE-89".to_string(),
            severity: "critical".to_string(),
            stages: vec![crate::TaintStage {
                message: "order_id".to_string(),
                file: "orders.rs".to_string(),
                line: 1,
            }],
        });
        // The active session ran only an unrelated task — no taint-iris and no
        // threat-model — yet the persisted attack path must still pin to the
        // OUTPUT feed, since the views now persist across phases from app state.
        let mut session = ActivitySession::new("r-x");
        session.tasks.insert(
            "context:build".to_string(),
            DagTaskRow::queued("context:build".into(), "context".into(), Vec::new()),
        );
        app.activity = Some(session);
        app.activity
            .as_mut()
            .unwrap()
            .set_deck_page(crate::ActivityDeckPage::AttackPath);

        let ActivityViewModel::Active(model) = activity_view_model(&app) else {
            panic!("expected active activity model");
        };
        let rows = model.feed_pane_rows(120);
        assert!(rows.iter().any(|row| row.text.contains("ATTACK PATH")));
        assert!(rows.iter().any(|row| row.text.contains("CWE-89")));
    }
}
