use super::activity_dag_rows::{activity_dag_pane_rows, ActivityDagPaneRow};
use super::activity_empty_state::{activity_empty_state_model, ActivityEmptyStateModel};
use super::activity_feed_rows::{
    activity_feed_pane_rows, ActivityFeedPaneRow, ActivityFeedRowTone,
};
use super::activity_footer::{activity_footer_model, ActivityFooterModel};
use super::activity_header::{activity_header_model, ActivityHeaderModel};
use super::activity_layout::{
    activity_frame_layout, activity_plain_pane_widths, ActivityFrameLayout, ActivityPaneWidths,
};
use super::activity_pane_chrome::{
    activity_pane_chrome_model, activity_plain_pane_header_model, ActivityPaneChromeModel,
    ActivityPlainPaneHeaderModel,
};
use super::activity_plain_rows::{activity_plain_pane_rows, ActivityPlainPaneRow};
use super::activity_scroll::{activity_feed_scroll_offset, activity_task_scroll_offset};
use super::threat_dfd_diagram::threat_dfd_diagram_feed_rows;
use crate::{ActivitySession, ShellApp};
use std::time::Instant;

pub(crate) enum ActivityViewModel<'a> {
    Active(ActiveActivityViewModel<'a>),
    Inactive(ActivityEmptyStateModel),
}

pub(crate) struct ActiveActivityViewModel<'a> {
    session: &'a ActivitySession,
    context_line: String,
    dfd_doc: Option<serde_json::Value>,
}

pub(crate) fn activity_view_model(app: &ShellApp) -> ActivityViewModel<'_> {
    match app.activity.as_ref() {
        Some(session) => ActivityViewModel::Active(ActiveActivityViewModel {
            session,
            context_line: activity_context_line(app),
            dfd_doc: activity_dfd_doc(app, session),
        }),
        None => ActivityViewModel::Inactive(activity_empty_state_model()),
    }
}

/// The persisted threat model, but only once a `threat-model` task is part of
/// this run — so the DFD only decorates the OUTPUT pane when it's relevant.
fn activity_dfd_doc(app: &ShellApp, session: &ActivitySession) -> Option<serde_json::Value> {
    session
        .tasks
        .keys()
        .any(|task_id| task_id.starts_with("threat-model") || task_id.starts_with("threat_model"))
        .then(|| super::threat_model_doc(app))
        .flatten()
}

/// Workspace context for the Activity header (target · ctx · model · findings).
/// Drops the `mode:`/`view:` segments — redundant inside the Activity view —
/// so the operator sees model + findings here instead of in a bottom strip.
fn activity_context_line(app: &ShellApp) -> String {
    super::context_strip_model(app)
        .compact_segments()
        .into_iter()
        .filter(|segment| !segment.starts_with("mode:") && !segment.starts_with("view:"))
        .collect::<Vec<_>>()
        .join("  ·  ")
}

impl<'a> ActiveActivityViewModel<'a> {
    pub(crate) fn header(&self) -> ActivityHeaderModel {
        activity_header_model(self.session)
    }

    pub(crate) fn context_line(&self) -> &str {
        &self.context_line
    }

    pub(crate) fn frame_layout(&self) -> ActivityFrameLayout {
        activity_frame_layout()
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
        activity_plain_pane_rows(self.session, widths.dag, widths.feed, now)
    }

    pub(crate) fn dag_pane_rows(
        &self,
        inner_width: usize,
        now: Instant,
    ) -> Vec<ActivityDagPaneRow> {
        activity_dag_pane_rows(self.session, inner_width, now)
    }

    pub(crate) fn feed_pane_rows(&self, inner_width: usize) -> Vec<ActivityFeedPaneRow> {
        let mut rows = activity_feed_pane_rows(self.session, inner_width);
        self.append_dfd_diagram(&mut rows, inner_width);
        rows
    }

    /// After the live feed, draw the target's data-flow diagram so a completed
    /// `threat-model` run leaves a readable picture in the OUTPUT pane.
    fn append_dfd_diagram(&self, rows: &mut Vec<ActivityFeedPaneRow>, inner_width: usize) {
        let Some(doc) = self.dfd_doc.as_ref() else {
            return;
        };
        let diagram = threat_dfd_diagram_feed_rows(doc, inner_width);
        if diagram.is_empty() {
            return;
        }
        rows.push(ActivityFeedPaneRow {
            text: String::new(),
            tone: ActivityFeedRowTone::Subtle,
        });
        rows.extend(diagram);
    }

    pub(crate) fn task_scroll_offset(&self, rows: usize, viewport_rows: usize) -> usize {
        activity_task_scroll_offset(self.session, rows, viewport_rows)
    }

    pub(crate) fn feed_scroll_offset(&self, rows: usize, viewport_rows: usize) -> usize {
        activity_feed_scroll_offset(self.session, rows, viewport_rows)
    }

    pub(crate) fn footer(&self, width: u16) -> ActivityFooterModel {
        activity_footer_model(self.session, width)
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

        assert_eq!(empty.title, "ACTIVITY");
        assert!(empty.body.contains("no run active"));
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
}
