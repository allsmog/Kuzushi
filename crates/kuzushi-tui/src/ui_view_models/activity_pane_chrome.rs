use crate::{ActivityRouteState, ActivitySession, PaneFocus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPaneChromeModel {
    pub(crate) dag: ActivityPaneTitle,
    pub(crate) feed: ActivityPaneTitle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPaneTitle {
    pub(crate) block_title: String,
    pub(crate) focused: bool,
}

pub(crate) fn activity_pane_chrome_model(
    session: &ActivitySession,
    route: &ActivityRouteState,
) -> ActivityPaneChromeModel {
    // "TASKS" / "OUTPUT" read for operators; "DAG"/"FEED" were dev jargon.
    ActivityPaneChromeModel {
        dag: pane_title(
            "TASKS",
            route.effective_pane_focus(session) == PaneFocus::Left,
        ),
        feed: pane_title(
            "OUTPUT",
            route.effective_pane_focus(session) == PaneFocus::Right,
        ),
    }
}

fn pane_title(label: &'static str, focused: bool) -> ActivityPaneTitle {
    ActivityPaneTitle {
        block_title: format!("── {label} ──"),
        focused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests exercise the stored-focus projection, which only applies
    /// while the TASKS pane is on screen — i.e. when DAG tasks exist
    /// (taskless sessions collapse to OUTPUT-only and force Right focus).
    fn seed_task(session: &mut ActivitySession) {
        session.tasks.insert(
            "context:build".to_string(),
            crate::DagTaskRow::queued(
                "context:build".to_string(),
                "context".to_string(),
                Vec::new(),
            ),
        );
    }

    #[test]
    fn activity_pane_chrome_model_projects_focus() {
        let mut session = ActivitySession::new("r-1");
        let mut route = ActivityRouteState::default();
        seed_task(&mut session);
        assert_eq!(
            activity_pane_chrome_model(&session, &route),
            ActivityPaneChromeModel {
                dag: pane_title("TASKS", true),
                feed: pane_title("OUTPUT", false),
            }
        );

        route.pane_focus = PaneFocus::Right;
        assert_eq!(
            activity_pane_chrome_model(&session, &route),
            ActivityPaneChromeModel {
                dag: pane_title("TASKS", false),
                feed: pane_title("OUTPUT", true),
            }
        );
    }

    #[test]
    fn activity_pane_title_projects_renderer_copy() {
        assert_eq!(
            pane_title("TASKS", true),
            ActivityPaneTitle {
                block_title: "── TASKS ──".to_string(),
                focused: true,
            }
        );
    }
}
