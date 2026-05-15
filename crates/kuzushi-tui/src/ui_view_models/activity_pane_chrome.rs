use crate::{ActivitySession, PaneFocus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPaneChromeModel {
    pub(crate) dag: ActivityPaneTitle,
    pub(crate) feed: ActivityPaneTitle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPaneTitle {
    pub(crate) label: &'static str,
    pub(crate) focused: bool,
}

pub(crate) fn activity_pane_chrome_model(session: &ActivitySession) -> ActivityPaneChromeModel {
    ActivityPaneChromeModel {
        dag: pane_title("DAG", session.pane_focus == PaneFocus::Left),
        feed: pane_title("FEED", session.pane_focus == PaneFocus::Right),
    }
}

fn pane_title(label: &'static str, focused: bool) -> ActivityPaneTitle {
    ActivityPaneTitle { label, focused }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_pane_chrome_model_projects_focus() {
        let mut session = ActivitySession::new("r-1");
        assert_eq!(
            activity_pane_chrome_model(&session),
            ActivityPaneChromeModel {
                dag: pane_title("DAG", true),
                feed: pane_title("FEED", false),
            }
        );

        session.pane_focus = PaneFocus::Right;
        assert_eq!(
            activity_pane_chrome_model(&session),
            ActivityPaneChromeModel {
                dag: pane_title("DAG", false),
                feed: pane_title("FEED", true),
            }
        );
    }
}
