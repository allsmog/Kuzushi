use crate::{ActivitySession, PaneFocus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPaneChromeModel {
    pub(crate) dag: ActivityPaneTitle,
    pub(crate) feed: ActivityPaneTitle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPlainPaneHeaderModel {
    pub(crate) dag: ActivityPlainPaneHeaderCell,
    pub(crate) separator: &'static str,
    pub(crate) feed: ActivityPlainPaneHeaderCell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPlainPaneHeaderCell {
    pub(crate) text: String,
    pub(crate) focused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPaneTitle {
    pub(crate) block_title: String,
    pub(crate) plain_header: String,
    pub(crate) focused: bool,
}

pub(crate) fn activity_pane_chrome_model(session: &ActivitySession) -> ActivityPaneChromeModel {
    ActivityPaneChromeModel {
        dag: pane_title("DAG", session.pane_focus == PaneFocus::Left),
        feed: pane_title("FEED", session.pane_focus == PaneFocus::Right),
    }
}

pub(crate) fn activity_plain_pane_header_model(
    session: &ActivitySession,
    dag_width: usize,
    feed_width: usize,
) -> ActivityPlainPaneHeaderModel {
    let chrome = activity_pane_chrome_model(session);
    ActivityPlainPaneHeaderModel {
        dag: plain_header_cell(&chrome.dag, dag_width),
        separator: " │ ",
        feed: plain_header_cell(&chrome.feed, feed_width),
    }
}

fn pane_title(label: &'static str, focused: bool) -> ActivityPaneTitle {
    ActivityPaneTitle {
        block_title: format!("── {label} ──"),
        plain_header: format!(" ── {label} "),
        focused,
    }
}

fn plain_header_cell(title: &ActivityPaneTitle, width: usize) -> ActivityPlainPaneHeaderCell {
    ActivityPlainPaneHeaderCell {
        text: fit_or_pad(&title.plain_header, width),
        focused: title.focused,
    }
}

fn fit_or_pad(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len >= width {
        return value.chars().take(width).collect();
    }
    let mut out = value.to_string();
    out.push_str(&" ".repeat(width - len));
    out
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

    #[test]
    fn activity_pane_title_projects_renderer_copy() {
        assert_eq!(
            pane_title("DAG", true),
            ActivityPaneTitle {
                block_title: "── DAG ──".to_string(),
                plain_header: " ── DAG ".to_string(),
                focused: true,
            }
        );
    }

    #[test]
    fn activity_plain_pane_header_model_projects_padded_cells() {
        let mut session = ActivitySession::new("r-1");

        assert_eq!(
            activity_plain_pane_header_model(&session, 10, 12),
            ActivityPlainPaneHeaderModel {
                dag: ActivityPlainPaneHeaderCell {
                    text: " ── DAG   ".to_string(),
                    focused: true,
                },
                separator: " │ ",
                feed: ActivityPlainPaneHeaderCell {
                    text: " ── FEED    ".to_string(),
                    focused: false,
                },
            }
        );

        session.pane_focus = PaneFocus::Right;
        assert_eq!(
            activity_plain_pane_header_model(&session, 6, 6),
            ActivityPlainPaneHeaderModel {
                dag: ActivityPlainPaneHeaderCell {
                    text: " ── DA".to_string(),
                    focused: false,
                },
                separator: " │ ",
                feed: ActivityPlainPaneHeaderCell {
                    text: " ── FE".to_string(),
                    focused: true,
                },
            }
        );
    }
}
