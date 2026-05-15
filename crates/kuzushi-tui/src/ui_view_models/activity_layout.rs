#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivityFrameLayout {
    pub(crate) header_rows: u16,
    pub(crate) footer_rows: u16,
    pub(crate) dag_percent: u16,
    pub(crate) feed_percent: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivityPaneWidths {
    pub(crate) dag: usize,
    pub(crate) feed: usize,
}

pub(crate) fn activity_frame_layout() -> ActivityFrameLayout {
    ActivityFrameLayout {
        header_rows: 2,
        footer_rows: 2,
        dag_percent: 46,
        feed_percent: 54,
    }
}

pub(crate) fn activity_plain_pane_widths(width: u16) -> ActivityPaneWidths {
    let usable = (width as usize).saturating_sub(1);
    let dag = (usable * activity_frame_layout().dag_percent as usize / 100).max(20);
    ActivityPaneWidths {
        dag,
        feed: usable.saturating_sub(dag).max(20),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_frame_layout_projects_split_geometry() {
        assert_eq!(
            activity_frame_layout(),
            ActivityFrameLayout {
                header_rows: 2,
                footer_rows: 2,
                dag_percent: 46,
                feed_percent: 54,
            }
        );
    }

    #[test]
    fn activity_plain_pane_widths_matches_split_with_minimums() {
        assert_eq!(
            activity_plain_pane_widths(120),
            ActivityPaneWidths { dag: 54, feed: 65 }
        );
        assert_eq!(
            activity_plain_pane_widths(30),
            ActivityPaneWidths { dag: 20, feed: 20 }
        );
    }
}
