#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivityFrameLayout {
    pub(crate) header_rows: u16,
    pub(crate) footer_rows: u16,
    pub(crate) wide_dag_width: u16,
    pub(crate) compact_breakpoint: u16,
    pub(crate) compact_dag_percent: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivityPaneWidths {
    pub(crate) dag: usize,
    pub(crate) feed: usize,
}

pub(crate) fn activity_frame_layout() -> ActivityFrameLayout {
    ActivityFrameLayout {
        // title + context (model/findings/target)
        header_rows: 2,
        footer_rows: 2,
        // Keep TASKS dense on wide terminals; OUTPUT gets the remaining width.
        wide_dag_width: 44,
        compact_breakpoint: 110,
        compact_dag_percent: 40,
    }
}

pub(crate) fn activity_plain_pane_widths(width: u16) -> ActivityPaneWidths {
    let usable = (width as usize).saturating_sub(3);
    let layout = activity_frame_layout();
    let dag = if width >= layout.compact_breakpoint {
        layout.wide_dag_width as usize
    } else {
        (usable * layout.compact_dag_percent as usize / 100).max(20)
    };
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
                wide_dag_width: 44,
                compact_breakpoint: 110,
                compact_dag_percent: 40,
            }
        );
    }

    #[test]
    fn activity_plain_pane_widths_matches_split_with_minimums() {
        assert_eq!(
            activity_plain_pane_widths(120),
            ActivityPaneWidths { dag: 44, feed: 73 }
        );
        assert_eq!(
            activity_plain_pane_widths(30),
            ActivityPaneWidths { dag: 20, feed: 20 }
        );
    }
}
