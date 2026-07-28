#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivityFrameLayout {
    pub(crate) header_rows: u16,
    pub(crate) footer_rows: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityPaneLayout {
    SideBySide { task_width: u16 },
    Stacked { task_height: u16 },
    Focused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivityPaneMetrics {
    pub(crate) task_content_rows: usize,
    pub(crate) task_content_width: usize,
    pub(crate) output_event_rows: usize,
}

pub(crate) const ACTIVITY_WIDE_MIN_WIDTH: u16 = 78;
pub(crate) const ACTIVITY_STACKED_MIN_WIDTH: u16 = 50;
pub(crate) const ACTIVITY_COMPACT_MIN_HEIGHT: u16 = 14;
const ACTIVITY_OUTPUT_MIN_WIDTH: u16 = 48;
const ACTIVITY_SPARSE_OUTPUT_MAX_ROWS: usize = 3;
const ACTIVITY_STACK_WIDTH_GAIN: u16 = 8;

pub(crate) fn activity_frame_layout(header_rows: u16, footer_rows: u16) -> ActivityFrameLayout {
    ActivityFrameLayout {
        header_rows,
        footer_rows,
    }
}

/// One measured-content geometry policy shared by rendering and hit-testing.
pub(crate) fn activity_pane_layout(
    width: u16,
    height: u16,
    metrics: ActivityPaneMetrics,
) -> ActivityPaneLayout {
    if width < ACTIVITY_STACKED_MIN_WIDTH || height < ACTIVITY_COMPACT_MIN_HEIGHT {
        return ActivityPaneLayout::Focused;
    }
    if width < ACTIVITY_WIDE_MIN_WIDTH || should_stack_wide(width, metrics) {
        return stacked_layout(height, metrics.task_content_rows);
    }
    ActivityPaneLayout::SideBySide {
        task_width: measured_task_width(width, metrics.task_content_width),
    }
}

fn should_stack_wide(width: u16, metrics: ActivityPaneMetrics) -> bool {
    let default_width = default_task_width(width);
    let preferred = u16::try_from(metrics.task_content_width).unwrap_or(u16::MAX);
    metrics.output_event_rows <= ACTIVITY_SPARSE_OUTPUT_MAX_ROWS
        && preferred > default_width.saturating_add(ACTIVITY_STACK_WIDTH_GAIN)
}

fn measured_task_width(width: u16, preferred: usize) -> u16 {
    let maximum = width.saturating_sub(ACTIVITY_OUTPUT_MIN_WIDTH).max(28);
    let preferred = u16::try_from(preferred).unwrap_or(u16::MAX);
    preferred.clamp(default_task_width(width), maximum)
}

fn default_task_width(width: u16) -> u16 {
    (width.saturating_mul(36) / 100).clamp(28, 46)
}

fn stacked_layout(height: u16, task_content_rows: usize) -> ActivityPaneLayout {
    let cap = (height.saturating_mul(40) / 100).max(3);
    let desired = u16::try_from(task_content_rows)
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    ActivityPaneLayout::Stacked {
        task_height: desired.clamp(3, cap),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(rows: usize, width: usize, output: usize) -> ActivityPaneMetrics {
        ActivityPaneMetrics {
            task_content_rows: rows,
            task_content_width: width,
            output_event_rows: output,
        }
    }

    #[test]
    fn wide_layout_is_side_by_side_when_both_panes_are_useful() {
        assert_eq!(
            activity_pane_layout(96, 80, metrics(4, 36, 8)),
            ActivityPaneLayout::SideBySide { task_width: 36 }
        );
        assert_eq!(
            activity_pane_layout(120, 36, metrics(4, 54, 8)),
            ActivityPaneLayout::SideBySide { task_width: 54 }
        );
    }

    #[test]
    fn wide_sparse_output_stacks_when_tasks_need_materially_more_width() {
        assert_eq!(
            activity_pane_layout(120, 36, metrics(4, 72, 1)),
            ActivityPaneLayout::Stacked { task_height: 6 }
        );
    }

    #[test]
    fn medium_layout_sizes_the_task_stack_from_content() {
        assert_eq!(
            activity_pane_layout(60, 20, metrics(3, 30, 8)),
            ActivityPaneLayout::Stacked { task_height: 5 }
        );
        assert_eq!(
            activity_pane_layout(60, 20, metrics(40, 30, 8)),
            ActivityPaneLayout::Stacked { task_height: 8 }
        );
    }

    #[test]
    fn narrow_or_short_layout_is_one_focused_viewport() {
        assert_eq!(
            activity_pane_layout(49, 30, metrics(4, 30, 8)),
            ActivityPaneLayout::Focused
        );
        assert_eq!(
            activity_pane_layout(120, 13, metrics(4, 30, 8)),
            ActivityPaneLayout::Focused
        );
    }
}
