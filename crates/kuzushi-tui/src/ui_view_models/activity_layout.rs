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

pub(crate) const ACTIVITY_WIDE_MIN_WIDTH: u16 = 78;
pub(crate) const ACTIVITY_STACKED_MIN_WIDTH: u16 = 50;
pub(crate) const ACTIVITY_COMPACT_MIN_HEIGHT: u16 = 14;

pub(crate) fn activity_frame_layout(header_rows: u16, footer_rows: u16) -> ActivityFrameLayout {
    ActivityFrameLayout {
        header_rows,
        footer_rows,
    }
}

/// One geometry policy shared by rendering and hit-testing. Wide terminals
/// stay side-by-side regardless of how tall they are; only genuinely compact
/// bodies collapse to a single focused viewport.
pub(crate) fn activity_pane_layout(
    width: u16,
    height: u16,
    task_content_rows: usize,
) -> ActivityPaneLayout {
    if width < ACTIVITY_STACKED_MIN_WIDTH || height < ACTIVITY_COMPACT_MIN_HEIGHT {
        return ActivityPaneLayout::Focused;
    }
    if width >= ACTIVITY_WIDE_MIN_WIDTH {
        // 36% (28–46) keeps real task ids like `carlini-threat-hunt:run`
        // readable; the old 32%/40-col cap truncated most two-word tools.
        let task_width = (width.saturating_mul(36) / 100).clamp(28, 46);
        return ActivityPaneLayout::SideBySide { task_width };
    }
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

    #[test]
    fn wide_layout_is_side_by_side_independent_of_tall_terminal() {
        assert_eq!(
            activity_pane_layout(96, 80, 4),
            ActivityPaneLayout::SideBySide { task_width: 34 }
        );
        assert_eq!(
            activity_pane_layout(78, 14, 40),
            ActivityPaneLayout::SideBySide { task_width: 28 }
        );
    }

    #[test]
    fn medium_layout_sizes_the_task_stack_from_content() {
        assert_eq!(
            activity_pane_layout(60, 20, 3),
            ActivityPaneLayout::Stacked { task_height: 5 }
        );
        assert_eq!(
            activity_pane_layout(60, 20, 40),
            ActivityPaneLayout::Stacked { task_height: 8 }
        );
    }

    #[test]
    fn narrow_or_short_layout_is_one_focused_viewport() {
        assert_eq!(activity_pane_layout(49, 30, 4), ActivityPaneLayout::Focused);
        assert_eq!(
            activity_pane_layout(120, 13, 4),
            ActivityPaneLayout::Focused
        );
    }
}
