use crate::ActivityRouteState;

pub(crate) fn activity_task_scroll_offset(
    route: &ActivityRouteState,
    line_count: usize,
    viewport_height: usize,
) -> usize {
    clamp_scroll(route.task_scroll, line_count, viewport_height)
}

pub(crate) fn activity_feed_scroll_offset(
    route: &ActivityRouteState,
    line_count: usize,
    viewport_height: usize,
) -> usize {
    if route.feed_auto_tail {
        return line_count.saturating_sub(viewport_height);
    }
    clamp_scroll(route.feed_scroll, line_count, viewport_height)
}

fn clamp_scroll(requested: usize, line_count: usize, viewport_height: usize) -> usize {
    if line_count <= viewport_height {
        return 0;
    }
    requested.min(line_count.saturating_sub(viewport_height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_task_scroll_offset_clamps_to_visible_range() {
        let mut route = ActivityRouteState::default();
        route.task_scroll = 99;

        assert_eq!(activity_task_scroll_offset(&route, 10, 4), 6);
        assert_eq!(activity_task_scroll_offset(&route, 3, 4), 0);
    }

    #[test]
    fn activity_feed_scroll_offset_tails_when_enabled() {
        let mut route = ActivityRouteState::default();
        route.feed_scroll = 1;
        route.feed_auto_tail = true;

        assert_eq!(activity_feed_scroll_offset(&route, 20, 7), 13);
    }

    #[test]
    fn activity_feed_scroll_offset_respects_manual_scroll() {
        let mut route = ActivityRouteState::default();
        route.feed_scroll = 3;
        route.feed_auto_tail = false;

        assert_eq!(activity_feed_scroll_offset(&route, 20, 7), 3);
        route.feed_scroll = 99;
        assert_eq!(activity_feed_scroll_offset(&route, 20, 7), 13);
    }
}
