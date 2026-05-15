use crate::ActivitySession;

pub(crate) fn activity_task_scroll_offset(
    session: &ActivitySession,
    line_count: usize,
    viewport_height: usize,
) -> usize {
    clamp_scroll(session.task_scroll, line_count, viewport_height)
}

pub(crate) fn activity_feed_scroll_offset(
    session: &ActivitySession,
    line_count: usize,
    viewport_height: usize,
) -> usize {
    if session.feed_auto_tail {
        return line_count.saturating_sub(viewport_height);
    }
    clamp_scroll(session.feed_scroll, line_count, viewport_height)
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
        let mut session = ActivitySession::new("r-1");
        session.task_scroll = 99;

        assert_eq!(activity_task_scroll_offset(&session, 10, 4), 6);
        assert_eq!(activity_task_scroll_offset(&session, 3, 4), 0);
    }

    #[test]
    fn activity_feed_scroll_offset_tails_when_enabled() {
        let mut session = ActivitySession::new("r-1");
        session.feed_scroll = 1;
        session.feed_auto_tail = true;

        assert_eq!(activity_feed_scroll_offset(&session, 20, 7), 13);
    }

    #[test]
    fn activity_feed_scroll_offset_respects_manual_scroll() {
        let mut session = ActivitySession::new("r-1");
        session.feed_scroll = 3;
        session.feed_auto_tail = false;

        assert_eq!(activity_feed_scroll_offset(&session, 20, 7), 3);
        session.feed_scroll = 99;
        assert_eq!(activity_feed_scroll_offset(&session, 20, 7), 13);
    }
}
