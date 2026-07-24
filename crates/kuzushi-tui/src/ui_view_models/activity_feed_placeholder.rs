use crate::{ActivityRouteState, ActivitySession};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFeedPlaceholderModel {
    pub(crate) text: String,
}

pub(crate) fn activity_feed_placeholder_model(
    session: &ActivitySession,
    route: &ActivityRouteState,
    running_tool: Option<&str>,
) -> Option<ActivityFeedPlaceholderModel> {
    if route.paused || session.event_count() > 0 {
        return None;
    }
    Some(ActivityFeedPlaceholderModel {
        text: placeholder_text(running_tool),
    })
}

fn placeholder_text(running_tool: Option<&str>) -> String {
    match running_tool {
        Some(tool) => format!(" ({tool} is running — waiting for its first lifecycle event…)"),
        None => " (no lifecycle events recorded for this run)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_feed_placeholder_model_waits_without_events() {
        let session = ActivitySession::new("r-1");
        let route = ActivityRouteState::default();

        assert_eq!(
            activity_feed_placeholder_model(&session, &route, Some("threat-model:build"))
                .map(|m| m.text),
            Some(
                " (threat-model:build is running — waiting for its first lifecycle event…)"
                    .to_string()
            )
        );
        assert_eq!(
            activity_feed_placeholder_model(&session, &route, None).map(|m| m.text),
            Some(" (no lifecycle events recorded for this run)".to_string())
        );
    }

    #[test]
    fn activity_feed_placeholder_model_skips_visible_or_paused_feed() {
        let session = ActivitySession::new("r-1");
        let mut route = ActivityRouteState::default();
        route.paused = true;
        assert!(activity_feed_placeholder_model(&session, &route, None).is_none());
    }
}
