use crate::ActivityRouteState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFeedPauseModel {
    pub(crate) text: &'static str,
}

pub(crate) fn activity_feed_pause_model(
    route: &ActivityRouteState,
) -> Option<ActivityFeedPauseModel> {
    route.paused.then_some(ActivityFeedPauseModel {
        text: "⏸ feed paused — press Space to resume",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_feed_pause_model_projects_pause_copy() {
        let mut route = ActivityRouteState::default();
        assert!(activity_feed_pause_model(&route).is_none());

        route.paused = true;
        assert_eq!(
            activity_feed_pause_model(&route),
            Some(ActivityFeedPauseModel {
                text: "⏸ feed paused — press Space to resume",
            })
        );
    }
}
