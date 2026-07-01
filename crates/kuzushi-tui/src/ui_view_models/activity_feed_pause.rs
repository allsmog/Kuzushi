use crate::ActivitySession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFeedPauseModel {
    pub(crate) text: &'static str,
}

pub(crate) fn activity_feed_pause_model(
    session: &ActivitySession,
) -> Option<ActivityFeedPauseModel> {
    session.paused.then_some(ActivityFeedPauseModel {
        text: "⏸ feed paused — press p to resume",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_feed_pause_model_projects_pause_copy() {
        let mut session = ActivitySession::new("r-1");
        assert!(activity_feed_pause_model(&session).is_none());

        session.paused = true;
        assert_eq!(
            activity_feed_pause_model(&session),
            Some(ActivityFeedPauseModel {
                text: "⏸ feed paused — press p to resume",
            })
        );
    }
}
