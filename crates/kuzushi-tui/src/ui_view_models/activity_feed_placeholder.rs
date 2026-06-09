use crate::ActivitySession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFeedPlaceholderModel {
    pub(crate) text: String,
}

pub(crate) fn activity_feed_placeholder_model(
    session: &ActivitySession,
) -> Option<ActivityFeedPlaceholderModel> {
    if session.paused || has_visible_feed_events(session) {
        return None;
    }
    Some(ActivityFeedPlaceholderModel {
        text: placeholder_text(
            hidden_subsystem_event_count(session),
            session.verbose_subsystems,
        ),
    })
}

fn has_visible_feed_events(session: &ActivitySession) -> bool {
    session
        .events
        .iter()
        .any(|event| event_is_visible(event.step.module_id.as_deref(), session.verbose_subsystems))
}

fn event_is_visible(module_id: Option<&str>, verbose_subsystems: bool) -> bool {
    if verbose_subsystems {
        return true;
    }
    !module_id
        .filter(|module_id| !module_id.is_empty())
        .map(crate::app::is_hidden_module_id)
        .unwrap_or(false)
}

fn hidden_subsystem_event_count(session: &ActivitySession) -> usize {
    session
        .events
        .iter()
        .filter(|event| hidden_event_module(event.step.module_id.as_deref()))
        .count()
}

fn hidden_event_module(module_id: Option<&str>) -> bool {
    module_id
        .map(crate::app::is_hidden_module_id)
        .unwrap_or(false)
}

fn placeholder_text(hidden_count: usize, verbose_subsystems: bool) -> String {
    if hidden_count == 0 || verbose_subsystems {
        return " (waiting for trace events…)".to_string();
    }
    format!(
        " ({hidden_count} hidden subsystem event{plural} — press V to show)",
        plural = plural_suffix(hidden_count)
    )
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::RunTraceStep;

    #[test]
    fn activity_feed_placeholder_model_waits_without_events() {
        let session = ActivitySession::new("r-1");

        assert_eq!(
            activity_feed_placeholder_model(&session).map(|model| model.text),
            Some(" (waiting for trace events…)".to_string())
        );
    }

    #[test]
    fn activity_feed_placeholder_model_counts_hidden_events() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(RunTraceStep::new(1, "reasoning", "index").with_module_id("pipeline"));
        session
            .apply_step(RunTraceStep::new(2, "reasoning", "slice").with_module_id("context-lite"));

        assert_eq!(
            activity_feed_placeholder_model(&session).map(|model| model.text),
            Some(" (2 hidden subsystem events — press V to show)".to_string())
        );
    }

    #[test]
    fn activity_feed_placeholder_model_skips_visible_or_paused_feed() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(RunTraceStep::new(1, "reasoning", "triage").with_module_id("triage"));
        assert!(activity_feed_placeholder_model(&session).is_none());

        session.events.clear();
        session.paused = true;
        assert!(activity_feed_placeholder_model(&session).is_none());
    }
}
