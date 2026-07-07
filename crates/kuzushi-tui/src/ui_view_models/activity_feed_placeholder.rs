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
    if route.paused || has_visible_feed_events(session, route) {
        return None;
    }
    Some(ActivityFeedPlaceholderModel {
        text: placeholder_text(
            hidden_subsystem_event_count(session),
            route.verbose_subsystems,
            running_tool,
        ),
    })
}

fn has_visible_feed_events(session: &ActivitySession, route: &ActivityRouteState) -> bool {
    session
        .events
        .iter()
        .any(|event| event_is_visible(event.step.module_id.as_deref(), route.verbose_subsystems))
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

fn placeholder_text(
    hidden_count: usize,
    verbose_subsystems: bool,
    running_tool: Option<&str>,
) -> String {
    if hidden_count > 0 && !verbose_subsystems {
        return format!(
            " ({hidden_count} hidden subsystem event{plural} — press V to show)",
            plural = plural_suffix(hidden_count)
        );
    }
    // An anonymous "(waiting…)" leaves the operator unsure anything is
    // happening — name the tool when one is live, and be honest when the
    // run simply produced no events.
    match running_tool {
        Some(tool) => format!(" ({tool} is working — waiting for its first trace event…)"),
        None => " (no trace events recorded for this run)".to_string(),
    }
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
        let route = ActivityRouteState::default();

        assert_eq!(
            activity_feed_placeholder_model(&session, &route, Some("threat-model:build"))
                .map(|m| m.text),
            Some(
                " (threat-model:build is working — waiting for its first trace event…)".to_string()
            )
        );
        assert_eq!(
            activity_feed_placeholder_model(&session, &route, None).map(|m| m.text),
            Some(" (no trace events recorded for this run)".to_string())
        );
    }

    #[test]
    fn activity_feed_placeholder_model_counts_hidden_events() {
        let mut session = ActivitySession::new("r-1");
        let route = ActivityRouteState::default();
        session.apply_step(RunTraceStep::new(1, "reasoning", "index").with_module_id("pipeline"));
        session
            .apply_step(RunTraceStep::new(2, "reasoning", "slice").with_module_id("context-lite"));

        assert_eq!(
            activity_feed_placeholder_model(&session, &route, None).map(|model| model.text),
            Some(" (2 hidden subsystem events — press V to show)".to_string())
        );
    }

    #[test]
    fn activity_feed_placeholder_model_skips_visible_or_paused_feed() {
        let mut session = ActivitySession::new("r-1");
        let mut route = ActivityRouteState::default();
        session.apply_step(RunTraceStep::new(1, "reasoning", "triage").with_module_id("triage"));
        assert!(activity_feed_placeholder_model(&session, &route, None).is_none());

        session.events.clear();
        route.paused = true;
        assert!(activity_feed_placeholder_model(&session, &route, None).is_none());
    }
}
