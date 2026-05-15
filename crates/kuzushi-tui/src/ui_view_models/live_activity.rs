use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveActivityModel {
    pub(crate) phase_label: &'static str,
    pub(crate) subject: String,
    pub(crate) detail: String,
}

pub(crate) fn live_activity_model(app: &ShellApp) -> Option<LiveActivityModel> {
    let activity = app.live_activity.as_ref()?;
    Some(LiveActivityModel {
        phase_label: activity.phase.label(),
        subject: activity.subject.clone(),
        detail: activity.detail.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LiveActivity, LiveActivityPhase};
    use kuzushi_core::V2Config;

    #[test]
    fn live_activity_model_projects_display_fields() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.live_activity = Some(LiveActivity::new(
            LiveActivityPhase::Thinking,
            "triage:run",
            "reviewing finding evidence",
        ));

        let model = live_activity_model(&app).expect("live activity");

        assert_eq!(model.phase_label, "thinking");
        assert_eq!(model.subject, "triage:run");
        assert_eq!(model.detail, "reviewing finding evidence");
    }
}
