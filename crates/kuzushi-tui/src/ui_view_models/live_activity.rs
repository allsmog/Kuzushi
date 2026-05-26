use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveActivityModel {
    pub(crate) phase_label: &'static str,
    pub(crate) subject: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainLiveActivityModel {
    pub(crate) title: &'static str,
    pub(crate) rows: Vec<String>,
}

pub(crate) fn live_activity_model(app: &ShellApp) -> Option<LiveActivityModel> {
    let activity = app.live_activity.as_ref()?;
    Some(LiveActivityModel {
        phase_label: activity.phase.label(),
        subject: activity.subject.clone(),
        detail: activity.detail.clone(),
    })
}

pub(crate) fn plain_live_activity_model(app: &ShellApp) -> Option<PlainLiveActivityModel> {
    live_activity_model(app).map(PlainLiveActivityModel::from_live_activity_model)
}

impl PlainLiveActivityModel {
    fn from_live_activity_model(model: LiveActivityModel) -> Self {
        PlainLiveActivityModel {
            title: "LIVE ACTIVITY",
            rows: vec![
                format!("phase: {}", model.phase_label),
                format!("subject: {}", model.subject),
                format!("detail: {}", model.detail),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::threat_model::threat_model_relative_path;
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

    #[test]
    fn plain_live_activity_model_projects_plain_lines() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let detail = format!("writes {}", threat_model_relative_path());
        app.live_activity = Some(LiveActivity::new(
            LiveActivityPhase::WritingArtifact,
            "threat-model:build",
            detail,
        ));

        let model = plain_live_activity_model(&app).expect("live activity model");
        let expected_detail = format!("detail: writes {}", threat_model_relative_path());

        assert_eq!(model.title, "LIVE ACTIVITY");
        assert_eq!(
            model.rows,
            vec![
                "phase: writing artifact".to_string(),
                "subject: threat-model:build".to_string(),
                expected_detail,
            ]
        );
    }
}
