use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveActivityModel {
    pub(crate) phase_label: &'static str,
    pub(crate) subject: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainLiveActivityRow {
    pub(crate) label: &'static str,
    pub(crate) value: String,
}

pub(crate) fn live_activity_model(app: &ShellApp) -> Option<LiveActivityModel> {
    let activity = app.live_activity.as_ref()?;
    Some(LiveActivityModel {
        phase_label: activity.phase.label(),
        subject: activity.subject.clone(),
        detail: activity.detail.clone(),
    })
}

pub(crate) fn plain_live_activity_rows(app: &ShellApp) -> Option<Vec<PlainLiveActivityRow>> {
    live_activity_model(app).map(|model| {
        vec![
            PlainLiveActivityRow {
                label: "phase",
                value: model.phase_label.to_string(),
            },
            PlainLiveActivityRow {
                label: "subject",
                value: model.subject,
            },
            PlainLiveActivityRow {
                label: "detail",
                value: model.detail,
            },
        ]
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

    #[test]
    fn plain_live_activity_rows_project_labelled_plain_rows() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.live_activity = Some(LiveActivity::new(
            LiveActivityPhase::WritingArtifact,
            "threat-model:build",
            "writes .kuzushi/threat-model.json",
        ));

        let rows = plain_live_activity_rows(&app).expect("live activity rows");

        assert_eq!(
            rows,
            vec![
                PlainLiveActivityRow {
                    label: "phase",
                    value: "writing artifact".to_string(),
                },
                PlainLiveActivityRow {
                    label: "subject",
                    value: "threat-model:build".to_string(),
                },
                PlainLiveActivityRow {
                    label: "detail",
                    value: "writes .kuzushi/threat-model.json".to_string(),
                },
            ]
        );
    }
}
