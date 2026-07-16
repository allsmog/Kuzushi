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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainRunProjectionModel {
    pub(crate) title: &'static str,
    pub(crate) rows: Vec<PlainRunProjectionRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainRunProjectionRow {
    pub(crate) key: Option<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) text: String,
}

pub(crate) fn live_activity_model(app: &ShellApp) -> Option<LiveActivityModel> {
    let activity = app.live_activity()?;
    Some(LiveActivityModel {
        phase_label: activity.phase.label(),
        subject: activity.subject.clone(),
        detail: activity.detail.clone(),
    })
}

pub(crate) fn plain_live_activity_model(app: &ShellApp) -> Option<PlainLiveActivityModel> {
    live_activity_model(app).map(PlainLiveActivityModel::from_live_activity_model)
}

pub(crate) fn plain_run_projection_model(app: &ShellApp) -> Option<PlainRunProjectionModel> {
    let session = app.activity()?;
    (!session.run_projection.timeline.is_empty()).then(|| PlainRunProjectionModel {
        title: "RUN",
        rows: plain_projection_rows(session),
    })
}

fn plain_projection_rows(session: &crate::ActivitySession) -> Vec<PlainRunProjectionRow> {
    let presentation = kuzushi_core::run_lifecycle::present_projection_with_hydration_and_health(
        &session.run_projection,
        kuzushi_core::run_lifecycle::RunProjectionSource::TypedV1,
        &session.run_presentation_hydration,
        session.effective_run_lifecycle_health(),
    );
    let mut rows = presentation
        .overview_lines()
        .into_iter()
        .map(unkeyed_row)
        .collect::<Vec<_>>();
    append_plain_summary_rows(&mut rows, &presentation);
    append_plain_timeline_rows(&mut rows, &presentation);
    rows
}

fn append_plain_summary_rows(
    rows: &mut Vec<PlainRunProjectionRow>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) {
    let mut active_section = None;
    for row in presentation.summary_text_rows() {
        if row.section != active_section {
            if let Some(section) = row.section.as_ref() {
                rows.push(unkeyed_row(section.label().to_string()));
            }
            active_section = row.section.clone();
        }
        rows.push(keyed_row(row));
    }
}

fn append_plain_timeline_rows(
    rows: &mut Vec<PlainRunProjectionRow>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) {
    let timeline = presentation.timeline_text_rows();
    if timeline.is_empty() {
        return;
    }
    rows.push(unkeyed_row("TIMELINE".to_string()));
    rows.extend(timeline.into_iter().map(keyed_row));
}

fn keyed_row(row: kuzushi_core::run_lifecycle::RunPresentationTextRowV1) -> PlainRunProjectionRow {
    PlainRunProjectionRow {
        key: Some(row.key),
        text: row.text,
    }
}

fn unkeyed_row(text: String) -> PlainRunProjectionRow {
    PlainRunProjectionRow { key: None, text }
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
        app.set_live_activity_state(Some(LiveActivity::new(
            LiveActivityPhase::Thinking,
            "triage:run",
            "reviewing finding evidence",
        )));

        let model = live_activity_model(&app).expect("live activity");

        assert_eq!(model.phase_label, "thinking");
        assert_eq!(model.subject, "triage:run");
        assert_eq!(model.detail, "reviewing finding evidence");
    }

    #[test]
    fn plain_live_activity_model_projects_plain_lines() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let detail = format!("writes {}", threat_model_relative_path());
        app.set_live_activity_state(Some(LiveActivity::new(
            LiveActivityPhase::WritingArtifact,
            "threat-model:build",
            detail,
        )));

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
