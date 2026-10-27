//! Investigation state takes precedence over shell diagnostics in phase readers.
use super::*;

fn applies(app: &ShellApp) -> bool {
    match app.shell_view() {
        ShellView::Workbench => crate::app::WorkflowPhase::INVESTIGATION_ORDER
            .contains(&super::super::active_workbench_page(app).phase()),
        ShellView::Campaign => fixed_study_view(app),
        view => investigation_reader(view),
    }
}

fn investigation_reader(view: ShellView) -> bool {
    matches!(
        view,
        ShellView::Setup
            | ShellView::Report
            | ShellView::Scene
            | ShellView::Lessons
            | ShellView::Relationships
            | ShellView::RunDiff
            | ShellView::Replay
            | ShellView::Activity
    )
}

fn fixed_study_view(app: &ShellApp) -> bool {
    let deck = app.router.campaign();
    let drafting = [
        deck.batch_scan_config.as_ref(),
        deck.setup_context_study.as_ref(),
        deck.workflow_proposal_study.as_ref(),
    ]
    .iter()
    .any(Option::is_some);
    drafting
        || deck
            .selected_campaign()
            .is_some_and(crate::app::is_fixed_study_snapshot)
}

pub(super) fn full_segments(app: &ShellApp) -> Option<Vec<String>> {
    if !applies(app) {
        return None;
    }
    let mut segments = Vec::new();
    segments.extend(autonomy_footer_segment(app));
    segments.extend(freshness_attention(app));
    segments.extend(operational_segments(app));
    if let Some(activity) = status_footer_activity(app) {
        segments.push(activity.label);
        segments.push(model_footer_segment(app));
    }
    Some(segments)
}

pub(super) fn compact_segments(app: &ShellApp, has_allowance: bool) -> Option<Vec<String>> {
    if !applies(app) {
        return None;
    }
    let mut segments = compact_policy(app, has_allowance);
    segments.extend(operational_segments(app));
    segments.extend(status_footer_activity(app).map(|activity| activity.label));
    Some(segments)
}

fn compact_policy(app: &ShellApp, has_allowance: bool) -> Vec<String> {
    let policy = autonomy_footer_segment(app).map(|text| text.replace("autonomy:", ""));
    let Some(state) = compact_source_attention(app) else {
        return policy.into_iter().collect();
    };
    let mut policy = policy.unwrap_or_default();
    if !policy.contains('⚠') {
        policy.push_str(" ⚠");
    }
    policy.push(' ');
    policy.push_str(compact_source_label(state, has_allowance));
    vec![policy.trim().into()]
}

fn compact_source_label(state: &str, has_allowance: bool) -> &'static str {
    match (state, has_allowance) {
        ("stale", _) => "stale",
        (_, true) => "source",
        _ => "source unchecked",
    }
}

fn freshness_attention(app: &ShellApp) -> Option<String> {
    if let Some(stale) = app.workspace_stale() {
        return Some(format!(
            "Workspace changed ({})",
            stale.chip().trim_start_matches("workspace:stale ")
        ));
    }
    app.domain()
        .returning_source_unverified()
        .then(|| "Source unchecked".into())
}

fn operational_segments(app: &ShellApp) -> impl Iterator<Item = String> {
    [
        reader_orientation(app),
        review_conflict_footer_segment(app),
        attention_footer_segment(app),
        scope_footer_segment(app),
        project_scope_footer_segment(app),
    ]
    .into_iter()
    .flatten()
}

fn reader_orientation(app: &ShellApp) -> Option<String> {
    match app.shell_view() {
        ShellView::Setup => Some("Setup".into()),
        ShellView::Workbench | ShellView::Report => None,
        _ => journey_footer_segment(app),
    }
}

#[cfg(test)]
mod tests;
