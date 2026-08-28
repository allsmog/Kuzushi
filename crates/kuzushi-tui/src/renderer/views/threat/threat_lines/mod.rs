use super::*;
use crate::ui_view_models::{threat_panel_model, ThreatPanel};

mod models;
mod scope;
mod stories;
mod stride;
mod summary;
mod versions;

/// One muted guidance line for a panel whose backing artifact does not exist.
fn empty_hint_line(hint: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("   "),
        Span::styled(hint.to_string(), theme::muted()),
    ])
}

pub(crate) fn threat_lines(app: &ShellApp, area: Rect, view: ThreatView) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(threat_nav(view));
    lines.push(blank());

    match threat_panel_model(view) {
        ThreatPanel::Stride => stride::append_stride_lines(app, area, &mut lines),
        ThreatPanel::Stories => stories::append_story_lines(app, area, &mut lines),
        ThreatPanel::Scope => scope::append_scope_lines(app, area, &mut lines),
        ThreatPanel::Summary => summary::append_summary_lines(app, area, &mut lines),
        ThreatPanel::Models => models::append_model_lines(app, area, &mut lines),
        ThreatPanel::Versions => versions::append_version_lines(app, area, &mut lines),
    }

    lines
}
