use super::*;
use crate::ui_view_models::{threat_panel_model, ThreatPanel};

mod scope;
mod stories;
mod stride;
mod summary;

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
    }

    lines
}
