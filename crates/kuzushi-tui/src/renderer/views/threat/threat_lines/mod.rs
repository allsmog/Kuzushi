use super::*;

mod dfd;
mod scope;
mod stories;
mod stride;
mod summary;

pub(crate) fn threat_lines(app: &ShellApp, area: Rect, view: ThreatView) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(threat_nav(view));
    lines.push(blank());

    match view {
        ThreatView::Dfd => dfd::append_dfd_lines(app, area, &mut lines),
        ThreatView::Stride => stride::append_stride_lines(app, area, &mut lines),
        ThreatView::Stories => stories::append_story_lines(app, area, &mut lines),
        ThreatView::Scope => scope::append_scope_lines(app, area, &mut lines),
        ThreatView::Summary => summary::append_summary_lines(app, area, &mut lines),
    }

    lines
}
