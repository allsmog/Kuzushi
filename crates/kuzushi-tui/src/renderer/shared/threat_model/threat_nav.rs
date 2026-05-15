use super::*;
use crate::ui_view_models::threat_nav_model;

pub(crate) fn threat_nav(active: ThreatView) -> Line<'static> {
    let mut spans = Vec::new();
    for (index, item) in threat_nav_model(active).iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ", theme::subtle()));
        }
        let style = if item.active {
            theme::selection()
        } else {
            theme::muted()
        };
        spans.push(Span::styled(item.label, style));
    }
    Line::from(spans)
}
