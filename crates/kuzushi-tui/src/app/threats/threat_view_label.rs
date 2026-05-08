use super::prelude::*;
use super::*;

pub(crate) fn threat_view_label(view: ThreatView) -> &'static str {
    match view {
        ThreatView::Dfd => "dfd",
        ThreatView::Stride => "stride",
        ThreatView::Stories => "stories",
        ThreatView::Scope => "scope",
        ThreatView::Summary => "summary",
    }
}
