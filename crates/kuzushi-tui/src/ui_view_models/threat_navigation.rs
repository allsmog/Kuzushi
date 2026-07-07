use crate::ThreatView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreatNavItem {
    pub(crate) label: &'static str,
    pub(crate) active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreatPanel {
    Stride,
    Stories,
    Scope,
    Summary,
}

pub(crate) fn threat_panel_model(view: ThreatView) -> ThreatPanel {
    match view {
        ThreatView::Stride => ThreatPanel::Stride,
        ThreatView::Stories => ThreatPanel::Stories,
        ThreatView::Scope => ThreatPanel::Scope,
        ThreatView::Summary => ThreatPanel::Summary,
    }
}

// The DFD tab moved into the Workbench command center's center pane; the
// remaining STRIDE / STORIES / SCOPE / SUMMARY tabs renumber from 1.
pub(crate) fn threat_nav_model(active: ThreatView) -> [ThreatNavItem; 4] {
    [
        nav_item(active, ThreatView::Stride, "1 STRIDE"),
        nav_item(active, ThreatView::Stories, "2 STORIES"),
        nav_item(active, ThreatView::Scope, "3 SCOPE"),
        nav_item(active, ThreatView::Summary, "4 SUMMARY"),
    ]
}

fn nav_item(active: ThreatView, view: ThreatView, label: &'static str) -> ThreatNavItem {
    ThreatNavItem {
        label,
        active: active == view,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_nav_model_marks_active_tab() {
        let items = threat_nav_model(ThreatView::Scope);

        assert_eq!(items.len(), 4);
        assert_eq!(items[2].label, "3 SCOPE");
        assert!(items[2].active);
        assert!(!items[0].active);
    }

    #[test]
    fn threat_panel_model_maps_shell_view_to_renderer_panel() {
        assert_eq!(threat_panel_model(ThreatView::Stride), ThreatPanel::Stride);
        assert_eq!(
            threat_panel_model(ThreatView::Summary),
            ThreatPanel::Summary
        );
    }
}
