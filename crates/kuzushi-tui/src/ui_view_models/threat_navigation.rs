use crate::ThreatView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreatNavItem {
    pub(crate) label: &'static str,
    pub(crate) active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreatPanel {
    Dfd,
    Stride,
    Stories,
    Scope,
    Summary,
}

pub(crate) fn threat_panel_model(view: ThreatView) -> ThreatPanel {
    match view {
        ThreatView::Dfd => ThreatPanel::Dfd,
        ThreatView::Stride => ThreatPanel::Stride,
        ThreatView::Stories => ThreatPanel::Stories,
        ThreatView::Scope => ThreatPanel::Scope,
        ThreatView::Summary => ThreatPanel::Summary,
    }
}

pub(crate) fn threat_nav_model(active: ThreatView) -> [ThreatNavItem; 5] {
    [
        nav_item(active, ThreatView::Dfd, "1 DFD"),
        nav_item(active, ThreatView::Stride, "2 STRIDE"),
        nav_item(active, ThreatView::Stories, "3 STORIES"),
        nav_item(active, ThreatView::Scope, "4 SCOPE"),
        nav_item(active, ThreatView::Summary, "5 SUMMARY"),
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

        assert_eq!(items.len(), 5);
        assert_eq!(items[3].label, "4 SCOPE");
        assert!(items[3].active);
        assert!(!items[0].active);
    }

    #[test]
    fn threat_panel_model_maps_shell_view_to_renderer_panel() {
        assert_eq!(threat_panel_model(ThreatView::Dfd), ThreatPanel::Dfd);
        assert_eq!(
            threat_panel_model(ThreatView::Summary),
            ThreatPanel::Summary
        );
    }
}
