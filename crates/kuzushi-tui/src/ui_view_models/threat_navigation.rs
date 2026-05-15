use crate::ThreatView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreatNavItem {
    pub(crate) label: &'static str,
    pub(crate) active: bool,
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
}
