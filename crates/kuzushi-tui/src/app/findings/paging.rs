//! Presentation navigation over the shared ledger page query.
use super::*;
use kuzushi_core::findings::{
    finding_page_continuity_anchor, FindingPageOrder, FindingPageRequest,
};

#[cfg(test)]
mod continuity_tests;
#[cfg(test)]
mod tests;

impl ShellApp {
    pub(crate) fn findings_page_request(&self, filter: Option<&str>) -> FindingPageRequest {
        if let Some(request) = &self.runtime_state.requested_findings_page {
            return request.clone();
        }
        let anchor = (filter == self.active_findings_filter().as_deref()
            && self.domain().findings_page().is_some())
        .then(|| {
            crate::ui_view_models::visible_finding_at_cursor(self)
                .map(|(_, finding)| finding_page_continuity_anchor(&finding))
        })
        .flatten();
        FindingPageRequest {
            cursor: None,
            anchor,
            order: FindingPageOrder::Confidence,
        }
    }

    pub(crate) fn move_findings_page(&mut self, next: bool) {
        let Some(page) = self.domain().findings_page() else {
            return;
        };
        let cursor = if next {
            &page.next_cursor
        } else {
            &page.previous_cursor
        };
        let Some(cursor) = cursor.clone() else {
            return;
        };
        self.router.findings_mut().clear_selection();
        self.runtime_state.requested_findings_page = Some(FindingPageRequest {
            cursor: Some(cursor),
            anchor: None,
            order: FindingPageOrder::Confidence,
        });
        EffectRuntime::execute(
            self,
            vec![ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: self.active_findings_filter().clone(),
            })],
        );
    }

    pub(crate) fn reset_findings_page_request(&mut self) {
        self.runtime_state.requested_findings_page = Some(FindingPageRequest {
            order: FindingPageOrder::Confidence,
            ..Default::default()
        });
    }
}
