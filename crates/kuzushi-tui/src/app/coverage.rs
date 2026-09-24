//! Coverage matrix deck behaviors: fold-on-open over campaign artifacts and
//! the loaded findings + cached review decisions. Read-only — the deck never
//! launches anything.

use super::*;
use kuzushi_core::capabilities::campaign::coverage::{
    coverage_findings_from_review_state, coverage_report,
};

impl ShellApp {
    pub(crate) fn open_coverage_view(&mut self) {
        self.refresh_coverage_deck();
        self.set_shell_view(ShellView::Coverage);
        self.log("coverage", "coverage matrix");
    }

    pub(crate) fn refresh_coverage_deck(&mut self) {
        let Some(target) = self.target_path_buf().cloned() else {
            let deck = self.router.coverage_mut();
            deck.report = None;
            deck.notice = Some("select a target to fold coverage".to_string());
            return;
        };
        let findings =
            coverage_findings_from_review_state(self.findings(), self.review_decisions());
        let deck = self.router.coverage_mut();
        match coverage_report(&target, &findings) {
            Ok(report) => {
                deck.report = Some(report);
                deck.notice = None;
            }
            Err(error) => {
                deck.report = None;
                deck.notice = Some(format!("coverage fold failed: {error:#}"));
            }
        }
    }
}