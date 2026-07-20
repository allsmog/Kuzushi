//! Coverage matrix deck behaviors: fold-on-open over campaign artifacts and
//! the loaded findings + cached review decisions. Read-only — the deck never
//! launches anything.

use super::*;
use kuzushi_core::capabilities::campaign::coverage::{
    confirmed_finding_ids_from_decisions, coverage_finding, coverage_report,
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
        let confirmed = confirmed_finding_ids_from_decisions(self.review_decisions());
        let findings = self
            .findings()
            .iter()
            .map(|finding| coverage_finding(finding, &confirmed))
            .collect::<Vec<_>>();
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
