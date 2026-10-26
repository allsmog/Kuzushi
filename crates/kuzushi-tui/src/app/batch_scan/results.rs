use crate::app::ShellApp;
use kuzushi_core::findings::derive_batch_occurrence_report;

type BatchReviewScope = (
    kuzushi_core::findings::BatchOccurrenceReport,
    std::collections::BTreeSet<String>,
);

impl ShellApp {
    pub(crate) fn open_batch_results(&mut self, batch_id: &str) {
        self.open_campaign_view(Some(batch_id.to_string()));
        let is_batch = self
            .router
            .campaign()
            .selected_campaign()
            .is_some_and(super::is_scan_batch_snapshot);
        if !is_batch {
            self.router.campaign_mut().notice =
                Some(format!("campaign {batch_id:?} is not a scan batch"));
            return;
        }
        let deck = self.router.campaign_mut();
        deck.detail = true;
        deck.active_batch_id = Some(batch_id.to_string());
        deck.active_batch_report = None;
        deck.active_batch_observation_fingerprints.clear();
        self.refresh_active_batch_report();
        self.reset_findings_page_request();
        self.refresh_findings_preserving_active_filter(false);
    }

    pub(crate) fn clear_batch_scope(&mut self) {
        self.router.campaign_mut().clear_active_batch();
        self.reset_findings_page_request();
        self.refresh_findings_preserving_active_filter(false);
        self.log(
            "batch",
            "Study Review scope cleared. Existing filters remain.",
        );
    }

    pub(crate) fn refresh_active_batch_report(&mut self) {
        let Some((target, batch_id)) = self
            .target_owned()
            .zip(self.router.campaign().active_batch_id.clone())
        else {
            return;
        };
        let report = self.open_store().and_then(|store| {
            let report = derive_batch_occurrence_report(&target, &batch_id, &store)?;
            let fingerprints = report.retained_observation_fingerprints(&target, &store)?;
            Ok((report, fingerprints))
        });
        self.apply_batch_report(batch_id, report);
    }

    fn apply_batch_report(&mut self, batch_id: String, report: anyhow::Result<BatchReviewScope>) {
        match report {
            Ok((report, fingerprints)) => {
                let deck = self.router.campaign_mut();
                deck.active_batch_report = Some(report);
                deck.active_batch_observation_fingerprints = fingerprints;
            }
            Err(error) => {
                let deck = self.router.campaign_mut();
                deck.active_batch_report = None;
                deck.active_batch_observation_fingerprints.clear();
                deck.notice = Some(format!("batch {batch_id} report unavailable: {error:#}"));
            }
        }
    }
}
