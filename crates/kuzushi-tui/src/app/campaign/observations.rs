//! Explicitly open recorded observations without starting or approving work.
use super::*;

impl ShellApp {
    pub(super) fn open_selected_batch_observations(&mut self) -> InputUpdate {
        let Some(id) = self
            .router
            .campaign()
            .selected_campaign()
            .filter(|campaign| super::super::is_scan_batch_snapshot(campaign))
            .map(|campaign| campaign.campaign_id.clone())
        else {
            self.router.campaign_mut().notice =
                Some("Select a discovery batch to read its observations.".into());
            return InputUpdate::handled();
        };
        let job = self.router.campaign().selected_job;
        self.open_batch_results(&id);
        let ceiling = self.router.campaign().detail_job_ceiling();
        self.router.campaign_mut().selected_job = job.min(ceiling);
        if self.router.campaign().active_batch_report.is_some() {
            self.router.campaign_mut().notice = Some("Review uses this batch's retained observations. batch clear restores workspace history. Reading starts no work.".into());
        }
        InputUpdate::handled()
    }
}

#[cfg(test)]
mod tests;
