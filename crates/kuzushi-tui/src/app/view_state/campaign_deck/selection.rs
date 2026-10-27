use super::*;

impl CampaignRouteState {
    pub(crate) fn clear_campaign_history(&mut self) {
        self.campaigns.clear();
        self.history_coverage = None;
        self.reset_campaign_selection();
        self.trend = None;
        self.trend_history.clear();
        self.notice = None;
    }

    pub(crate) fn replace_campaigns(&mut self, campaigns: Vec<CampaignSnapshot>) -> Option<String> {
        let campaign_id = self.selected_campaign().map(|row| row.campaign_id.clone());
        let job_id = self.selected_job().map(|row| row.job_id.clone());
        self.campaigns = campaigns;
        let index = self
            .campaigns
            .iter()
            .position(|row| Some(&row.campaign_id) == campaign_id.as_ref());
        let notice = match index {
            Some(index) => {
                self.selected_campaign = index;
                self.restore_job_selection(job_id.as_deref())
            }
            None => {
                self.reset_campaign_selection();
                campaign_id.map(|id| format!("Previously selected campaign {id:?} is unavailable. Choose a campaign to inspect."))
            }
        };
        self.sync_selected_batch_workers();
        notice
    }

    fn restore_job_selection(&mut self, job_id: Option<&str>) -> Option<String> {
        let Some(job_id) = job_id else {
            self.selected_job = 0;
            return None;
        };
        let index = self
            .selected_campaign()?
            .jobs
            .iter()
            .position(|row| row.job_id == job_id);
        if let Some(index) = index {
            self.selected_job = index;
            return None;
        }
        self.selected_job = 0;
        self.job_detail = false;
        self.read_scroll = 0;
        Some(format!(
            "Previously selected job {job_id:?} is unavailable. Choose a job to inspect."
        ))
    }

    fn reset_campaign_selection(&mut self) {
        self.selected_campaign = self
            .selected_campaign
            .min(self.campaigns.len().saturating_sub(1));
        self.selected_job = 0;
        self.detail = false;
        self.job_detail = false;
        self.read_scroll = 0;
        self.excluded.clear();
    }
}
