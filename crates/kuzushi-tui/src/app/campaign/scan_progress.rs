use super::*;
use crate::app::ViewHydrationKey;

impl ShellApp {
    pub(crate) fn scan_study_navigation_active(&self) -> bool {
        self.shell_view() == ShellView::Campaign
            && self.router.campaign().batch_scan_config.is_none()
            && self
                .router
                .campaign()
                .scan_study_origin
                .as_ref()
                .is_some_and(|origin| origin.belongs_to_target(self.target()))
    }

    pub(crate) fn open_current_scan_study(&mut self) {
        let Some(ViewHydrationKey::ScanStudyProgress { campaign_id }) =
            self.scan_study_progress_key()
        else {
            return;
        };
        let Some(target) = self.target_owned() else {
            return;
        };
        let query = self.active_findings_filter().clone().unwrap_or_default();
        let origin = self.capture_linked_findings_origin(target, query);
        self.open_campaign_view(Some(campaign_id));
        self.router.campaign_mut().scan_study_origin = Some(origin);
        self.set_input_mode(crate::InputMode::Navigate);
    }

    pub(crate) fn restore_scan_study_origin(&mut self) -> bool {
        if self.shell_view() != ShellView::Campaign
            || self.router.campaign().job_detail
            || self.router.campaign().batch_scan_config.is_some()
        {
            return false;
        }
        let Some(origin) = self.router.campaign_mut().scan_study_origin.take() else {
            return false;
        };
        if !origin.belongs_to_target(self.target()) {
            return false;
        }
        self.restore_linked_findings_origin(origin);
        true
    }
}
