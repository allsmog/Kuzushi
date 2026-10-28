use super::*;
use crate::app::ViewHydrationKey;

impl ShellApp {
    pub(crate) fn scan_study_jobs_key(&self) -> char {
        let policy = self
            .phase_result_target_phase()
            .and_then(|phase| self.projected_phase_result_policy(phase));
        let actions = policy
            .as_ref()
            .map(|policy| policy.actions.as_slice())
            .unwrap_or(&[]);
        study_jobs_key(actions)
    }

    pub(crate) fn study_navigation_return_active(&self) -> bool {
        self.scan_study_navigation_active() || self.dfd_study_jobs_navigation_active()
    }

    pub(crate) fn restore_campaign_reader_origin(&mut self) -> bool {
        self.restore_scan_study_origin() || self.restore_dfd_study_jobs_origin()
    }

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
        self.open_campaign_view(Some(campaign_id.clone()));
        self.router.campaign_mut().scan_study_origin = Some(origin);
        self.set_input_mode(crate::InputMode::Navigate);
        self.reveal_scan_study_job(&campaign_id);
    }

    pub(super) fn reveal_scan_study_job(&mut self, campaign_id: &str) {
        if !self.scan_study_navigation_active() || self.input_mode() != crate::InputMode::Navigate {
            return;
        }
        let offset = self
            .router
            .campaign()
            .selected_campaign()
            .filter(|campaign| campaign.campaign_id == campaign_id)
            .and_then(|_| crate::renderer::campaign_selection_scroll(self));
        if let Some(offset) = offset {
            self.router.campaign_mut().read_scroll = offset;
        }
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

fn study_jobs_key(actions: &[kuzushi_core::workflow_attempts::PhaseResultAction]) -> char {
    if actions.contains(&kuzushi_core::workflow_attempts::PhaseResultAction::ContinueRun) {
        'C'
    } else {
        'c'
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::workflow_attempts::PhaseResultAction;

    #[test]
    fn study_reading_does_not_claim_the_resume_action() {
        assert_eq!(
            study_jobs_key(&[PhaseResultAction::ContinueRun, PhaseResultAction::Open]),
            'C'
        );
        assert_eq!(
            study_jobs_key(&[PhaseResultAction::Select, PhaseResultAction::Open]),
            'c'
        );
        assert_eq!(study_jobs_key(&[]), 'c');
    }
}
