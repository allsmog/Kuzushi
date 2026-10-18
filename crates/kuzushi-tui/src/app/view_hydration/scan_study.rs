use super::*;

impl ShellApp {
    pub(crate) fn scan_study_progress_key(&self) -> Option<ViewHydrationKey> {
        let target = self.target()?;
        if self.shell_view() != ShellView::Workbench
            || crate::ui_view_models::active_workbench_page(self) != WorkbenchPage::Scan
        {
            return None;
        }
        let campaign_id = self
            .owned_scan_study(target)
            .or_else(|| self.approved_scan_study())?;
        Some(ViewHydrationKey::ScanStudyProgress { campaign_id })
    }

    fn owned_scan_study(&self, target: &Path) -> Option<String> {
        let (origin, id) = self.runtime_state.owned_dispatcher_origin()?;
        if origin != target {
            return None;
        }
        self.router
            .campaign()
            .campaigns
            .iter()
            .find(|plan| plan.campaign_id == id && discovery_plan(plan))
            .map(|plan| plan.campaign_id.clone())
    }

    fn approved_scan_study(&self) -> Option<String> {
        let target = self.target()?;
        let key = self.investigation_allowance_key()?;
        let state = self
            .workbench_cache()
            .borrow()
            .cached_investigation_allowance(target, &key);
        let ViewDataState::Ready(Ok(Some(allowance))) = state else {
            return None;
        };
        let plan = allowance.work_plan.as_ref()?;
        if plan.jobs.is_empty() || !plan.jobs.iter().all(|job| job.tool == "sast:scan") {
            return None;
        }
        Some(plan.campaign_id.clone())
    }
}

fn discovery_plan(plan: &kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot) -> bool {
    use kuzushi_core::capabilities::campaign::{
        CONTEXT_MATRIX_KIND, SCAN_BATCH_KIND, SCOPE_STUDY_KIND,
    };
    matches!(
        plan.kind.as_deref(),
        Some(SCAN_BATCH_KIND | CONTEXT_MATRIX_KIND | SCOPE_STUDY_KIND)
    )
}

#[cfg(test)]
mod tests;
