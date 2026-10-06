use super::BatchScanConfig;
use crate::app::ShellApp;
use kuzushi_core::capabilities::campaign::{
    load_study_allowance, load_study_plan_receipt, StudyPlanReceipt,
};
use serde_json::Value;

impl ShellApp {
    pub(crate) fn check_selected_study_approval(
        &self,
        target: &std::path::Path,
        id: &str,
    ) -> anyhow::Result<()> {
        if self
            .router
            .campaign()
            .selected_campaign()
            .is_some_and(|campaign| campaign.kind.as_deref() == Some("context-study"))
        {
            return check_context_approval(target, id);
        }
        if !self
            .router
            .campaign()
            .selected_campaign()
            .is_some_and(super::is_scan_batch_snapshot)
        {
            return Ok(());
        }
        let receipt = load_study_plan_receipt(target, id)?;
        if !receipt.approval_required {
            return Ok(());
        }
        let allowance = load_study_allowance(target, &receipt)?.ok_or_else(|| {
            anyhow::anyhow!("Review this plan and its allowance with a before starting jobs.")
        })?;
        anyhow::ensure!(
            allowance.work_plan.as_ref().is_some_and(
                |plan| plan.campaign_id == id && plan.plan_sha256 == receipt.plan_sha256
            ),
            "This exact plan is not approved. Press a to review its plan and allowance."
        );
        Ok(())
    }

    /// Updates only the matching draft. Background completion never navigates.
    pub(crate) fn cache_study_result(&mut self, tool: &str, data: &Value) -> bool {
        match tool {
            "campaign:context-study" => return self.cache_context_generation_result(tool, data),
            "campaign:context-map" => return self.cache_context_map_result(data),
            "campaign:study" => self.cache_study_receipt(data),
            "campaign:approve-allowance" => self.cache_study_approval(data),
            "threat-model:read" => return self.cache_study_context_preview(data),
            _ => return false,
        }
        true
    }

    fn cache_study_receipt(&mut self, data: &Value) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        if data["campaignId"].as_str() != config.study.campaign_id.as_deref() {
            return;
        }
        match serde_json::from_value::<StudyPlanReceipt>(data.clone()) {
            Ok(receipt) => {
                config.apply_worker_resolution(receipt.workers, receipt.worker_limitation.clone());
                config.study.record_receipt(receipt);
                config.notice = Some("Draft ready. No jobs started. Review Source and context, then set the allowance.".into());
            }
            Err(error) => config.notice = Some(format!("Study receipt unavailable: {error}")),
        }
    }

    fn cache_study_approval(&mut self, data: &Value) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        if data["allowance"]["investigationId"].as_str() != Some(&config.study.investigation_id) {
            return;
        }
        match serde_json::from_value(data["allowance"].clone()) {
            Ok(allowance) => {
                config.study.allowance = Some(allowance);
                reset_context_review(config);
                config.notice = Some("Approval saved. Open approved jobs when ready; starting them is a separate action.".into());
            }
            Err(error) => config.notice = Some(format!("Approval receipt unavailable: {error}")),
        }
    }

    pub(crate) fn review_selected_study(&mut self) {
        let Some(target) = self.target_owned() else {
            return;
        };
        let Some(id) = self
            .router
            .campaign()
            .selected_campaign()
            .map(|c| c.campaign_id.clone())
        else {
            return;
        };
        if self
            .router
            .campaign()
            .selected_campaign()
            .is_some_and(|campaign| campaign.kind.as_deref() == Some("context-study"))
        {
            self.restore_context_generation(&target, &id);
            return;
        }
        match restore_study(&target, &id) {
            Ok(config) => {
                self.show_study_form(config);
            }
            Err(error) => {
                self.router.campaign_mut().notice =
                    Some(format!("Study review unavailable: {error:#}"))
            }
        }
    }

    pub(super) fn refresh_study_allowance(&mut self) {
        let Some(target) = self.target_owned() else {
            return;
        };
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(receipt) = config.study.receipt.as_ref() else {
            return;
        };
        match load_study_allowance(&target, receipt) {
            Ok(allowance) => {
                config.study.allowance = allowance;
                config.notice = Some("Allowance refreshed. Draft values preserved.".into());
            }
            Err(error) => {
                config.study.allowance = None;
                config.notice = Some(format!("Allowance unavailable: {error:#}"));
            }
        }
    }
}

fn check_context_approval(target: &std::path::Path, id: &str) -> anyhow::Result<()> {
    let receipt = kuzushi_core::capabilities::campaign::load_context_study(target, id)?;
    let allowance = receipt
        .load_allowance(target)?
        .ok_or_else(|| anyhow::anyhow!("Press a to review the context plan and its allowance."))?;
    receipt.bound_input(&allowance)?;
    Ok(())
}

fn reset_context_review(config: &mut BatchScanConfig) {
    if let Some(generation) = config.context_generation.as_mut() {
        generation.scroll = 0;
        generation.show_options = false;
    }
}

fn restore_study(target: &std::path::Path, id: &str) -> anyhow::Result<BatchScanConfig> {
    let receipt = load_study_plan_receipt(target, id)?;
    anyhow::ensure!(
        receipt.approval_required,
        "Legacy batch: use scan batch to prepare a study with an explicit allowance."
    );
    let allowance = load_study_allowance(target, &receipt)?;
    let baseline =
        kuzushi_core::capabilities::campaign::load_study_resource_baseline(target, &receipt)?;
    let mut config = BatchScanConfig::load(target, baseline.as_deref());
    config.trials = receipt.job_count;
    config.requested_workers = receipt.requested_workers;
    config.apply_worker_resolution(receipt.workers, receipt.worker_limitation.clone());
    config.study.investigation_id = receipt
        .investigation_id
        .clone()
        .unwrap_or_else(|| id.into());
    config.study.campaign_id = Some(id.into());
    config.study.record_receipt(receipt);
    if let Some(allowance) = allowance {
        config.study.restore_allowance(allowance);
    }
    config.notice = Some(
        "Saved study loaded. Source drift is checked again before approval and execution.".into(),
    );
    Ok(config)
}
