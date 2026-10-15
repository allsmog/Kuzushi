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
        let kind = self
            .router
            .campaign()
            .selected_campaign()
            .and_then(|campaign| campaign.kind.as_deref());
        match kind {
            Some(kuzushi_core::capabilities::campaign::SCOPE_STUDY_KIND) => {
                super::scope_study::check_approval(target, id)
            }
            Some(kuzushi_core::capabilities::campaign::CONTEXT_MATRIX_KIND) => {
                super::context_matrix::check_matrix_approval(target, id)
            }
            Some("context-study") => check_context_approval(target, id),
            Some(kuzushi_core::capabilities::campaign::REVIEW_STUDY_KIND) => {
                super::review_study::recovery::check_review_approval(target, id)
            }
            Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND) => {
                check_scan_approval(target, id)
            }
            _ => Ok(()),
        }?;
        self.check_selected_study_call_capacity(target, id)
    }

    fn check_selected_study_call_capacity(
        &self,
        target: &std::path::Path,
        id: &str,
    ) -> anyhow::Result<()> {
        let pending_model_work = self
            .router
            .campaign()
            .selected_campaign()
            .filter(|campaign| super::is_fixed_study_snapshot(campaign))
            .is_some_and(|campaign| campaign.jobs.iter().any(pending_job_needs_model));
        if !pending_model_work {
            return Ok(());
        }
        let workspace = kuzushi_core::WorkspaceTarget::new(target)?;
        let Some(allowance) =
            kuzushi_core::SpendLimiter::read_campaign_allowance(&workspace.findings_db_path(), id)?
        else {
            return Ok(());
        };
        let category = self
            .router
            .campaign()
            .selected_campaign()
            .filter(|campaign| {
                campaign.kind.as_deref()
                    == Some(kuzushi_core::capabilities::campaign::REVIEW_STUDY_KIND)
            })
            .map_or(
                kuzushi_core::allowance::InvestigationWork::Discovery,
                |_| kuzushi_core::allowance::InvestigationWork::Review,
            );
        allowance.require_call_capacity(category)
    }

    /// Updates only the matching draft. Background completion never navigates.
    pub(crate) fn cache_study_result(&mut self, tool: &str, data: &Value) -> bool {
        match tool {
            "campaign:brief" => return self.cache_brief_result(data),
            "campaign:allowance" => return self.cache_study_allowance_read(data),
            "campaign:context-study" => return self.cache_context_generation_result(tool, data),
            "campaign:review-study" => return self.cache_review_study_result(data),
            "campaign:context-map" => return self.cache_context_map_result(data),
            "campaign:study" => self.cache_study_receipt(data),
            "campaign:approve-allowance" => self.cache_study_approval(data),
            "threat-model:read" => return self.cache_study_context_preview(data),
            "threat-model:revise" => return self.cache_context_edit_result(data),
            "threat-model:verify" => return self.cache_context_check_result(data),
            _ => return false,
        }
        self.checkpoint_study_choices();
        true
    }

    fn cache_study_allowance_read(&mut self, data: &Value) -> bool {
        if data["target"].as_str().map(std::path::Path::new) != self.target() {
            return false;
        }
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return false;
        };
        if !matches_pending_baseline_allowance(config, data) {
            return false;
        }
        match serde_json::from_value(data["allowance"].clone()) {
            Ok(allowance) => {
                config.study.restore_allowance(allowance);
                config.notice = Some("Baseline allowance read. Existing spending and limits are retained; no work starts.".into());
            }
            Err(error) => {
                config.study.accounting_error =
                    Some(format!("Baseline allowance unavailable: {error}"))
            }
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
        if record_case_study_receipt(config, data) {
            return;
        }
        let decoded =
            serde_json::from_value::<StudyPlanReceipt>(data.clone()).and_then(|receipt| {
                super::context_experiment::read_context_experiment(data)
                    .map(|experiment| (receipt, experiment))
                    .map_err(serde::de::Error::custom)
            });
        match decoded {
            Ok((receipt, experiment)) => {
                config.study.context_baseline_run_id = experiment
                    .as_ref()
                    .map(|receipt| receipt.baseline_run_id.clone());
                config.study.context_experiment = experiment;
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
        let kind = self
            .router
            .campaign()
            .selected_campaign()
            .and_then(|campaign| campaign.kind.clone());
        self.restore_study_editor(&target, &id, kind.as_deref());
    }

    fn restore_study_editor(&mut self, target: &std::path::Path, id: &str, kind: Option<&str>) {
        if kind == Some("context-study") {
            self.restore_context_generation(target, id);
            return;
        }
        if kind == Some(kuzushi_core::capabilities::campaign::REVIEW_STUDY_KIND) {
            self.restore_review_study(target, id);
            return;
        }
        let restored = restore_named_study(target, id, kind);
        match restored {
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
        if super::context_matrix::refresh_matrix_allowance(config) {
            return;
        };
        if super::scope_study::refresh_allowance(config) {
            return;
        }
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

fn record_case_study_receipt(config: &mut BatchScanConfig, data: &Value) -> bool {
    super::context_matrix::try_record_matrix_receipt(config, data)
        || super::scope_study::try_record_receipt(config, data)
}

fn pending_job_needs_model(
    job: &kuzushi_core::capabilities::campaign::snapshot::CampaignJobSnapshot,
) -> bool {
    job.state != "completed"
        && job
            .tool
            .as_deref()
            .is_some_and(|tool| kuzushi_core::modules::tool_needs_runtime(tool, &job.input))
}

fn matches_pending_baseline_allowance(config: &BatchScanConfig, data: &Value) -> bool {
    config.study.baseline_allowance_pending
        && data["allowance"]["investigationId"].as_str()
            == Some(config.study.investigation_id.as_str())
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
    let experiment =
        kuzushi_core::capabilities::campaign::load_study_context_experiment(target, &receipt)?;
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
    config.study.context_baseline_run_id = experiment
        .as_ref()
        .map(|value| value.baseline_run_id.clone());
    config.study.context_experiment = experiment;
    if let Some(allowance) = allowance {
        config.study.restore_allowance(allowance);
    }
    Ok(config)
}

fn restore_named_study(
    target: &std::path::Path,
    id: &str,
    kind: Option<&str>,
) -> anyhow::Result<BatchScanConfig> {
    if kind == Some(kuzushi_core::capabilities::campaign::SCOPE_STUDY_KIND) {
        return super::scope_study::restore(target, id);
    }
    if kind == Some(kuzushi_core::capabilities::campaign::CONTEXT_MATRIX_KIND) {
        return super::context_matrix::restore_matrix(target, id);
    }
    restore_study(target, id)
}

fn check_scan_approval(target: &std::path::Path, id: &str) -> anyhow::Result<()> {
    let receipt = load_study_plan_receipt(target, id)?;
    if !receipt.approval_required {
        return Ok(());
    };
    let allowance = load_study_allowance(target, &receipt)?.ok_or_else(|| {
        anyhow::anyhow!("Review this plan and its allowance with a before starting jobs.")
    })?;
    anyhow::ensure!(
        allowance
            .work_plan
            .as_ref()
            .is_some_and(|plan| plan.campaign_id == id && plan.plan_sha256 == receipt.plan_sha256),
        "This exact plan is not approved. Press a to review its plan and allowance."
    );
    Ok(())
}
