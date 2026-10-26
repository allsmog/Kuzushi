use super::BatchScanConfig;
use crate::app::ShellApp;
use kuzushi_core::capabilities::campaign::{
    load_study_allowance, load_study_plan_receipt, StudyPlanReceipt,
};
use serde_json::Value;

mod support;
use support::*;

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
