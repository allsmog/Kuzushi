use super::{launch::study_input, BatchScanConfig};
use crate::app::{state_transitions::InputUpdate, ShellApp};
use anyhow::{Context, Result};
use serde_json::{json, Value};

impl ShellApp {
    pub(super) fn launch_batch_from_config(&mut self) -> InputUpdate {
        if self.has_running_work() {
            self.set_batch_config_notice("Wait for active work before changing this study.");
            return InputUpdate::handled();
        }
        let Some(config) = self.router.campaign().batch_scan_config.clone() else {
            return InputUpdate::handled();
        };
        if config.number_edit.is_some() {
            return InputUpdate::handled();
        }
        self.advance_study(config)
    }

    fn advance_study(&mut self, config: BatchScanConfig) -> InputUpdate {
        if config.study.receipt.is_none() {
            return self.prepare_study_draft(&config);
        }
        if config.study.approved() {
            return self.open_approved_study_jobs(&config);
        }
        match allowance_input(&config, self.config().model.as_deref()) {
            Ok(input) => self.dispatch_study_action("campaign:approve-allowance", input),
            Err(error) => {
                self.set_batch_config_notice(format!("{error:#}"));
                InputUpdate::handled()
            }
        }
    }

    fn prepare_study_draft(&mut self, config: &BatchScanConfig) -> InputUpdate {
        let Some(target) = self.target_owned() else {
            return InputUpdate::handled();
        };
        let id = kuzushi_core::new_run_id("study");
        match study_input(self, &target, config, &id) {
            Ok(input) => self.dispatch_new_study(id, input),
            Err(error) => {
                self.set_batch_config_notice(format!("Study draft unavailable: {error:#}"));
                InputUpdate::handled()
            }
        }
    }

    fn dispatch_new_study(&mut self, id: String, input: Value) -> InputUpdate {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return InputUpdate::handled();
        };
        config.study.campaign_id = Some(id);
        self.dispatch_study_action("campaign:study", input)
    }

    fn dispatch_study_action(&mut self, tool: &str, input: Value) -> InputUpdate {
        self.set_batch_config_notice("Preparing the selected action. No scan jobs started.");
        InputUpdate::handled_with_effects(
            self.reduce_run_tool(Some(tool.into()), Some(input.to_string())),
        )
    }

    fn open_approved_study_jobs(&mut self, config: &BatchScanConfig) -> InputUpdate {
        let Some(receipt) = &config.study.receipt else {
            return InputUpdate::handled();
        };
        let id = receipt.campaign_id.clone();
        self.router.campaign_mut().batch_scan_config = None;
        self.open_batch_results(&id);
        self.router.campaign_mut().notice = Some(
            "Plan approved. L starts its fixed jobs; a reopens the plan and allowance.".into(),
        );
        InputUpdate::handled()
    }
}

fn allowance_input(config: &BatchScanConfig, selected_model: Option<&str>) -> Result<Value> {
    let study = &config.study;
    let receipt = study
        .receipt
        .as_ref()
        .context("Prepare a study draft first.")?;
    let model = receipt
        .equivalence
        .components
        .model
        .as_deref()
        .or(selected_model)
        .filter(|model| !model.trim().is_empty())
        .context("Select a model in Setup before approving an allowance.")?;
    let mut input = allowance_terms(study, model)?;
    input["reason"] =
        json!("Operator reviewed the finite discovery study and its total call allowance.");
    input["campaignId"] = json!(receipt.campaign_id);
    input["campaignPlanSha256"] = json!(receipt.plan_sha256);
    input["campaignJobs"] = json!(receipt.job_count);
    input["maxJobAttempts"] = json!(study.max_job_attempts);
    Ok(input)
}

pub(super) fn allowance_terms(
    study: &super::study_state::StudyDraftState,
    model: &str,
) -> Result<Value> {
    let total = study
        .max_provider_calls
        .context("Set Total calls before reviewing the allowance.")?;
    let review = study
        .protected_review_calls
        .context("Set Protected review explicitly, including zero if intended.")?;
    anyhow::ensure!(
        review <= total,
        "Protected review must fit within Total calls."
    );
    Ok(json!({
        "investigationId": study.investigation_id,
        "expectedRevision": study.allowance.as_ref().map_or(0, |value| value.revision),
        "model": model, "maxProviderCalls": total, "protectedReviewCalls": review,
    }))
}

#[cfg(test)]
mod tests;
