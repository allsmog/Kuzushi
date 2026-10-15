use super::*;

impl ShellApp {
    pub(crate) fn cache_review_planning_failure(&mut self, tool: &str, message: &str) -> bool {
        if !matches!(tool, "campaign:review-study" | "campaign:approve-allowance") {
            return false;
        }
        let Some(config) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .filter(|config| config.review_plan.is_some())
        else {
            return false;
        };
        config.study.preparation_error = Some(message.into());
        config.review_plan.as_mut().unwrap().scroll = 0;
        true
    }
    pub(crate) fn cache_review_study_result(&mut self, data: &Value) -> bool {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return false;
        };
        if data["campaignId"].as_str() != config.study.campaign_id.as_deref()
            || config.review_plan.is_none()
        {
            return false;
        }
        match serde_json::from_value::<ReviewStudyReceipt>(data.clone()) {
            Ok(receipt) => {
                config.study.review_receipt = Some(receipt);
                config.notice=Some("Exact review draft ready. Inspect observations and options, then review the shared allowance. No jobs started.".into());
            }
            Err(error) => config.notice = Some(format!("Review draft unavailable: {error}")),
        }
        true
    }

    pub(crate) fn restore_review_study(&mut self, target: &std::path::Path, id: &str) {
        match restored_config(target,id) {
            Ok(config)=>self.show_study_form(config),
            Err(error)=>self.router.campaign_mut().notice=Some(format!("Review recovery unavailable: {error:#}. Inspect the saved outcome before another attempt.")),
        }
    }

    pub(crate) fn refresh_review_study_model(&mut self) {
        let model = self.config().model.clone();
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(review) = config.review_plan.as_mut() else {
            return;
        };
        if review.input["model"].as_str() == model.as_deref() {
            return;
        }
        review.input.as_object_mut().unwrap().remove("model");
        if let Some(model) = model {
            review.input["model"] = json!(model);
        }
        config.study.invalidate_plan();
        config.notice=Some("Selected model changed. Prepare and approve a new review draft; earlier spending is retained.".into());
    }
}

fn restored_config(target: &std::path::Path, id: &str) -> Result<BatchScanConfig> {
    let receipt = kuzushi_core::capabilities::campaign::load_review_study(target, id)?;
    let mut config = BatchScanConfig::load(target, None);
    config.study.investigation_id = receipt.investigation_id.clone();
    if let Some(allowance) =
        kuzushi_core::capabilities::campaign::load_review_study_allowance(target, &receipt)?
    {
        config.study.restore_allowance(allowance);
    }
    config.study.campaign_id = Some(id.into());
    config.review_plan = Some(ReviewStudyDraft {
        input: receipt.input.clone(),
        planning_step: None,
        scroll: 0,
        show_options: false,
        show_evidence: false,
    });
    config.study.review_receipt = Some(receipt);
    Ok(config)
}

pub(in crate::app::batch_scan) fn check_review_approval(
    target: &std::path::Path,
    id: &str,
) -> Result<()> {
    let receipt = kuzushi_core::capabilities::campaign::load_review_study(target, id)?;
    let allowance =
        kuzushi_core::capabilities::campaign::load_review_study_allowance(target, &receipt)?
            .context("Review its fixed plan and allowance before starting")?;
    receipt.bound_input(&allowance)?;
    Ok(())
}
