use super::BatchScanConfig;
use kuzushi_core::capabilities::campaign::{load_study_allowance, load_study_plan_receipt};
use serde_json::Value;

pub(super) fn record_case_study_receipt(config: &mut BatchScanConfig, data: &Value) -> bool {
    super::super::context_matrix::try_record_matrix_receipt(config, data)
        || super::super::scope_study::try_record_receipt(config, data)
}

pub(super) fn pending_job_needs_model(
    job: &kuzushi_core::capabilities::campaign::snapshot::CampaignJobSnapshot,
) -> bool {
    job.state != "completed"
        && job
            .tool
            .as_deref()
            .is_some_and(|tool| kuzushi_core::modules::tool_needs_runtime(tool, &job.input))
}

pub(super) fn matches_pending_baseline_allowance(config: &BatchScanConfig, data: &Value) -> bool {
    config.study.baseline_allowance_pending
        && data["allowance"]["investigationId"].as_str()
            == Some(config.study.investigation_id.as_str())
}

pub(super) fn check_context_approval(target: &std::path::Path, id: &str) -> anyhow::Result<()> {
    let receipt = kuzushi_core::capabilities::campaign::load_context_study(target, id)?;
    let allowance = receipt
        .load_allowance(target)?
        .ok_or_else(|| anyhow::anyhow!("Press a to review the context plan and its allowance."))?;
    receipt.bound_input(&allowance)?;
    Ok(())
}

pub(super) fn reset_context_review(config: &mut BatchScanConfig) {
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

pub(super) fn restore_named_study(
    target: &std::path::Path,
    id: &str,
    kind: Option<&str>,
) -> anyhow::Result<BatchScanConfig> {
    if kind == Some(kuzushi_core::capabilities::campaign::SCOPE_STUDY_KIND) {
        return super::super::scope_study::restore(target, id);
    }
    if kind == Some(kuzushi_core::capabilities::campaign::CONTEXT_MATRIX_KIND) {
        return super::super::context_matrix::restore_matrix(target, id);
    }
    restore_study(target, id)
}

pub(super) fn check_scan_approval(target: &std::path::Path, id: &str) -> anyhow::Result<()> {
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
