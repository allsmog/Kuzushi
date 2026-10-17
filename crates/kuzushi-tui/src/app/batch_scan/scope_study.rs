//! Scope selections remain a local draft until shared planning and approval.
use super::BatchScanConfig;
use kuzushi_core::capabilities::campaign::{
    load_scope_study_receipt, ScopeStudyDraft, ScopeStudyReceipt, SCOPE_STUDY_KIND,
};
use serde_json::{json, Value};
use std::path::Path;

pub(super) fn bind_scope_input(input: &mut Value, config: &BatchScanConfig) {
    let Some(scopes) = &config.study.scope_draft else {
        return;
    };
    input["scopeProposalRef"] = json!(scopes.proposal_ref);
    input["scopeCases"] = json!(scopes.cases);
}

pub(super) fn try_record_receipt(config: &mut BatchScanConfig, data: &Value) -> bool {
    if data["kind"] != SCOPE_STUDY_KIND {
        return false;
    }
    if let Err(error) = record_receipt(
        config,
        serde_json::from_value(data.clone()).map_err(anyhow::Error::from),
    ) {
        config.notice = Some(format!("Scope study receipt unavailable: {error:#}"));
    }
    true
}

fn record_receipt(
    config: &mut BatchScanConfig,
    receipt: anyhow::Result<ScopeStudyReceipt>,
) -> anyhow::Result<()> {
    let receipt = receipt?;
    let input = receipt.draft_scan_input()?;
    config.trials = receipt.scope_study.first()?.passes;
    config.requested_workers = receipt.requested_workers;
    config.apply_worker_resolution(receipt.workers, receipt.worker_limitation.clone());
    config.study.scan_input = Some(input);
    config.study.scope_draft = Some(ScopeStudyDraft {
        proposal_ref: receipt.scope_study.proposal_ref.clone(),
        cases: receipt.scope_study.selections.clone(),
    });
    config.scope_context.labels = receipt
        .scope_study
        .cases
        .iter()
        .map(|case| (case.id.clone(), case.label.clone()))
        .collect();
    config.study.scope_receipt = Some(receipt);
    config.prior_campaign_id = config
        .study
        .scope_receipt
        .as_ref()
        .and_then(|receipt| receipt.resource_evidence.as_ref())
        .map(|evidence| evidence.baseline_campaign_id.clone());
    config.study.receipt = None;
    config.notice = Some("Scope draft ready. Review every selected boundary, workload and shared allowance. No jobs started.".into());
    Ok(())
}

pub(super) fn restore(target: &Path, id: &str) -> anyhow::Result<BatchScanConfig> {
    let receipt = load_scope_study_receipt(target, id)?;
    let allowance = receipt.load_allowance(target)?;
    let investigation = receipt
        .investigation_id
        .clone()
        .unwrap_or_else(|| id.into());
    let mut config = BatchScanConfig::load(target, None);
    record_receipt(&mut config, Ok(receipt))?;
    config.study.investigation_id = investigation;
    config.study.campaign_id = Some(id.into());
    if let Some(allowance) = allowance {
        config.study.restore_allowance(allowance);
    }
    Ok(config)
}

pub(super) fn refresh_allowance(config: &mut BatchScanConfig) -> bool {
    let Some(receipt) = &config.study.scope_receipt else {
        return false;
    };
    match receipt.load_allowance(&config.target) {
        Ok(allowance) => {
            config.study.allowance = allowance;
            config.notice = Some("Scope allowance refreshed. Draft values preserved.".into());
        }
        Err(error) => {
            config.study.allowance = None;
            config.notice = Some(format!("Scope allowance unavailable: {error:#}"));
        }
    }
    true
}

pub(super) fn check_approval(target: &Path, id: &str) -> anyhow::Result<()> {
    let receipt = load_scope_study_receipt(target, id)?;
    let allowance = receipt.load_allowance(target)?.ok_or_else(|| {
        anyhow::anyhow!("Review the scope study and allowance with a before starting")
    })?;
    anyhow::ensure!(
        allowance
            .work_plan
            .as_ref()
            .is_some_and(|work| work.campaign_id == id && work.plan_sha256 == receipt.plan_sha256),
        "This exact scope workload is not approved"
    );
    Ok(())
}

pub(super) fn update_passes(config: &mut BatchScanConfig, value: usize) {
    if let Some(draft) = &mut config.study.scope_draft {
        for case in &mut draft.cases {
            case.passes = value;
        }
    }
}

pub(super) fn job_count(config: &BatchScanConfig) -> usize {
    config
        .study
        .scope_draft
        .as_ref()
        .map_or(config.trials, ScopeStudyDraft::job_count)
}

pub(super) fn picker_input(config: &BatchScanConfig, mut input: Value) -> Value {
    if let Some(draft) = &config.study.scope_draft {
        if let Some(case) = draft.cases.first() {
            input["scanScopeRef"] = json!(kuzushi_core::workspace::ScanScopeRef {
                proposal: draft.proposal_ref.clone(),
                scope_id: case.scope_id.clone()
            });
        }
    }
    input
}

pub(super) fn remove_picker_scope(config: &BatchScanConfig, input: &mut Value) {
    if config.study.scope_draft.is_some() {
        input.as_object_mut().unwrap().remove("scanScopeRef");
    }
}
