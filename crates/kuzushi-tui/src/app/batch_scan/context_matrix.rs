//! Operator-owned finite context cases. Editing starts no work.
use super::BatchScanConfig;
use crate::app::{state_transitions::InputUpdate, ShellApp};
use crossterm::event::KeyCode;
use kuzushi_core::capabilities::campaign::{
    ContextCaseInput, ContextMatrixReceipt, MAX_CONTEXT_CASES,
};
use serde_json::json;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct StudyContextMatrix {
    pub(crate) cases: Vec<ContextCaseInput>,
    pub(crate) baseline_case_id: Option<String>,
    pub(crate) receipt: Option<ContextMatrixReceipt>,
    pub(crate) open: bool,
    pub(crate) cursor: usize,
    pub(crate) results: bool,
    pub(crate) pass_selection: Option<bool>,
    pub(crate) pass_cursor: usize,
    pub(crate) baseline_run_id: Option<String>,
    pub(crate) detail_scroll: usize,
}

impl StudyContextMatrix {
    pub(crate) fn planned_jobs(&self) -> usize {
        self.cases.iter().map(|case| case.passes).sum()
    }
}

impl ShellApp {
    pub(super) fn open_context_matrix(&mut self) -> InputUpdate {
        if self.scope_context_action_unavailable(KeyCode::Char('+')) {
            return InputUpdate::handled();
        }
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.study.matrix.open = true;
            config.notice = None;
        }
        InputUpdate::handled()
    }

    pub(super) fn handle_context_matrix_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        if !self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .study
            .matrix
            .open
        {
            return None;
        }
        if let Some(update) = self.handle_matrix_result_key(code) {
            return Some(update);
        };
        if let Some(update) = self.context_matrix_primary_key(code) {
            return Some(update);
        }
        let config = self.router.campaign_mut().batch_scan_config.as_mut()?;
        match code {
            KeyCode::Esc | KeyCode::Char('q') => config.study.matrix.open = false,
            KeyCode::Up => {
                config.study.matrix.cursor = config.study.matrix.cursor.saturating_sub(1)
            }
            KeyCode::Down => {
                config.study.matrix.cursor = (config.study.matrix.cursor + 1)
                    .min(config.study.matrix.cases.len().saturating_sub(1))
            }
            _ => apply_case_action(config, code),
        }
        Some(InputUpdate::handled())
    }

    fn context_matrix_primary_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        match code {
            KeyCode::Char('a') => {
                self.router
                    .campaign_mut()
                    .batch_scan_config
                    .as_mut()?
                    .study
                    .matrix
                    .open = false;
                Some(self.open_study_context_picker())
            }
            KeyCode::Char('L') => Some(self.launch_batch_from_config()),
            KeyCode::Char('v') => Some(self.open_matrix_results()),
            KeyCode::Char('p') => {
                self.router
                    .campaign_mut()
                    .batch_scan_config
                    .as_mut()?
                    .begin_number_edit(super::BatchScanConfigRow::CasePasses);
                Some(InputUpdate::handled())
            }
            _ => None,
        }
    }

    pub(super) fn add_inspected_context_case(&mut self, baseline: bool) {
        let Some(picker) = self.study_context_picker().cloned() else {
            return;
        };
        if picker.selected.is_some() && picker.preview.is_none() {
            self.set_batch_config_notice(
                "Inspect this exact revision with Enter before including it in a matrix.",
            );
            return;
        }
        let reference = json!(picker.selected);
        let label = picker
            .preview
            .as_ref()
            .and_then(|preview| preview.document["title"].as_str())
            .unwrap_or("Omit context")
            .to_owned();
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            add_case(config, reference, label, baseline);
        }
    }
}

mod results;

fn add_case(
    config: &mut BatchScanConfig,
    reference: serde_json::Value,
    label: String,
    baseline: bool,
) {
    if config.study.context_baseline_run_id.is_some() {
        config.notice = Some("Clear the historical Context comparison before creating a fresh matrix. Its spending remains recorded.".into());
        return;
    }
    let index = config
        .study
        .matrix
        .cases
        .iter()
        .position(|case| case.threat_model_ref == reference);
    let Some(index) = include_case(config, index, reference, label) else {
        return;
    };
    if baseline {
        config.study.matrix.baseline_case_id = Some(config.study.matrix.cases[index].id.clone());
    }
    config.study.matrix.cursor = index;
    config.study.invalidate_plan();
    config.context_picker = None;
    config.study.matrix.open = true;
    config.notice = Some(
        "Case included. b baseline · p passes · L prepare the finite matrix. No work starts."
            .into(),
    );
}

fn include_case(
    config: &mut BatchScanConfig,
    index: Option<usize>,
    reference: serde_json::Value,
    label: String,
) -> Option<usize> {
    if let Some(index) = index {
        return Some(index);
    };
    if config.study.matrix.cases.len() >= MAX_CONTEXT_CASES {
        config.notice = Some("Eight context cases are already selected. Remove or replace a case before adding another.".into());
        return None;
    }
    config.study.matrix.cases.push(ContextCaseInput {
        id: kuzushi_core::new_run_id("case"),
        label,
        threat_model_ref: reference,
        passes: config.trials,
    });
    Some(config.study.matrix.cases.len() - 1)
}

fn apply_case_action(config: &mut BatchScanConfig, code: KeyCode) {
    let index = config.study.matrix.cursor;
    match code {
        KeyCode::Char('b') => select_case_baseline(config, index),
        KeyCode::Char('x') => remove_case(config, index),
        KeyCode::Char('c') => {
            config.study.matrix = Default::default();
            config.study.invalidate_plan();
            config.notice = Some(
                "Context cases cleared. Spending is retained; a replacement study needs approval."
                    .into(),
            );
        }
        _ => {}
    }
}

fn select_case_baseline(config: &mut BatchScanConfig, index: usize) {
    let Some(case) = config.study.matrix.cases.get(index) else {
        return;
    };
    config.study.matrix.baseline_case_id = Some(case.id.clone());
    config.study.invalidate_plan();
}

fn remove_case(config: &mut BatchScanConfig, index: usize) {
    if index >= config.study.matrix.cases.len() {
        return;
    };
    let removed = config.study.matrix.cases.remove(index);
    if config.study.matrix.baseline_case_id.as_deref() == Some(removed.id.as_str()) {
        config.study.matrix.baseline_case_id = None;
    }
    config.study.matrix.cursor = index.min(config.study.matrix.cases.len().saturating_sub(1));
    config.study.invalidate_plan();
}

pub(super) fn record_matrix_receipt(
    config: &mut BatchScanConfig,
    data: &serde_json::Value,
) -> anyhow::Result<()> {
    let receipt: ContextMatrixReceipt = serde_json::from_value(data.clone())?;
    let baseline = receipt.matrix.baseline()?;
    let mut input = baseline.base_input.clone();
    input
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Matrix scanner input is malformed"))?
        .remove("threatModelRef");
    let cases = receipt
        .matrix
        .cases
        .iter()
        .map(|case| ContextCaseInput {
            id: case.id.clone(),
            label: case.label.clone(),
            passes: case.passes,
            threat_model_ref: case.base_input["threatModelRef"].clone(),
        })
        .collect();
    config.apply_worker_resolution(receipt.workers, receipt.worker_limitation.clone());
    config.study.scan_input = Some(input);
    config.study.receipt = None;
    config.study.matrix.cases = cases;
    config.study.matrix.baseline_case_id = Some(receipt.matrix.baseline_case_id.clone());
    config.prior_campaign_id = receipt
        .resource_evidence
        .as_ref()
        .map(|evidence| evidence.baseline_campaign_id.clone());
    config.study.matrix.receipt = Some(receipt);
    config.notice = Some("Matrix draft ready. Review all cases and the shared allowance before approving. No jobs started.".into());
    Ok(())
}

pub(super) fn try_record_matrix_receipt(
    config: &mut BatchScanConfig,
    data: &serde_json::Value,
) -> bool {
    if data.get("matrix").is_none() {
        return false;
    };
    if let Err(error) = record_matrix_receipt(config, data) {
        config.notice = Some(format!("Matrix receipt unavailable: {error:#}"));
    }
    true
}

pub(super) fn restore_matrix(
    target: &std::path::Path,
    id: &str,
) -> anyhow::Result<BatchScanConfig> {
    let receipt = kuzushi_core::capabilities::campaign::load_context_matrix_receipt(target, id)?;
    let mut config = BatchScanConfig::load(target, None);
    config.study.campaign_id = Some(id.into());
    config.study.investigation_id = receipt
        .investigation_id
        .clone()
        .unwrap_or_else(|| id.into());
    config.requested_workers = receipt.requested_workers;
    record_matrix_receipt(&mut config, &serde_json::to_value(receipt)?)?;
    if let Some(allowance) = config
        .study
        .matrix
        .receipt
        .as_ref()
        .unwrap()
        .load_allowance(target)?
    {
        config.study.restore_allowance(allowance);
    }
    config.notice = Some("Saved matrix loaded. All contexts and spending are retained; source is checked before new work.".into());
    Ok(config)
}

pub(super) fn check_matrix_approval(target: &std::path::Path, id: &str) -> anyhow::Result<()> {
    let receipt = kuzushi_core::capabilities::campaign::load_context_matrix_receipt(target, id)?;
    let allowance = receipt.load_allowance(target)?.ok_or_else(|| {
        anyhow::anyhow!(
            "Press a to review this exact matrix and its shared allowance before starting"
        )
    })?;
    let plan = allowance
        .work_plan
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Matrix work approval is missing"))?;
    anyhow::ensure!(
        plan.plan_sha256 == receipt.plan_sha256 && plan.jobs.len() == receipt.job_count,
        "Matrix changed after approval; prepare and approve its exact work again"
    );
    Ok(())
}

pub(super) fn refresh_matrix_allowance(config: &mut BatchScanConfig) -> bool {
    let Some(receipt) = &config.study.matrix.receipt else {
        return false;
    };
    let result = receipt.load_allowance(&config.target);
    apply_matrix_allowance_read(config, result);
    true
}

fn apply_matrix_allowance_read(
    config: &mut BatchScanConfig,
    result: anyhow::Result<Option<kuzushi_core::allowance::AllowanceSnapshot>>,
) {
    match preserve_allowance_continuity(config, result) {
        Ok(Some(allowance)) => {
            config.study.accounting_error = None;
            config.study.allowance = Some(allowance);
            config.notice = Some(
                "Matrix allowance refreshed. Cases, limits and prior spending are retained.".into(),
            );
        }
        Ok(None) => {
            config.notice = Some(
                "Allowance not approved. Review this plan and set its limits before work.".into(),
            )
        }
        Err(error) => {
            config.study.accounting_error =
                Some(format!("Matrix accounting unavailable: {error:#}"));
            config.notice = Some("Accounting is unavailable; work is blocked. r retries the read without replacing this investigation.".into());
        }
    }
}

fn preserve_allowance_continuity(
    config: &BatchScanConfig,
    result: anyhow::Result<Option<kuzushi_core::allowance::AllowanceSnapshot>>,
) -> anyhow::Result<Option<kuzushi_core::allowance::AllowanceSnapshot>> {
    anyhow::ensure!(
        !(config.study.allowance.is_some() && matches!(&result, Ok(None))),
        "Previously recorded allowance is missing; spending cannot be reset"
    );
    result
}
