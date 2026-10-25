//! Forecast only the model component of explicitly frozen runtime-free work.
use crate::app::BatchScanConfig;
use kuzushi_core::capabilities::campaign::FrozenContextCase;
use serde_json::Value;

pub(super) fn lines(config: &BatchScanConfig) -> Option<Vec<String>> {
    let jobs = frozen_jobs(config)?;
    let review = config.study.protected_review_calls.map_or_else(
        || "not set".into(),
        |calls| format!("{calls} calls within the total"),
    );
    let mut lines = vec![
        format!("Frozen discovery: {jobs} native jobs · 0 model-provider requests."),
        "Model-provider charges for these jobs: $0. Local compute and scanner-service costs are not estimated.".into(),
        format!("Protected Review limit: {review}. Model-backed follow-ups require separately approved work."),
        "Estimate basis: frozen inputs and shared runtime policy.".into(),
    ];
    if let Some(id) = config
        .prior_campaign_id
        .as_ref()
        .or(config.prior_run_id.as_ref())
    {
        lines.push(format!("Historical evidence: {id}."));
    }
    Some(lines)
}

fn frozen_jobs(config: &BatchScanConfig) -> Option<usize> {
    if config.study.review_receipt.is_some() {
        return None;
    }
    if scope_work(config) {
        let receipt = config.study.scope_receipt.as_ref()?;
        return case_jobs(&receipt.scope_study.cases, receipt.job_count);
    }
    if matrix_work(config) {
        let receipt = config.study.matrix.receipt.as_ref()?;
        return case_jobs(&receipt.matrix.cases, receipt.job_count);
    }
    single_jobs(config)
}

fn scope_work(config: &BatchScanConfig) -> bool {
    config.study.scope_draft.is_some() || config.study.scope_receipt.is_some()
}

fn matrix_work(config: &BatchScanConfig) -> bool {
    !config.study.matrix.cases.is_empty() || config.study.matrix.receipt.is_some()
}

fn single_jobs(config: &BatchScanConfig) -> Option<usize> {
    let receipt = config.study.receipt.as_ref()?;
    native_input(&receipt.scan_input, &receipt.equivalence.components.model)
        .then_some(receipt.job_count)
        .filter(|jobs| *jobs > 0)
}

fn case_jobs(cases: &[FrozenContextCase], expected: usize) -> Option<usize> {
    let jobs = cases
        .iter()
        .try_fold(0usize, |jobs, case| jobs.checked_add(native_passes(case)?))?;
    (expected > 0 && jobs == expected).then_some(jobs)
}

fn native_passes(case: &FrozenContextCase) -> Option<usize> {
    if case.passes == 0 || !native_input(&case.base_input, &case.equivalence.components.model) {
        return None;
    }
    Some(case.passes)
}

fn native_input(input: &Value, model: &Option<String>) -> bool {
    model.is_none() && !kuzushi_core::modules::tool_needs_runtime("sast:scan", input)
}
