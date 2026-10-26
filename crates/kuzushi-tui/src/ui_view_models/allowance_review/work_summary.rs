use crate::app::BatchScanConfig;
use kuzushi_core::capabilities::campaign::{ContextStudyReceipt, FrozenContextCase};
use serde_json::Value;
mod cargo_audit;
mod formatting;
mod models;
#[cfg(test)]
use formatting::bounded_label;
use formatting::{context_line, engine_line, scope_line, semgrep_time_line};
use models::{execution_model_line, model_overview};

struct FrozenWorkSummary<'a> {
    campaign: &'a str,
    digest: &'a str,
    jobs: usize,
    workers: usize,
    lines: Vec<String>,
    models: Vec<Option<&'a str>>,
}

pub(super) fn summary(
    config: &BatchScanConfig,
    input: &Value,
) -> Option<super::AllowanceWorkSummary> {
    let candidates = frozen_summaries(config);
    let Some(frozen) = candidates
        .iter()
        .find(|candidate| input["campaignId"].as_str() == Some(candidate.campaign))
    else {
        return (!candidates.is_empty()).then(mismatch_lines);
    };
    if !matches_plan(frozen, input) {
        return Some(mismatch_lines());
    }
    let name = config
        .target
        .file_name()
        .unwrap_or(config.target.as_os_str())
        .to_string_lossy();
    let repository = format!("Repository: {name}");
    let mut overview = vec![repository.clone()];
    overview.extend(frozen.lines.first().cloned());
    overview.extend(model_overview(&frozen.models));
    let mut details = vec![repository];
    details.extend(frozen.lines.iter().filter(|line| !line.is_empty()).cloned());
    Some(super::AllowanceWorkSummary {
        overview,
        details,
        workers: Some(frozen.workers),
    })
}

fn frozen_summaries(config: &BatchScanConfig) -> Vec<FrozenWorkSummary<'_>> {
    [
        review_summary(config),
        generation_summary(config),
        scope_summary(config),
        matrix_summary(config),
        scan_summary(config),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn matches_plan(frozen: &FrozenWorkSummary<'_>, input: &Value) -> bool {
    input["campaignPlanSha256"].as_str() == Some(frozen.digest)
        && input["campaignJobs"].as_u64() == Some(frozen.jobs as u64)
}

fn mismatch_lines() -> super::AllowanceWorkSummary {
    super::AllowanceWorkSummary {
        overview: vec![
            "Work summary unavailable: this approval differs from the displayed plan.".into(),
        ],
        details: Vec::new(),
        workers: None,
    }
}

fn review_summary(config: &BatchScanConfig) -> Option<FrozenWorkSummary<'_>> {
    config
        .study
        .review_receipt
        .as_ref()
        .map(|receipt| FrozenWorkSummary {
            campaign: &receipt.campaign_id,
            digest: &receipt.plan_sha256,
            jobs: 1,
            workers: 1,
            models: vec![Some(receipt.model.as_str())],
            lines: vec![
                format!(
                    "Review: {} frozen observations · 1 worker",
                    receipt.findings.len()
                ),
                format!(
                    "Strategy: {}",
                    receipt.input["strategy"].as_str().unwrap_or("not recorded")
                ),
                context_line(&receipt.input),
                execution_model_line(Some(&receipt.model)),
            ],
        })
}

fn generation_summary(config: &BatchScanConfig) -> Option<FrozenWorkSummary<'_>> {
    config
        .context_generation
        .as_ref()?
        .receipt
        .as_ref()
        .map(context_summary)
}

fn context_summary(receipt: &ContextStudyReceipt) -> FrozenWorkSummary<'_> {
    if receipt.generation_tool == "planner:propose" {
        return workflow_proposal_summary(receipt);
    }
    let jobs = receipt.preparation_jobs.len() + 1;
    let mut lines = context_action_lines(receipt, jobs);
    lines.extend(context_source_lines(receipt));
    FrozenWorkSummary {
        campaign: &receipt.campaign_id,
        digest: &receipt.plan_sha256,
        jobs,
        workers: 1,
        models: vec![Some(receipt.model.as_str())],
        lines,
    }
}

fn context_action_lines(receipt: &ContextStudyReceipt, jobs: usize) -> Vec<String> {
    vec![
        format!("Context: {jobs} fixed jobs · 1 worker"),
        format!("Action: {}", receipt.generation_tool),
        format!("Preparation jobs: {}", receipt.preparation_jobs.len()),
        execution_model_line(Some(&receipt.model)),
        receipt.input["question"]
            .as_str()
            .map(|question| format!("Frozen question: {question}"))
            .unwrap_or_default(),
        context_line(&receipt.input),
    ]
}

fn context_source_lines(receipt: &ContextStudyReceipt) -> Vec<String> {
    let Some(paths) = receipt.input["sourcePaths"].as_array() else {
        return Vec::new();
    };
    let mut lines = vec![format!("Evidence: {} exact files (quoted)", paths.len())];
    lines.extend(paths.iter().map(|path| format!("  {path}")));
    lines.extend(crate::ui_view_models::evidence_inventory::receipt_lines(
        receipt.source_inventory.as_ref(),
    ));
    lines
}

fn workflow_proposal_summary(receipt: &ContextStudyReceipt) -> FrozenWorkSummary<'_> {
    FrozenWorkSummary {
        campaign: &receipt.campaign_id, digest: &receipt.plan_sha256, jobs: 1, workers: 1,
        models: vec![Some(receipt.model.as_str())],
        lines: vec![
            "Workflow proposal: 1 fixed job · 1 worker".into(),
            execution_model_line(Some(&receipt.model)),
            format!("Frozen goal: {}", receipt.input["goal"].as_str().unwrap_or("missing")),
            format!("Phase: {}", receipt.input["phase"].as_str().unwrap_or("option proposals and notes only")),
            "Input: declared Core capabilities and this goal. Source contents are not supplied to the model.".into(),
            "One proposal request with no tools or repair. Proposed actions need a separate decision and spending approval.".into(),
        ],
    }
}

fn scope_summary(config: &BatchScanConfig) -> Option<FrozenWorkSummary<'_>> {
    config.study.scope_receipt.as_ref().map(|receipt| {
        case_summary(
            &receipt.campaign_id,
            &receipt.plan_sha256,
            receipt.job_count,
            receipt.workers,
            "scopes",
            &receipt.scope_study.cases,
        )
    })
}

fn matrix_summary(config: &BatchScanConfig) -> Option<FrozenWorkSummary<'_>> {
    config.study.matrix.receipt.as_ref().map(|receipt| {
        case_summary(
            &receipt.campaign_id,
            &receipt.plan_sha256,
            receipt.job_count,
            receipt.workers,
            "context cases",
            &receipt.matrix.cases,
        )
    })
}

fn scan_summary(config: &BatchScanConfig) -> Option<FrozenWorkSummary<'_>> {
    let receipt = config.study.receipt.as_ref()?;
    Some(FrozenWorkSummary {
        campaign: &receipt.campaign_id,
        digest: &receipt.plan_sha256,
        jobs: receipt.job_count,
        workers: receipt.workers,
        models: vec![receipt.equivalence.components.model.as_deref()],
        lines: vec![
            format!(
                "Scan: {} passes · {} worker(s)",
                receipt.job_count, receipt.workers
            ),
            engine_line(&receipt.scan_input),
            semgrep_time_line(&receipt.scan_input),
            cargo_audit::limits_line(&receipt.scan_input),
            cargo_audit::network_line(&receipt.scan_input),
            scope_line(&receipt.scan_input),
            context_line(&receipt.scan_input),
            execution_model_line(receipt.equivalence.components.model.as_deref()),
        ],
    })
}

fn case_summary<'a>(
    campaign: &'a str,
    digest: &'a str,
    jobs: usize,
    workers: usize,
    kind: &str,
    cases: &'a [FrozenContextCase],
) -> FrozenWorkSummary<'a> {
    let mut lines = vec![format!(
        "Scan: {} {kind} · {jobs} fixed jobs · {workers} worker(s)",
        cases.len()
    )];
    for case in cases {
        lines.push(format!("{}: {} passes", case.label, case.passes));
        lines.extend([
            engine_line(&case.base_input),
            semgrep_time_line(&case.base_input),
            cargo_audit::limits_line(&case.base_input),
            cargo_audit::network_line(&case.base_input),
            scope_line(&case.base_input),
            context_line(&case.base_input),
            execution_model_line(case.equivalence.components.model.as_deref()),
        ]);
    }
    FrozenWorkSummary {
        campaign,
        digest,
        jobs,
        lines,
        workers,
        models: cases
            .iter()
            .map(|case| case.equivalence.components.model.as_deref())
            .collect(),
    }
}

#[cfg(test)]
mod tests;
