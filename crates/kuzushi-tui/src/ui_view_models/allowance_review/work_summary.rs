use crate::app::BatchScanConfig;
use kuzushi_core::capabilities::campaign::{ContextStudyReceipt, FrozenContextCase};
use serde_json::Value;
mod cargo_audit;
mod models;
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

fn engine_line(input: &Value) -> String {
    if input["taskMode"] == "auto" {
        return "Engines: automatic selection; inspect per-engine outcomes after execution".into();
    }
    let engines = input["tasks"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|text| !text.is_empty());
    format!("Engines: {}", engines.as_deref().unwrap_or("not recorded"))
}

fn semgrep_time_line(input: &Value) -> String {
    let selected = input["tasks"].as_array().is_some_and(|tasks| {
        tasks
            .iter()
            .any(|task| matches!(task.as_str(), Some("semgrep" | "semgrep:scan")))
    });
    if !selected && input["taskMode"] != "auto" {
        return String::new();
    }
    let milliseconds = input["semgrepTimeoutMs"]
        .as_u64()
        .unwrap_or(kuzushi_core::scan::DEFAULT_SEMGREP_JOB_TIMEOUT_MS);
    let jobs = input["semgrepJobs"].as_u64().unwrap_or(1);
    format!("Semgrep when selected: {milliseconds} ms per job for subprocess work across roots/batches. Source authentication is separate. Scan workers within each job: {jobs}.")
}

fn scope_line(input: &Value) -> String {
    if let Some(scope) = saved_scope_line(input) {
        return scope;
    }
    if let Some(paths) = input["paths"].as_array().filter(|paths| !paths.is_empty()) {
        return format!(
            "Scope: {} selected path(s): {}",
            paths.len(),
            paths_preview(paths)
        );
    }
    "Scope: whole repository".into()
}

fn paths_preview(paths: &[Value]) -> String {
    let mut text = paths
        .iter()
        .take(3)
        .filter_map(Value::as_str)
        .map(|path| bounded_label(path))
        .collect::<Vec<_>>()
        .join(", ");
    if paths.len() > 3 {
        text.push_str("; further paths remain in the frozen inputs");
    }
    text
}

fn bounded_label(label: &str) -> String {
    let mut chars = label.chars();
    let mut text = chars.by_ref().take(96).collect::<String>();
    if chars.next().is_some() {
        text.push('…');
    }
    text
}

fn saved_scope_line(input: &Value) -> Option<String> {
    if let Some(reference) = input.get("scanScopeRef").filter(|value| !value.is_null()) {
        return Some(reference["scopeId"].as_str().map_or_else(
            || "Scope: recorded boundary is unavailable; inspect the frozen inputs".into(),
            |id| format!("Scope: accepted boundary {id}"),
        ));
    }
    input["shard"]
        .as_str()
        .map(|shard| format!("Scope: selected shard {shard}"))
}

fn context_line(input: &Value) -> String {
    format!(
        "Threat context: {}",
        crate::ui_view_models::study_config::context_reference_summary(input)
    )
}

#[cfg(test)]
mod tests;
