use crate::app::BatchScanConfig;
use crate::app::ViewDataState;
use kuzushi_core::capabilities::campaign::{
    ScanResourceEvidence, ScopeStudyDraft, StudyResourceProjection,
};
mod campaign_resources;
mod native_work;

pub(super) fn row_value(config: &BatchScanConfig) -> String {
    if let Some(campaign) = &config.prior_campaign_id {
        return format!("study {campaign}");
    }
    let Some(prior) = config.selected_prior() else {
        return missing_selection_label(config).into();
    };
    let evidence = match &prior.evidence {
        ViewDataState::Ready(Ok(evidence)) => evidence,
        ViewDataState::Ready(Err(_)) => return "unavailable".into(),
        _ => return "loading usage".into(),
    };
    let calls = evidence.provider_usage.as_ref().map_or_else(
        || "calls unknown".into(),
        |usage| format!("{} calls", usage.committed_calls),
    );
    let dollars = evidence
        .cost_usd
        .map_or_else(|| "$ unknown".into(), |cost| format!("${cost:.4}"));
    format!("{calls} · {dollars}")
}

fn missing_selection_label(config: &BatchScanConfig) -> &'static str {
    match (&config.prior_run_id, &config.prior_catalogue) {
        (Some(_), _) => "unavailable",
        (_, ViewDataState::Ready(Err(_))) => "history unavailable",
        (_, ViewDataState::Ready(Ok(catalogue))) if catalogue.run_ids.is_empty() => {
            "no completed scans"
        }
        (_, ViewDataState::Ready(_)) => "select explicitly",
        _ => "loading history",
    }
}

pub(crate) fn study_resource_lines(config: &BatchScanConfig) -> Vec<String> {
    if config.review_plan.is_some() {
        return crate::ui_view_models::review_study::review_budget_lines(config);
    }
    if let Some(lines) = native_work::lines(config) {
        return lines;
    }
    let mut lines = history_lines(config);
    lines.extend(selected_resource_lines(config));
    lines
}

fn history_lines(config: &BatchScanConfig) -> Vec<String> {
    match &config.prior_catalogue {
        ViewDataState::Ready(Ok(catalogue)) if catalogue.history_limit_reached => vec![format!("Usage choices cover the most recent {} run records. Older evidence named by a saved plan remains readable.", kuzushi_core::capabilities::campaign::SCAN_USAGE_HISTORY_LIMIT)],
        ViewDataState::Ready(Ok(_)) => Vec::new(),
        ViewDataState::Ready(Err(error)) => vec![format!("Usage history unavailable: {error}. Press r to refresh; the chosen baseline remains selected.")],
        _ => vec!["Loading recent usage choices in the background. You can keep editing or cancel.".into()],
    }
}

fn selected_resource_lines(config: &BatchScanConfig) -> Vec<String> {
    if let Some(lines) = campaign_resources::lines(config) {
        return lines;
    }
    if let Some(draft) = config.study.scope_draft.as_ref() {
        return scope_resource_lines(config, draft);
    }
    if !config.study.matrix.cases.is_empty() {
        return matrix_resource_lines(config);
    }
    historical_single_resource_lines(config)
}

fn scope_resource_lines(config: &BatchScanConfig, draft: &ScopeStudyDraft) -> Vec<String> {
    let jobs = draft.job_count();
    let mut lines = vec![format!(
        "{} selected boundaries · {jobs} fixed discovery jobs · {} maximum starts per job ({} starts).",
        draft.cases.len(), config.study.max_job_attempts,
        jobs.saturating_mul(config.study.max_job_attempts)
    )];
    lines.extend([
        "Each boundary needs matching historical source, context, engine, model and runtime evidence. One boundary's usage cannot estimate its siblings.".into(),
        "Provider requests: not estimated for this scope set. Internal turns and retries consume the shared allowance.".into(),
        "Dollar estimate: unavailable. No dollar ceiling enforced.".into(),
    ]);
    lines.extend(uncalibrated_capacity_lines(config));
    lines
}

fn uncalibrated_capacity_lines(config: &BatchScanConfig) -> Vec<String> {
    proposed_scan_calls(config).map_or_else(
        || vec!["Set Total calls and Protected review to compare available capacity.".into()],
        |available| vec![format!("Under the proposed limits: {available} context/scan calls available after commitments and protected review."),
            "This is spending capacity, not an estimate that all jobs will finish. Approve any new allowance separately.".into()],
    )
}

fn historical_single_resource_lines(config: &BatchScanConfig) -> Vec<String> {
    let Some(prior) = config.selected_prior() else {
        if let Some(run) = &config.prior_run_id {
            return vec![format!("Recorded usage evidence {run} is unavailable. Refresh or select another completed scan; no projection.")];
        }
        return vec!["Provider requests: not estimated. Select a completed scan as usage evidence.".into(),
            "One job can make several requests. Internal turns and retries consume the shared allowance.".into(),
            "Dollar estimate: unavailable. Unknown charges are never zero.".into()];
    };
    let mut lines = Vec::new();
    let evidence = match &prior.evidence {
        ViewDataState::Ready(Ok(evidence)) => evidence,
        ViewDataState::Ready(Err(error)) => {
            lines.push(
                "Historical usage unavailable. Press r to refresh or Enter to choose another scan."
                    .into(),
            );
            lines.push(format!("Selected usage evidence: {}", prior.run_id));
            lines.push(format!("Details: {error}. No projection."));
            return lines;
        }
        _ => {
            return vec![format!(
            "Loading historical usage for {}. No projection yet; spending limits remain unchanged.",
            prior.run_id
        )]
        }
    };
    lines.extend(historical_lines(evidence));
    match config.resource_projection() {
        Ok(projection) => lines.extend(projection_lines(config, &projection)),
        Err(reason) => lines.push(format!(
            "Projection withheld: {reason}. Recorded usage remains historical."
        )),
    }
    lines.push(format!("Usage evidence: {}", prior.run_id));
    lines.extend(identity_lines(evidence));
    lines
}

fn matrix_resource_lines(config: &BatchScanConfig) -> Vec<String> {
    let mut lines = vec![format!("{} fixed discovery jobs across {} explicit contexts.",config.study.matrix.planned_jobs(),config.study.matrix.cases.len()),
        "Cases can consume different amounts. Each fresh pass can make multiple requests; internal turns and retries share the investigation allowance.".into(),
        "No calibrated whole-matrix estimate. A historical pass is usage evidence for its own conditions only.".into(),
        "Dollar consumption: unknown without complete price receipts. A dollar ceiling is not enforced; approve call limits and protected review explicitly.".into()];
    if let Some(evidence) = config
        .selected_prior()
        .and_then(|prior| match &prior.evidence {
            ViewDataState::Ready(Ok(evidence)) => Some(evidence),
            _ => None,
        })
    {
        lines.extend(historical_lines(evidence));
    }
    lines.extend(uncalibrated_capacity_lines(config));
    lines
}

fn historical_lines(evidence: &ScanResourceEvidence) -> Vec<String> {
    let mut lines = Vec::new();
    match &evidence.provider_usage {
        Some(usage) => lines.extend([format!(
            "Observed: {} provider requests · {} unresolved. Includes internal turns and retries.",
            usage.committed_calls, usage.unresolved_calls
        )]),
        None => lines.push(
            "Historical provider-request accounting unavailable. No zero is inferred.".into(),
        ),
    }
    lines.push(evidence.cost_usd.map_or_else(
        || "Historical dollar cost: unavailable.".into(),
        |cost| format!("Historical dollar cost: ${cost:.4}."),
    ));
    lines
}

fn identity_lines(evidence: &ScanResourceEvidence) -> Vec<String> {
    evidence
        .provider_usage
        .as_ref()
        .map_or_else(Vec::new, |usage| {
            vec![
                format!(
                    "Recorded model: {}",
                    crate::app::display_model_selector(&usage.model)
                ),
                format!("Recorded source: {}", usage.source_identity),
            ]
        })
}

fn projection_lines(config: &BatchScanConfig, projection: &StudyResourceProjection) -> Vec<String> {
    let mut lines = vec![
        "Recorded source, context, scan options, model and runtime match this frozen draft.".into(),
    ];
    lines.push(projection.provider_calls.map_or_else(|| "Provider-request projection unavailable.".into(), |calls|
        format!("Full plan estimate: {calls} provider requests across {} passes and {} maximum starts per job ({} starts).",config.trials, config.study.max_job_attempts,projection.starts)));
    lines.push(projection.cost_usd.map_or_else(
        || "Dollar estimate: unavailable. No dollar ceiling enforced.".into(),
        |cost| format!("Historical dollar projection: ${cost:.4}. Charges remain uncertain."),
    ));
    lines.extend(capacity_lines(config, projection.provider_calls));
    lines.extend(["One historical scan is limited evidence. Actual turns, repairs, retries and usage may differ; there is no estimated upper bound.".into(),
        "The projection covers the full planned workload. Consumed attempts remain consumed. Review and Report keep their protected calls.".into()]);
    lines
}

fn capacity_lines(config: &BatchScanConfig, projected: Option<u64>) -> Vec<String> {
    let Some(calls) = projected else {
        return Vec::new();
    };
    let Some(available) = proposed_scan_calls(config) else {
        return vec!["Set Total calls and Protected review to compare available capacity.".into()];
    };
    let mut lines = vec![format!("Under the proposed limits: {available} context/scan calls available after commitments and protected review.")];
    if calls > available {
        lines.push(format!("The estimate exceeds available calls by {}. This plan may stop before all passes finish. Revise passes, attempts or allowance explicitly.",calls-available));
    }
    lines
}

fn proposed_scan_calls(config: &BatchScanConfig) -> Option<u64> {
    let total = u64::try_from(config.study.max_provider_calls?).ok()?;
    let review = u64::try_from(config.study.protected_review_calls?).ok()?;
    let (committed, reviewed) = config.study.allowance.as_ref().map_or((0, 0), |usage| {
        (
            u64::from(usage.committed_calls),
            u64::from(usage.review_calls),
        )
    });
    Some(
        total
            .saturating_sub(committed)
            .saturating_sub(review.saturating_sub(reviewed)),
    )
}
