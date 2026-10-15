use crate::app::BatchScanConfig;
use crate::renderer::shared::text::wrap_text;
mod source_evidence;

pub(crate) fn review_study_lines(
    config: &BatchScanConfig,
    model: Option<&str>,
    width: usize,
) -> Vec<String> {
    let mut lines = review_attention_lines(config);
    if config
        .review_plan
        .as_ref()
        .is_some_and(|review| review.show_evidence)
    {
        lines.extend(source_evidence::details(config));
        lines.extend(review_budget_lines(config));
        return wrap_review_document(lines, width, true);
    }
    lines.extend(review_summary(config, model));
    lines.extend(review_budget_lines(config));
    lines.extend(source_evidence::summary(config));
    if let Some(notice) = config
        .notice
        .as_ref()
        .filter(|_| config.study.preparation_error.is_none())
    {
        lines.push(notice.clone());
    }
    lines.extend(review_selection_lines(config));
    wrap_review_document(lines, width, false)
}

fn wrap_review_document(lines: Vec<String>, width: usize, source: bool) -> Vec<String> {
    lines
        .into_iter()
        .flat_map(|line| {
            if source && line.contains(" │ ") {
                super::source_review::wrap_code_line(&line, width)
            } else {
                wrap_text(&line, width.max(1))
            }
        })
        .collect()
}

fn review_attention_lines(config: &BatchScanConfig) -> Vec<String> {
    config.study.preparation_error.as_ref().map_or_else(Vec::new,|error|vec![format!("Review preparation or approval failed: {error}\nEsc dismisses this error and preserves your draft. No review job started.")])
}

fn review_summary(config: &BatchScanConfig, model: Option<&str>) -> Vec<String> {
    let receipt = config.study.review_receipt.as_ref();
    let input = receipt
        .map(|receipt| &receipt.input)
        .or_else(|| config.review_plan.as_ref().map(|review| &review.input));
    let model = receipt
        .map(|receipt| receipt.model.as_str())
        .or_else(|| input.and_then(|input| input["model"].as_str()))
        .or(model)
        .unwrap_or("not selected; M chooses a model");
    let strategy = input
        .and_then(|input| input["strategy"].as_str())
        .unwrap_or("resolved during preparation; bulk review keeps deep analysis");
    vec![
        format!("Next: {}", config.study.next_action()),
        "One job · one worker · one attempt. No automatic follow-up work.".into(),
        format!("Model: {model}"),
        format!("Review strategy: {strategy}"),
        format!("Context: {}", context_label(input)),
        format!(
            "Repository: {}",
            config
                .target
                .file_name()
                .unwrap_or(config.target.as_os_str())
                .to_string_lossy()
        ),
    ]
}

pub(crate) fn review_budget_lines(config: &BatchScanConfig) -> Vec<String> {
    let study = &config.study;
    let mut lines = vec![
        format!(
            "Total calls: {} · protected Review: {}",
            limit(study.max_provider_calls),
            limit(study.protected_review_calls)
        ),
        "Internal turns and retries count against the shared investigation allowance.".into(),
    ];
    if let Some(allowance) = &study.allowance {
        lines.push(format!(
            "Already committed: {} · unresolved: {} · last approved total: {}",
            allowance.committed_calls,
            allowance.unresolved_calls,
            allowance.limits.max_provider_calls
        ));
        lines.push(format!("Review may use up to {} remaining total calls; {} are protected from other phases. Revisit approval after changing limits.",allowance.remaining_calls(),allowance.protected_review_remaining()));
    }
    lines.push("Consumption estimate: uncalibrated. Dollar charges are uncertain; no dollar ceiling is enforced.".into());
    lines
}

fn limit(value: Option<usize>) -> String {
    value.map_or_else(|| "set explicitly".into(), |value| value.to_string())
}

fn context_label(input: Option<&serde_json::Value>) -> String {
    match input.and_then(|input| input.get("threatModelRef")) {
        Some(value) if value.is_null() => "explicitly omitted".into(),
        Some(value) => value.to_string(),
        None => "accepted Map revision; c explicitly omits context".into(),
    }
}

fn review_selection_lines(config: &BatchScanConfig) -> Vec<String> {
    let Some(review) = config.review_plan.as_ref() else {
        return Vec::new();
    };
    let input = config
        .study
        .review_receipt
        .as_ref()
        .map_or(&review.input, |receipt| &receipt.input);
    if review.show_options {
        return vec![
            "Exact review input · Tab returns to observations".into(),
            serde_json::to_string_pretty(input)
                .unwrap_or_else(|error| format!("Options unreadable: {error}")),
        ];
    }
    let Some(receipt) = config.study.review_receipt.as_ref() else {
        return vec![
            "Selection is not frozen. Enter prepares exact pending observations before approval."
                .into(),
        ];
    };
    let mut lines = vec![
        format!("Frozen observations: {}", receipt.findings.len()),
        format!("Planned review source: {}", receipt.source_identity),
        format!("Plan digest: {}", receipt.plan_sha256),
    ];
    for finding in &receipt.findings {
        lines.push(format!(
            "generation:{} · {} · {}:{} · observed in {}",
            finding.id.unwrap_or_default(),
            finding.title,
            finding.file_path,
            finding.start_line,
            finding.scan_id.as_deref().unwrap_or("unrecorded run")
        ));
        lines.extend(observation_source_lines(receipt, finding.id));
    }
    lines
}

fn observation_source_lines(
    receipt: &kuzushi_core::capabilities::campaign::ReviewStudyReceipt,
    generation: Option<i64>,
) -> Vec<String> {
    let Some(source) = receipt
        .observation_sources
        .iter()
        .find(|source| Some(source.generation_id) == generation)
    else {
        return vec!["Observation commit was not recorded in this draft. Inspect the original run before applying a verdict.".into()];
    };
    let Some(git) = &source.recorded_git else {
        let message = if source.metadata_unavailable {
            "Observation commit metadata is unavailable."
        } else {
            "Observation commit was not recorded."
        };
        return vec![message.into()];
    };
    recorded_commit_lines(receipt, git)
}

fn recorded_commit_lines(
    receipt: &kuzushi_core::capabilities::campaign::ReviewStudyReceipt,
    git: &kuzushi_core::run_artifacts::RunTargetGitMetadata,
) -> Vec<String> {
    let state = if git.dirty { "dirty" } else { "clean" };
    let mut lines = vec![format!(
        "Recorded observation commit: {} · {state}",
        git.sha
    )];
    let planned = receipt
        .source_identity
        .strip_prefix("git:")
        .and_then(|identity| identity.split(';').next());
    if planned.is_some_and(|sha| sha != git.sha) {
        lines.push("Different commit from this planned review. Compare source evidence before applying the verdict; this plan does not establish a fix.".into());
    }
    lines
}

pub(crate) fn review_controls(config: &BatchScanConfig) -> &'static str {
    if config
        .review_plan
        .as_ref()
        .is_some_and(|review| review.show_evidence)
    {
        return "PgUp/Dn Home/End · f files\nv plan · Tab input · Esc back";
    }
    "t total · r protect · M model\nc context · s strategy · e source\nf files · v read · Tab input · n new\nPgUp/Dn Home/End · Enter next · Esc"
}

pub(crate) fn review_body_height(config: &BatchScanConfig, height: u16) -> u16 {
    height.saturating_sub(review_controls(config).lines().count() as u16 + 3)
}

#[cfg(test)]
mod tests;
