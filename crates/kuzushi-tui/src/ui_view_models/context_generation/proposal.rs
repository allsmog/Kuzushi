use super::*;

pub(super) fn summary(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    let mut lines = vec![
        generation.action(config).into(),
        "Experimental · one proposal job · one worker · one model request".into(),
        format!("Model: {}", generation.context_input["model"].as_str().unwrap_or("missing")),
        format!("Goal: {}", generation.context_input["goal"].as_str().unwrap_or("missing")),
        format!("Phase: {}", generation.context_input["phase"].as_str().unwrap_or("option proposals and notes only")),
        "No tools, delegation, output repair, exploit work, reproducers or vulnerability patches.".into(),
        format!("Total calls: {}", limit(config.study.max_provider_calls)),
        format!("Protected review: {}", limit(config.study.protected_review_calls)),
        "Potentially billable transport retries share the approved allowance. Dollar consumption is uncertain; requested output tokens may not be enforced.".into(),
        "Proposal approval permits this fixed job only. Inspect the result before any action; actions do not inherit its spending approval.".into(),
    ];
    lines.splice(2..2, result_lines(generation));
    lines.extend(generation.result_error.iter().map(|error| format!("Proposal result unavailable: {error}. Enter inspects the original job; no repair request was made.")));
    lines.extend(config.notice.iter().cloned());
    lines.extend(generation_plan_lines(config));
    lines.extend(allowance_status_lines(config));
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn result_lines(generation: &StudyContextGeneration) -> Vec<String> {
    let Some(result) = &generation.generated_proposal else {
        return Vec::new();
    };
    let mut lines = vec![format!(
        "Draft: {}",
        result.proposal["summary"].as_str().unwrap_or("unavailable")
    )];
    for change in result.proposal["changes"].as_array().into_iter().flatten() {
        lines.push(change_line(change));
    }
    for question in result.proposal["unsupported"]
        .as_array()
        .into_iter()
        .flatten()
    {
        lines.push(format!(
            "Open question: {}",
            question.as_str().unwrap_or("unavailable")
        ));
    }
    lines
}

fn change_line(change: &serde_json::Value) -> String {
    match change["kind"].as_str() {
        Some("note") => format!("Note: {}", change["text"].as_str().unwrap_or("unavailable")),
        Some("run_tool") => format!(
            "Proposed action: {} · input {}",
            change["tool"].as_str().unwrap_or("unavailable"),
            change["input"]
        ),
        Some("set_option") => format!(
            "Proposed option: {}.{} = {} · global {}",
            change["tool"].as_str().unwrap_or("unavailable"),
            change["name"].as_str().unwrap_or("unavailable"),
            change["value"],
            change["global"]
        ),
        _ => "Unknown proposed change; inspect the original job".into(),
    }
}

pub(super) fn receipt_lines(
    receipt: &kuzushi_core::capabilities::campaign::ContextStudyReceipt,
) -> Vec<String> {
    vec![
        format!("Source at preparation: {}", receipt.source_identity),
        format!("Plan: {}", receipt.campaign_id),
        format!("Plan digest: {}", receipt.plan_sha256),
        format!(
            "Reasoning: {} · requested output: {} tokens",
            receipt.input["thinkingLevel"]
                .as_str()
                .unwrap_or("recorded runtime setting"),
            receipt.input["maxOutputTokens"]
        ),
        "Model input: bounded goal and Core capability metadata. No source contents are supplied."
            .into(),
        "Tab shows exact options. Applying actions checks source and capabilities again.".into(),
    ]
}
