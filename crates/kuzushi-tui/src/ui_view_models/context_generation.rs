use super::study_config::{allowance_status_lines, study_config_area};
use crate::app::ShellApp;
use crate::renderer::shared::text::wrap_text;
use ratatui::layout::Rect;
mod diagnosis;

pub(crate) fn generation_body(columns: u16, rows: u16) -> Rect {
    let area = study_config_area(columns, rows);
    Rect::new(
        area.x + 2,
        area.y + 2,
        area.width.saturating_sub(4),
        area.height.saturating_sub(5),
    )
}

pub(crate) fn generation_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let Some(config) = app.router.campaign().batch_scan_config.as_ref() else {
        return Vec::new();
    };
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    if generation.show_rejected {
        return diagnosis::lines(generation.rejected_output.as_ref(), width);
    }
    if generation.show_options {
        return option_lines(&generation.options, width);
    }
    let mut lines = generation_summary(config, width);
    if generation.is_scope_proposal() && generation.receipt.is_none() {
        let model = format!(
            "Selected model: {} · reasoning: {}. M chooses a model.",
            crate::app::display_model_selector(
                app.config().model.as_deref().unwrap_or("select explicitly")
            ),
            app.config()
                .runtime
                .thinking_level
                .as_deref()
                .unwrap_or("selected runtime default")
        );
        let mut header = wrap_text(&model, width.max(1));
        header.append(&mut lines);
        return header;
    }
    lines
}

fn generation_summary(config: &crate::app::BatchScanConfig, width: usize) -> Vec<String> {
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    if generation.is_scope_proposal() {
        return scope_generation_summary(config, width);
    }
    context_generation_summary(config, width)
}

fn context_generation_summary(config: &crate::app::BatchScanConfig, width: usize) -> Vec<String> {
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    let mut lines = context_result_lines(config);
    lines.push(
        diagnosis::retention_label(generation.receipt.as_ref(), &generation.context_input).into(),
    );
    if generation.rejected_available {
        lines.push("d inspects retained rejected output locally. Inspection does not accept context or start work.".into());
    }
    if let Some(notice) = &config.notice {
        lines.extend([String::new(), notice.clone()]);
    }
    lines.extend([
        String::new(),
        format!("Total calls: {}", limit(config.study.max_provider_calls)),
        format!("Protected review: {}", limit(config.study.protected_review_calls)),
        "Context and scans share these limits. Internal turns and retries consume calls; Review and Report keep their reserved calls.".into(),
        "Dollar estimate: unavailable. No dollar ceiling is enforced.".into(),
    ]);
    lines.extend(generation_plan_lines(config));
    lines.extend(generation_preparation_lines(config));
    lines.extend(allowance_status_lines(config));
    lines.push("n opens a new draft for separate approval. Previous spending and consumed attempts remain recorded.".into());
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn context_result_lines(config: &crate::app::BatchScanConfig) -> Vec<String> {
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    let mut lines = vec![
        generation.action(config).into(),
        workload_line(generation.preparation_count()),
        result_guidance(
            generation.generated.is_some(),
            generation.result_error.is_some(),
        )
        .into(),
    ];
    if let Some(error) = &generation.result_error {
        lines.extend([
            format!("Context result unavailable: {error}"),
            "Enter opens the recorded job outcome. A replacement draft needs separate approval; existing spending remains recorded.".into(),
        ]);
    }
    if let Some(Err(error)) = &generation.rejected_output {
        lines.push(format!(
            "Retained diagnostic unavailable: {error}. d inspects this failure."
        ));
    }
    lines
}

fn result_guidance(has_result: bool, result_unavailable: bool) -> &'static str {
    if result_unavailable {
        return "The context result could not be recovered. Inspect the job before deciding on a new draft.";
    }
    if has_result {
        return "Enter inspects the exact revision. m opens its recorded Map for review and explicit acceptance before scanning.";
    }
    "Source-only generation creates a new draft. Inspect and select it before scanning."
}

fn generation_preparation_lines(config: &crate::app::BatchScanConfig) -> Vec<String> {
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    let preparations = match generation.receipt.as_ref() {
        Some(receipt) => match serde_json::to_value(&receipt.preparation_jobs) {
            Ok(jobs) => jobs,
            Err(error) => return vec![format!("Preparation jobs unavailable: {error}")],
        },
        None => generation.preparation_jobs.clone(),
    };
    preparation_lines(&preparations)
}

fn generation_plan_lines(config: &crate::app::BatchScanConfig) -> Vec<String> {
    config.context_generation.as_ref()
        .and_then(|generation| generation.receipt.as_ref())
        .map(receipt_lines)
        .unwrap_or_else(|| vec!["Enter freezes source, selected model and bounded generation options. Preparing the draft makes no model request.".into()])
}

fn receipt_lines(
    receipt: &kuzushi_core::capabilities::campaign::ContextStudyReceipt,
) -> Vec<String> {
    if receipt.generation_tool == "pack:suggest-scopes" {
        return scope_receipt_lines(receipt);
    }
    vec![
        format!("Model: {}", crate::app::display_model_selector(&receipt.model)),
        format!("Source: {}", receipt.source_identity),
        format!("Plan: {}", receipt.campaign_id),
        format!("Plan digest: {}", receipt.plan_sha256),
        format!(
            "Methodology: {} · requested output: {} tokens",
            receipt.input["methodology"]
                .as_str()
                .unwrap_or("unavailable"),
            receipt.input["maxOutputTokens"]
        ),
        "Output enforcement depends on the model adapter. The approved allowance bounds provider-request counts.".into(),
        format!(
            "Source excerpts: at most {} bytes; repository coverage may be partial.",
            receipt.input["maxSourceBytes"]
        ),
        "Tab shows every exact generation option.".into(),
    ]
}

fn scope_generation_summary(config: &crate::app::BatchScanConfig, width: usize) -> Vec<String> {
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    let mut lines = vec![generation.action(config).into(),
        "One scope proposal job · one worker · one attempt".into(),
        "At most eight primary scopes and optional shared context. No tools, recursive subdivision, output repair or scan jobs.".into(),
        "Enter reviews the fixed plan, then the shared allowance. A completed result opens scope review; boundary acceptance remains separate.".into(),
        format!("Architecture context: {}", if generation.context_input["threatModelRef"].is_null() { "explicitly omitted" } else { "exact accepted Map revision" })];
    if let Some(error) = &generation.result_error {
        lines.push(format!("Scope outcome unavailable: {error}. Enter opens the recorded job; n prepares a separately approved replacement."));
    }
    if let Some(notice) = &config.notice {
        lines.extend([String::new(), notice.clone()]);
    }
    lines.extend([format!("Total calls: {}",limit(config.study.max_provider_calls)),format!("Protected review: {}",limit(config.study.protected_review_calls)),
        "Scope planning, context, scans and review share accounting. Internal turns and retries consume calls; existing commitments remain.".into(),
        "Dollar estimate: unavailable. No dollar ceiling is enforced.".into()]);
    lines.extend(generation_plan_lines(config));
    lines.extend(allowance_status_lines(config));
    lines.push("A new draft requires its own approval. Previous spending and consumed attempts remain recorded.".into());
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn scope_receipt_lines(
    receipt: &kuzushi_core::capabilities::campaign::ContextStudyReceipt,
) -> Vec<String> {
    vec![format!("Model: {}",crate::app::display_model_selector(&receipt.model)),format!("Source: {}",receipt.source_identity),
        format!("Plan: {}",receipt.campaign_id),format!("Plan digest: {}",receipt.plan_sha256),
        format!("Requested output: {} tokens. Subscription OAuth may not enforce this ceiling.",receipt.input["maxOutputTokens"]),
        "Model data: at most 64 KiB, using the saved inventory and bounded architecture. Omitted rows and incomplete inventory are disclosed in the resulting scope draft.".into(),
        "Tab shows every exact proposal option. M chooses a model for a new draft.".into()]
}

pub(crate) fn format_options(input: &serde_json::Value) -> Vec<String> {
    match serde_json::to_string_pretty(input) {
        Ok(text) => text.lines().map(str::to_string).collect(),
        Err(error) => vec![format!("Options unavailable: {error}")],
    }
}

fn option_lines(options: &[String], width: usize) -> Vec<String> {
    let mut lines = vec![
        "EXACT GENERATION OPTIONS".into(),
        "Tab returns to the plan and allowance.".into(),
    ];
    if options.is_empty() {
        lines.push("Prepare a context draft first.".into());
    }
    lines.extend_from_slice(options);
    lines
        .into_iter()
        .flat_map(|line| super::study_context::context_wrap(&line, width.max(1)))
        .collect()
}

fn limit(value: Option<usize>) -> String {
    value.map_or_else(|| "set explicitly".into(), |value| value.to_string())
}

fn workload_line(count: usize) -> String {
    if count == 0 {
        return "One repository-wide context job · one worker · one attempt".into();
    }
    format!(
        "{} fixed jobs: {count} preparation + one context · one worker · one attempt per job",
        count + 1
    )
}

fn preparation_lines(jobs: &serde_json::Value) -> Vec<String> {
    jobs.as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, job)| {
            format!(
                "Before generation {}: {} (deterministic)",
                index + 1,
                job["tool"].as_str().unwrap_or("unavailable")
            )
        })
        .collect()
}
