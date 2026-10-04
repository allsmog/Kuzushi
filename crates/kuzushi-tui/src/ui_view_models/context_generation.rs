use super::study_config::{allowance_status_lines, study_config_area};
use crate::app::ShellApp;
use crate::renderer::shared::text::wrap_text;
use ratatui::layout::Rect;

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
    if generation.show_options {
        return option_lines(&generation.options, width);
    }
    generation_summary(config, width)
}

fn generation_summary(config: &crate::app::BatchScanConfig, width: usize) -> Vec<String> {
    let generation = config.context_generation.as_ref().unwrap();
    let mut lines = vec![
        generation.action(config).into(),
        workload_line(generation.preparation_count()),
        "Source-only generation creates a new draft. Inspect and select it before scanning.".into(),
    ];
    if let Some(error) = &generation.result_error {
        lines.extend([
            format!("Context result unavailable: {error}"),
            "Enter opens the recorded job outcome. A replacement draft needs separate approval; existing spending remains recorded.".into(),
        ]);
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
    if let Some(receipt) = &generation.receipt {
        lines.extend(receipt_lines(receipt));
    } else {
        lines.push("Enter freezes source, selected model and bounded generation options. Preparing the draft makes no model request.".into());
    }
    lines.extend(generation_preparation_lines(generation));
    lines.extend(allowance_status_lines(config));
    lines.push("n opens a new draft for separate approval. Previous spending and consumed attempts remain recorded.".into());
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn generation_preparation_lines(generation: &crate::app::StudyContextGeneration) -> Vec<String> {
    let preparations = generation
        .receipt
        .as_ref()
        .map(|receipt| serde_json::to_value(&receipt.preparation_jobs).unwrap())
        .unwrap_or_else(|| generation.preparation_jobs.clone());
    preparation_lines(&preparations)
}

fn receipt_lines(
    receipt: &kuzushi_core::capabilities::campaign::ContextStudyReceipt,
) -> Vec<String> {
    vec![
        format!("Model: {}", receipt.model),
        format!("Source: {}", receipt.source_identity),
        format!("Plan: {}", receipt.campaign_id),
        format!("Plan digest: {}", receipt.plan_sha256),
        format!(
            "Methodology: {} · output limit: {} tokens",
            receipt.input["methodology"]
                .as_str()
                .unwrap_or("unavailable"),
            receipt.input["maxOutputTokens"]
        ),
        format!(
            "Source excerpts: at most {} bytes; repository coverage may be partial.",
            receipt.input["maxSourceBytes"]
        ),
        "Tab shows every exact generation option.".into(),
    ]
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
