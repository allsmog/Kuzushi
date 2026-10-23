//! Put the work and spending decision before the evidence and frozen receipt.
use super::*;
use crate::renderer::shared::text::wrap_document_lines;
use ratatui::text::Line;
use serde_json::Value;

pub(super) fn summary(
    app: &ShellApp,
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    let input = recorded_input(generation);
    let mut lines = overview(app, config, generation, input, width);
    lines.extend(generation.result_error.iter().map(|error| {
        format!("Context result unavailable: {error}. Enter reads the recorded outcome. A replacement needs separate approval.")
    }));
    lines.extend(config.notice.iter().cloned());
    lines.extend(source_lines(app, generation, input));
    lines.extend(execution_lines());
    lines.extend(brief_guidance_lines(config, generation));
    lines.extend(generation_plan_lines(config));
    lines.extend(allowance_status_lines(config));
    wrap_document_lines(
        lines.into_iter().map(Line::raw).collect(),
        width.clamp(1, u16::MAX as usize) as u16,
    )
    .into_iter()
    .map(|line| line.to_string())
    .collect()
}

fn overview(
    app: &ShellApp,
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    input: &Value,
    width: usize,
) -> Vec<String> {
    let count = input["sourcePaths"].as_array().map_or(0, Vec::len);
    vec![
        super::super::study_config::study_allowance_summary(config, width),
        format!("{count} files · 1 job · 1 attempt"),
        format!(
            "Calls: {} max · {} for Review",
            config
                .study
                .max_provider_calls
                .map_or("unset".into(), |n| n.to_string()),
            config
                .study
                .protected_review_calls
                .map_or("unset".into(), |n| n.to_string())
        ),
        "Dollar estimate unavailable".into(),
        model_summary(app, generation),
        generation.action(config).into(),
    ]
}

fn recorded_input(generation: &StudyContextGeneration) -> &Value {
    generation
        .receipt
        .as_ref()
        .map_or(&generation.context_input, |receipt| &receipt.input)
}

fn model_summary(app: &ShellApp, generation: &StudyContextGeneration) -> String {
    if let Some(receipt) = &generation.receipt {
        return model_line(
            &receipt.model,
            receipt.input["thinkingLevel"].as_str().unwrap_or("runtime"),
        );
    }
    model_line(
        generation.context_input["model"]
            .as_str()
            .or(app.config().model.as_deref())
            .unwrap_or("model unset"),
        generation.context_input["thinkingLevel"]
            .as_str()
            .or(app.config().runtime.thinking_level.as_deref())
            .unwrap_or("runtime"),
    )
}

fn model_line(model: &str, reasoning: &str) -> String {
    format!(
        "{} · {reasoning}",
        crate::app::display_model_selector(model)
    )
}

fn source_lines(app: &ShellApp, generation: &StudyContextGeneration, input: &Value) -> Vec<String> {
    let paths = input["sourcePaths"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut lines = vec![
        String::new(),
        inherited_label(app, input),
        format!("{} exact evidence files (quoted):", paths.len()),
    ];
    lines.extend(paths.iter().map(|path| format!("  {path}")));
    lines.push("Source excerpts use these files. The inherited architecture is separate.".into());
    let inventory = generation
        .receipt
        .as_ref()
        .and_then(|receipt| receipt.source_inventory.as_ref());
    if generation.receipt.is_some() {
        lines.extend(super::super::evidence_inventory::receipt_lines(inventory));
    } else {
        lines.push("Inventory is checked during preparation. Selected files must be recorded members; enumeration may be partial.".into());
    }
    lines.push(format!(
        "Inherited revision: {}",
        input
            .pointer("/inheritedContextRef/revisionId")
            .and_then(Value::as_str)
            .unwrap_or("unavailable")
    ));
    lines
}

fn inherited_label(app: &ShellApp, input: &Value) -> String {
    let Ok(reference) = serde_json::from_value::<kuzushi_core::ThreatModelRef>(
        input["inheritedContextRef"].clone(),
    ) else {
        return "Inherits: unavailable; inspect exact options".into();
    };
    let label = super::super::study_context::context_catalog(app)
        .rows
        .into_iter()
        .find(|row| row.reference.as_ref() == Some(&reference))
        .map(|row| row.label)
        .unwrap_or_else(|| "recorded architecture; exact revision below".into());
    format!("Inherits: {label}")
}

fn execution_lines() -> Vec<String> {
    vec![
        String::new(),
        "One full architecture draft: components, data flows, trust boundaries and open questions.".into(),
        "One worker and one synthesis request. Tools and output repair are disabled.".into(),
        "The draft stays inactive for review. Prepare, approve the allowance, then launch.".into(),
        "Review calls stay protected. Internal turns and retries share the call limit. No dollar ceiling is enforced.".into(),
        "Source limits may omit material; the result records supplied excerpts and omissions.".into(),
        "Scanning needs a separate approved plan. Back returns to the diagram.".into(),
    ]
}

#[cfg(test)]
mod tests;
