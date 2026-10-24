use super::*;
use kuzushi_core::capabilities::campaign::GeneratedStudyContext;
use std::sync::Arc;

const PREVIEW_CHAR_LIMIT: usize = 8192;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GeneratedContextPreview {
    reference: kuzushi_core::ThreatModelRef,
    title: String,
    attention_action: Option<&'static str>,
    lines: Arc<Vec<String>>,
}

pub(crate) fn context_preview(output: GeneratedStudyContext) -> GeneratedContextPreview {
    let title = output
        .document
        .get("title")
        .and_then(serde_json::Value::as_str);
    let text = super::super::study_context::context_summary(&output.document)
        .into_iter()
        .skip(usize::from(title.is_some()))
        .collect::<Vec<_>>()
        .join("\n");
    let prefix = text.chars().take(PREVIEW_CHAR_LIMIT).collect::<String>();
    let mut lines = prefix.lines().map(str::to_owned).collect::<Vec<_>>();
    if text.chars().count() > PREVIEW_CHAR_LIMIT {
        lines.push(format!("Preview limited to {PREVIEW_CHAR_LIMIT} characters. Enter reads the complete saved revision."));
    }
    lines.push("Generated context claims need human review. This preview does not establish finding verdicts or complete coverage.".into());
    lines.push(format!(
        "Saved source content: {}",
        output
            .document
            .pointer("/provenance/treeHash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unrecorded")
    ));
    GeneratedContextPreview {
        reference: output.reference,
        title: preview_title(title),
        attention_action: attention_action(&output.document),
        lines: Arc::new(lines),
    }
}

fn attention_action(document: &serde_json::Value) -> Option<&'static str> {
    match document
        .pointer("/verification/verdict")
        .and_then(serde_json::Value::as_str)
    {
        Some("partial") => Some("Inspect partial context"),
        Some("failed") => Some("Inspect context with failed checks"),
        Some("stale") => Some("Inspect stale context"),
        _ => None,
    }
}

fn preview_title(title: Option<&str>) -> String {
    let mut chars = title.unwrap_or("Saved context").chars();
    let mut title = chars.by_ref().take(256).collect::<String>();
    if chars.next().is_some() {
        title.push('…');
    }
    title
}

pub(super) fn overview(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    let action = selected_preview(generation)
        .and_then(|preview| preview.attention_action)
        .unwrap_or_else(|| generation.action(config));
    let mut lines = vec![action.into()];
    append_outcome(&mut lines, config, generation);
    append_diagnostic_notice(&mut lines, generation);
    lines.extend(config.notice.iter().cloned());
    lines.extend(result_allowance_lines(config));
    lines.push("p reads the frozen plan · Tab exact generation options · n new draft with separate approval".into());
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn selected_preview(generation: &StudyContextGeneration) -> Option<&GeneratedContextPreview> {
    generation
        .generated_preview
        .as_ref()
        .filter(|preview| Some(&preview.reference) == generation.generated.as_ref())
}

fn append_diagnostic_notice(lines: &mut Vec<String>, generation: &StudyContextGeneration) {
    if let Some(Err(error)) = &generation.rejected_output {
        lines.push(format!(
            "Retained diagnostic unavailable: {error}. d inspects this failure."
        ));
    }
}

fn append_outcome(
    lines: &mut Vec<String>,
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
) {
    if let Some(error) = &generation.result_error {
        lines.push(format!("Context result unavailable: {error}"));
        lines.push("Enter opens the recorded job outcome. A replacement draft needs separate approval; existing spending remains recorded.".into());
        return;
    }
    if let Some(preview) = selected_preview(generation) {
        lines.push(preview.title.clone());
        lines.extend(usage_lines(config));
        lines.push("Enter inspects the exact revision. m opens its recorded Map for review and explicit acceptance before scanning.".into());
        lines.extend(preview.lines.iter().cloned());
    } else {
        lines.push("Preview unavailable. Enter reads the exact saved revision; another context is never substituted.".into());
    }
}

fn usage_lines(config: &BatchScanConfig) -> Vec<String> {
    if config.study.accounting_error.is_some() {
        return allowance_status_lines(config);
    }
    let Some(allowance) = &config.study.allowance else {
        return vec!["Allowance unavailable. Reading starts no model requests.".into()];
    };
    vec![format!(
        "Calls: {} / {} · Review: {} left · {} unresolved",
        allowance.committed_calls,
        allowance.limits.max_provider_calls,
        allowance.protected_review_remaining(),
        allowance.unresolved_calls
    )]
}

fn result_allowance_lines(config: &BatchScanConfig) -> Vec<String> {
    let lines = allowance_status_lines(config);
    if config.study.accounting_error.is_some() {
        return lines;
    }
    lines.into_iter().skip(1).collect()
}

#[cfg(test)]
mod tests;
