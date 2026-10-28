use super::study_config::{allowance_status_lines, study_config_area};
use crate::app::{BatchScanConfig, ShellApp, StudyContextGeneration};
use crate::renderer::shared::text::wrap_text;
use ratatui::layout::Rect;
mod diagnosis;
mod evidence;
mod lesson_sources;
pub(crate) use lesson_sources::lesson_source_lines;
mod planning;
mod proposal;
mod question;
mod receipts;
mod result;
mod scope;
mod scope_correction;
pub(crate) use scope_correction::{correction_notice, CORRECTION_CONTROLS};
mod summaries;
use planning::*;
pub(crate) use receipts::format_options;
pub(crate) use result::{context_preview, GeneratedContextPreview};
use summaries::generation_summary;

pub(crate) fn generation_body(columns: u16, rows: u16, regeneration: bool) -> Rect {
    let area = study_config_area(columns, rows);
    Rect::new(
        area.x + 2,
        area.y + 2,
        area.width.saturating_sub(4),
        area.height.saturating_sub(if regeneration { 6 } else { 5 }),
    )
}

pub(crate) fn generation_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let Some(config) = app.router.campaign().batch_scan_config.as_ref() else {
        return Vec::new();
    };
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    if let Some(lines) = generation_subview_lines(generation, width) {
        return lines;
    }
    generation_content_lines(app, config, generation, width)
}

fn generation_content_lines(
    app: &ShellApp,
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    if uses_evidence_summary(generation) {
        return evidence::summary(app, config, generation, width);
    }
    let mut lines = generation_summary(config, generation, width);
    if generation.allows_model_choice() && generation.receipt.is_none() {
        let model = format!(
            "Selected model: {} · reasoning: {}. M chooses a model.",
            crate::app::display_model_selector(
                app.config().model.as_deref().unwrap_or("select explicitly")
            ),
            generation.context_input["thinkingLevel"]
                .as_str()
                .or(app.config().runtime.thinking_level.as_deref())
                .unwrap_or("selected runtime default")
        );
        let mut header = wrap_text(&model, width.max(1));
        header.append(&mut lines);
        return header;
    }
    lines
}

fn uses_evidence_summary(generation: &StudyContextGeneration) -> bool {
    generation.context_input.get("sourcePaths").is_some()
        && matches!(
            generation.generation_tool.as_deref(),
            None | Some("threat-model:build")
        )
}

fn generation_subview_lines(
    generation: &crate::app::StudyContextGeneration,
    width: usize,
) -> Option<Vec<String>> {
    if let Some((lines, _)) = &generation.lesson_sources {
        return Some(
            lines
                .iter()
                .flat_map(|line| wrap_text(line, width.max(1)))
                .collect(),
        );
    }
    if generation.show_brief_guidance {
        return Some(bound_brief_lines(generation, width));
    }
    remaining_generation_subview_lines(generation, width)
}

fn remaining_generation_subview_lines(
    generation: &crate::app::StudyContextGeneration,
    width: usize,
) -> Option<Vec<String>> {
    if generation.show_answer {
        return Some(question::answer_lines(generation, width));
    }
    non_answer_subview_lines(generation, width)
}

fn non_answer_subview_lines(
    generation: &crate::app::StudyContextGeneration,
    width: usize,
) -> Option<Vec<String>> {
    if let Some(state) = generation
        .scope_correction
        .as_ref()
        .filter(|state| state.editing)
    {
        return Some(scope_correction::lines(state, width));
    }
    if generation.guidance_editing {
        return Some(guidance_lines(generation, width));
    }
    document_subview_lines(generation, width)
}

fn document_subview_lines(
    generation: &StudyContextGeneration,
    width: usize,
) -> Option<Vec<String>> {
    if generation.show_rejected {
        return Some(diagnosis::lines(generation.rejected_output.as_ref(), width));
    }
    if generation.show_options {
        return Some(option_lines(&generation.options, width));
    }
    None
}

fn guidance_lines(generation: &crate::app::StudyContextGeneration, width: usize) -> Vec<String> {
    let mut lines = vec![if generation.is_workflow_proposal() {
        "PLANNING GOAL".into()
    } else if generation.is_question() {
        "QUESTION".into()
    } else if generation.is_lesson() {
        "LESSON GUIDANCE".into()
    } else {
        "REGENERATION GUIDANCE".into()
    }];
    lines.extend(generation.guidance_notice.iter().cloned());
    let Some(editor) = generation.guidance_editor.as_ref() else {
        return wrap_text(GUIDANCE_EDITOR_UNAVAILABLE, width.max(1));
    };
    lines.extend(editor.text().lines().map(str::to_owned));
    lines.extend([
        "Enter newline · Ctrl+S use text".into(),
        format!(
            "Esc back · draft kept · max {} B",
            generation.editor_limit()
        ),
    ]);
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

pub(crate) const GUIDANCE_EDITOR_UNAVAILABLE: &str =
    "Guidance editor unavailable. Esc returns to the plan; saved input is unchanged.";

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
        .map(receipts::receipt_lines)
        .unwrap_or_else(|| vec!["Enter freezes source, selected model and bounded generation options. Preparing the draft makes no model request.".into()])
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
