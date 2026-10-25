use super::study_config::{allowance_status_lines, study_config_area};
use crate::app::{BatchScanConfig, ShellApp, StudyContextGeneration};
use crate::renderer::shared::text::wrap_text;
use ratatui::layout::Rect;
mod diagnosis;
mod evidence;
mod proposal;
mod question;
mod result;
mod scope;
pub(crate) use result::{context_preview, GeneratedContextPreview};

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
    if generation.guidance_editing {
        return Some(guidance_lines(generation, width));
    }
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

fn generation_summary(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    if generation.is_workflow_proposal() {
        return proposal::summary(config, generation, width);
    }
    if generation.is_question() {
        return question::summary(config, generation, width);
    }
    non_question_generation_summary(config, generation, width)
}

fn non_question_generation_summary(
    config: &crate::app::BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    if generation.is_scope_proposal() {
        return scope::summary(config, width);
    }
    if generation.is_regeneration() {
        return regeneration_summary(config, generation, width);
    }
    if generation.is_lesson() {
        return lesson_generation_summary(config, generation, width);
    }
    remaining_generation_summary(config, generation, width)
}

fn remaining_generation_summary(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    if generation.is_scope_context() {
        return file_group_summary(config, generation, width);
    }
    if generation.supports_result_overview() && !generation.show_plan {
        return result::overview(config, generation, width);
    }
    context_generation_summary(config, width)
}

fn file_group_summary(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    let mut lines=vec![generation.action(config).into(),
        format!("Boundary: {}",generation.context_input.pointer("/scanScopeRef/scopeId").and_then(serde_json::Value::as_str).unwrap_or("unavailable")),
        "One file-group context job · one worker · one attempt".into(),
        "One tool-free synthesis over accepted discovery and shared files. No sibling source, discovery jobs, delegation or output repair.".into(),
        "The result stays inactive. Inspect its data flow, source and omissions before choosing it for this boundary. Sibling context choices remain.".into(),
        format!("Inherited context: {}",generation.context_input.pointer("/inheritedContextRef/revisionId").and_then(serde_json::Value::as_str).unwrap_or("explicitly omitted")),
        format!("Total calls: {}",limit(config.study.max_provider_calls)),format!("Protected review: {}",limit(config.study.protected_review_calls)),
        "Context generation and discovery share spending. A completed draft does not approve scans. Dollar estimate unavailable.".into()];
    lines.extend(brief_guidance_lines(config, generation));
    lines.extend(config.notice.iter().cloned());
    lines.extend(generation_plan_lines(config));
    lines.extend(allowance_status_lines(config));
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn lesson_generation_summary(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    let mut lines=vec![generation.action(config).into(),"One lesson job · one worker · one attempt".into(),
        format!("Origin: requested generation #{}. Preparation checks exact human confirmation.",generation.context_input["findingId"]),
        "One bounded synthesis request with tools disabled. Uses recorded observation and captured source only; source omissions remain visible. Output stays a draft for human review. No new findings, scans or Map completion.".into(),
        "Learning calls share the investigation allowance; protected Review calls remain reserved. Preparing a plan makes no model request. Execution needs separate approval and start.".into(),
        format!("Total calls: {}",limit(config.study.max_provider_calls)),format!("Protected review: {}",limit(config.study.protected_review_calls)),"Internal transport retries consume the same shared allowance. Dollar consumption is uncertain; no dollar ceiling is enforced.".into()];
    lines.extend(config.notice.iter().cloned());
    if let Some(error) = &generation.result_error {
        lines.push(format!("Lesson result unavailable: {error}. Enter opens its recorded outcome. No automatic retry or repair."));
    }
    lines.extend(generation_plan_lines(config));
    lines.extend(
        allowance_status_lines(config)
            .into_iter()
            .map(|line| line.replace("context/scan", "Learning")),
    );
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn regeneration_summary(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    let mut lines=vec![generation.action(config).into(),"One selected-text job · one worker · one attempt".into(),
        "One synthesis request, with tools disabled. Original and unselected text are preserved. Output is an inactive draft; compare it before selecting it for work.".into(),
        regeneration_selection_line(generation),
        "Preparing a plan makes no model request. Execution requires its own approved allowance and a separate start action.".into()];
    lines.extend(config.notice.iter().cloned());
    if let Some(error) = &generation.result_error {
        lines.push(format!("Regeneration unavailable: {error}. Enter opens the recorded job outcome; n prepares a separate draft."));
    }
    if generation.generated.is_some() {
        lines.push("Enter inspects the exact inactive candidate. d compares it with its parent; a selects it for a separately approved study.".into());
    }
    lines.extend([format!("Total calls: {}",limit(config.study.max_provider_calls)),format!("Protected review: {}",limit(config.study.protected_review_calls)),"Internal transport retries consume the same shared allowance. Existing spending is retained.".into(),"Dollar estimate: unavailable. No dollar ceiling is enforced.".into()]);
    lines.extend(generation_plan_lines(config));
    lines.extend(allowance_status_lines(config));
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn bound_brief_lines(generation: &crate::app::StudyContextGeneration, width: usize) -> Vec<String> {
    let Some(guidance) = generation
        .receipt
        .as_ref()
        .and_then(|receipt| receipt.brief_guidance.as_ref())
    else {
        return vec!["This plan supplies no goal guidance.".into()];
    };
    ["GOAL IN THIS CONTEXT PLAN".into(), format!("{} · exact revision {} · {} text bytes", guidance.reference.brief_id, guidance.reference.revision, guidance.text_bytes),
        "Entire reviewed text is supplied for priorities and questions. It is not source evidence or a finding verdict.".into(),
        guidance.text.clone(), "Later goal edits cannot rewrite this plan. Esc returns to its allowance review.".into()]
        .into_iter().flat_map(|line| wrap_text(&line, width.max(1))).collect()
}

fn brief_guidance_lines(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
) -> Vec<String> {
    if let Some(guidance) = generation
        .receipt
        .as_ref()
        .and_then(|receipt| receipt.brief_guidance.as_ref())
    {
        return vec![format!(
            "Goal guidance: frozen revision {} · {} text bytes. b reads the planned goal text.",
            guidance.reference.revision, guidance.text_bytes
        )];
    }
    if generation.receipt.is_some() {
        return vec!["Goal guidance: omitted from this frozen plan.".into()];
    }
    let selection =
        config
            .study
            .brief
            .as_ref()
            .map_or("no reviewed goal selected".into(), |brief| {
                format!(
                    "revision {} · {} text bytes",
                    brief.reference.revision,
                    brief.document.text.len()
                )
            });
    vec![format!("Goal guidance: {} · {selection}. g toggles; b reviews the goal.", if generation.use_brief_guidance { "on" } else { "off" }),
        "Only an explicitly approved context request receives this text. Source, scan scope, model and finding decisions stay unchanged; entire selected text is supplied without truncation.".into()]
}

fn context_generation_summary(config: &crate::app::BatchScanConfig, width: usize) -> Vec<String> {
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    let mut lines = context_result_lines(config);
    append_plan_heading(&mut lines, generation);
    lines.extend(brief_guidance_lines(config, generation));
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

fn append_plan_heading(lines: &mut Vec<String>, generation: &StudyContextGeneration) {
    if generation.show_plan {
        lines.insert(0, "FROZEN GENERATION PLAN · p result".into());
    }
}

fn regeneration_selection_line(generation: &crate::app::StudyContextGeneration) -> String {
    if let Some(label) = &generation.selected_text_label {
        return format!("Selected text: {label}");
    }
    let count = generation.context_input["fields"]
        .as_array()
        .map_or(0, Vec::len);
    format!("Selected text: {count} saved field(s). Tab shows the exact selection.")
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
    if receipt.generation_tool == "planner:propose" {
        return proposal::receipt_lines(receipt);
    }
    if receipt.generation_tool == "threat-model:ask" {
        return question::receipt_lines(receipt);
    }
    non_question_receipt_lines(receipt)
}

fn non_question_receipt_lines(
    receipt: &kuzushi_core::capabilities::campaign::ContextStudyReceipt,
) -> Vec<String> {
    if receipt.generation_tool == "findings:lesson-generate" {
        return lesson_receipt_lines(receipt);
    }
    if receipt.generation_tool == "pack:suggest-scopes" {
        return scope::receipt_lines(receipt);
    }
    if receipt.generation_tool == "threat-model:regenerate" {
        return regeneration_receipt_lines(receipt);
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

fn lesson_receipt_lines(
    receipt: &kuzushi_core::capabilities::campaign::ContextStudyReceipt,
) -> Vec<String> {
    vec![
        format!("Model: {} · reasoning: {}", crate::app::display_model_selector(&receipt.model), receipt.input["thinkingLevel"].as_str().unwrap_or("recorded runtime setting")),
        format!("Source at preparation: {}", receipt.source_identity),
        format!("Plan: {}", receipt.campaign_id),
        format!("Plan digest: {}", receipt.plan_sha256),
        format!("Requested output: {} tokens. Output enforcement depends on the adapter; the allowance bounds provider requests.", receipt.input["maxOutputTokens"]),
        format!("Recorded source excerpt: at most {} bytes. Missing captures are disclosed; current files are not substituted.", receipt.input["maxSourceBytes"]),
        "Tab shows every exact generation option.".into(),
    ]
}

pub(crate) fn format_options(input: &serde_json::Value) -> Vec<String> {
    match serde_json::to_string_pretty(input) {
        Ok(text) => text.lines().map(str::to_string).collect(),
        Err(error) => vec![format!("Options unavailable: {error}")],
    }
}

fn regeneration_receipt_lines(
    receipt: &kuzushi_core::capabilities::campaign::ContextStudyReceipt,
) -> Vec<String> {
    vec![format!("Model: {}", crate::app::display_model_selector(&receipt.model)),
        format!("Source: {}", receipt.source_identity), format!("Plan: {}", receipt.campaign_id),
        format!("Plan digest: {}", receipt.plan_sha256),
        format!("Requested output: {} tokens. Subscription OAuth may not enforce this ceiling.", receipt.input["maxOutputTokens"]),
        format!("Source excerpts: at most {} bytes across {} files. Architecture: at most 128 KiB; complete prompt: at most 512 KiB. Supplied excerpts and omissions are retained with the result.", receipt.input["maxSourceBytes"], receipt.input["contextLimit"]),
        "Tab shows the exact parent, fields, guidance and generation options. New work needs separate approval.".into()]
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
