use super::*;

pub(super) fn generation_summary(
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
