use super::*;

pub(super) fn bound_brief_lines(
    generation: &crate::app::StudyContextGeneration,
    width: usize,
) -> Vec<String> {
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

pub(super) fn brief_guidance_lines(
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

pub(super) fn context_generation_summary(
    config: &crate::app::BatchScanConfig,
    width: usize,
) -> Vec<String> {
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

pub(super) fn append_plan_heading(lines: &mut Vec<String>, generation: &StudyContextGeneration) {
    if generation.show_plan {
        lines.insert(0, "FROZEN GENERATION PLAN · p result".into());
    }
}

pub(super) fn regeneration_selection_line(
    generation: &crate::app::StudyContextGeneration,
) -> String {
    if let Some(label) = &generation.selected_text_label {
        return format!("Selected text: {label}");
    }
    let count = generation.context_input["fields"]
        .as_array()
        .map_or(0, Vec::len);
    format!("Selected text: {count} saved field(s). Tab shows the exact selection.")
}
