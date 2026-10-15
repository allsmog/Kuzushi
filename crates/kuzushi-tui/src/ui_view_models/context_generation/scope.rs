use super::*;

pub(super) fn summary(config: &BatchScanConfig, width: usize) -> Vec<String> {
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    let mut lines = vec![generation.action(config).into()];
    append_outcome(&mut lines, generation);
    lines.push("One scope proposal job · one worker · one attempt".into());
    lines.extend(allowance_status_lines(config));
    lines.extend([
        format!("Total calls: {}", limit(config.study.max_provider_calls)),
        format!("Protected review: {}", limit(config.study.protected_review_calls)),
        "Dollar estimate: unavailable. No dollar ceiling is enforced.".into(),
        "Scope planning, context, scans and review share accounting. Internal turns and retries consume calls; existing commitments remain.".into(),
        "At most eight primary scopes and optional shared context. No tools, recursive subdivision, output repair or scan jobs.".into(),
        "Enter reviews the fixed plan, then the shared allowance. A completed result opens scope review; boundary acceptance remains separate.".into(),
        architecture_line(generation),
    ]);
    lines.extend(config.notice.iter().cloned());
    lines.extend(generation_plan_lines(config));
    lines.push("A new draft requires its own approval. Previous spending and consumed attempts remain recorded.".into());
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn append_outcome(lines: &mut Vec<String>, generation: &StudyContextGeneration) {
    if let Some(error) = &generation.result_error {
        lines.push(error.clone());
        lines.push("Enter opens the recorded job. n prepares a replacement with separate approval. No automatic repair or rerun.".into());
    }
}

fn architecture_line(generation: &StudyContextGeneration) -> String {
    let context = if generation.context_input["threatModelRef"].is_null() {
        "explicitly omitted"
    } else {
        "exact accepted Map revision"
    };
    format!("Architecture context: {context}")
}

#[cfg(test)]
mod tests;
