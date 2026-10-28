use kuzushi_core::workspace::{ScanScopeGeneration, ScanScopeReview};

pub(super) fn generation_summary(generation: Option<&ScanScopeGeneration>) -> Vec<String> {
    let Some(generation) = generation else {
        return Vec::new();
    };
    let mut lines = vec![
        format!(
            "Proposal model: {}",
            crate::app::display_model_selector(&generation.model)
        ),
        proposal_context_summary(generation),
        format!(
            "Model input: {} bytes; {}/{} filenames.",
            generation.input_bytes, generation.supplied_files, generation.inventoried_files
        ),
    ];
    lines.extend(generation.limitations.first().cloned());
    lines
}

pub(super) fn generation_detail(review: &ScanScopeReview) -> Vec<String> {
    let Some(generation) = &review.record.generation else {
        return correction_detail(review);
    };
    let edited = serde_json::to_string(&review.record.draft)
        .map(|text| kuzushi_core::options::prompt_content_sha256(&text) != generation.draft_sha256)
        .unwrap_or(true);
    let mut lines = vec![
        format!(
            "Suggested with {}. Subsequent operator edits: {edited}.",
            crate::app::display_model_selector(&generation.model)
        ),
        format!(
            "Model input: {} bytes; {} of {} file names supplied. Run: {}.",
            generation.input_bytes,
            generation.supplied_files,
            generation.inventoried_files,
            generation.run_id
        ),
    ];
    lines.extend(proposal_context_detail(generation));
    lines.extend(generation.limitations.clone());
    lines
}

fn proposal_context_summary(generation: &ScanScopeGeneration) -> String {
    generation.context_ref.as_ref().map_or_else(
        || "Proposal context reference: not recorded.".into(),
        |context| format!("Proposal context: saved revision {}", context.revision_id),
    )
}

fn proposal_context_detail(generation: &ScanScopeGeneration) -> Vec<String> {
    let mut lines = vec![proposal_context_summary(generation)];
    if let Some(context) = &generation.context_ref {
        lines.extend([
            format!("Proposal context model: {}", context.model_id),
            format!("Proposal context SHA-256: {}", context.sha256),
            "Map acceptance and scan context are reviewed separately.".into(),
        ]);
    }
    lines
}

pub(super) fn correction_summary(
    correction: Option<&kuzushi_core::workspace::ScanScopeCorrection>,
) -> Vec<String> {
    correction.map_or_else(Vec::new, |_| {
        vec!["Manually corrected. Original proposal job remains failed.".into()]
    })
}

fn correction_detail(review: &ScanScopeReview) -> Vec<String> {
    let Some(correction) = &review.record.correction else {
        return Vec::new();
    };
    vec![
        "Manual correction of retained, unaccepted model output.".into(),
        format!(
            "Original failed job: {}. Model: {}.",
            correction.rejected.run_id,
            crate::app::display_model_selector(&correction.model)
        ),
        format!(
            "Reviewed plan: {}. Retained output: {}.",
            correction.rejected.plan_sha256, correction.rejected.artifact_hash
        ),
        format!(
            "Context: {}. Saving approved neither scans nor additional spending.",
            correction
                .context_ref
                .as_ref()
                .map_or("explicitly omitted", |context| context.revision_id.as_str())
        ),
    ]
}

#[cfg(test)]
mod tests;
