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
        format!(
            "Model input: {} bytes; {}/{} files.",
            generation.input_bytes, generation.supplied_files, generation.inventoried_files
        ),
    ];
    lines.extend(generation.limitations.first().cloned());
    lines
}

pub(super) fn generation_detail(review: &ScanScopeReview) -> Vec<String> {
    let Some(generation) = &review.record.generation else {
        return Vec::new();
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
    lines.extend(generation.limitations.clone());
    lines
}

#[cfg(test)]
mod tests;
