use super::*;
use kuzushi_core::capabilities::campaign::{ReviewSourceBinding, ReviewSourceObservation};

pub(super) fn summary(config: &BatchScanConfig) -> Vec<String> {
    if let Some(evidence) = config
        .study
        .review_receipt
        .as_ref()
        .and_then(|receipt| receipt.source_evidence.as_ref())
    {
        let included = evidence
            .observations
            .iter()
            .filter(|source| source.text.is_some())
            .count();
        let model_bytes = evidence
            .observations
            .iter()
            .map(|source| source.model_input().len())
            .sum::<usize>();
        return vec![format!("Cited source: {included}/{} primary files · {} / {} bytes · v reads supplied text and omissions", evidence.observations.len(), evidence.included_bytes, evidence.max_bytes),
            format!("Model source blocks: {model_bytes} bytes before finding and transport formatting. Dollar consumption remains uncertain."),
            "Matching source bytes do not settle the finding's verdict. No dependency files are added automatically.".into()];
    }
    let input = config.review_plan.as_ref().map(|review| &review.input);
    if input.is_some_and(|input| input["sourceEvidence"] == "cited") {
        let limit = input
            .and_then(|input| input["maxSourceEvidenceBytes"].as_u64())
            .unwrap_or(32768);
        return vec![format!(
            "Cited source: selected · {limit} bytes maximum · Enter freezes text before approval"
        )];
    }
    vec!["Additional source text: none. Finding data and accepted context are still supplied. e selects bounded cited files for standard Review.".into()]
}

pub(super) fn details(config: &BatchScanConfig) -> Vec<String> {
    let Some(evidence) = config
        .study
        .review_receipt
        .as_ref()
        .and_then(|receipt| receipt.source_evidence.as_ref())
    else {
        return vec!["FROZEN SOURCE INPUT".into(), "No source text is frozen in this draft. Select cited files with e, then prepare with Enter. No model request starts during preparation.".into()];
    };
    let mut lines = vec![
        "FROZEN SOURCE INPUT · v returns".into(),
        format!(
            "Read only · {} / {} bytes",
            evidence.included_bytes, evidence.max_bytes
        ),
    ];
    for source in &evidence.observations {
        lines.extend(source_lines(source));
    }
    lines.extend([format!("Snapshot: {}", evidence.snapshot_hash), format!("Content: {}", evidence.tree_hash),
        "This source text is added to that generation's Review user prompt using the shared untrusted-data wrapper. Recorded observations are unchanged.".into()]);
    lines
}

fn source_lines(source: &ReviewSourceObservation) -> Vec<String> {
    let path = kuzushi_core::run_lifecycle::SafeText::operator_visible(&source.path);
    let mut lines = vec![path.to_string()];
    lines.push(binding_label(source.binding).into());
    if let Some(text) = &source.text {
        lines.extend(text.lines().enumerate().map(|(index, line)| {
            format!(
                "{:>5} │ {}",
                index + 1,
                kuzushi_core::run_lifecycle::SafeText::operator_visible(line)
            )
        }));
    } else {
        lines.push(file_omission(source.file.as_ref().map(|file| file.state)).into());
    }
    lines.push(format!("Observation: generation:{}", source.generation_id));
    lines
}

fn file_omission(state: Option<kuzushi_core::findings::ReviewCapturedFileState>) -> &'static str {
    use kuzushi_core::findings::ReviewCapturedFileState::*;
    match state {
        Some(TooLarge) => "No text supplied: the complete file exceeds the remaining byte limit.",
        Some(ExcludedOrMissing) => "No text supplied: file is excluded or missing from the recorded source tree.",
        Some(BinaryOrInvalidText) => "No text supplied: binary or invalid text.",
        _ => "No cited-file text was captured. Existing finding data and accepted context are still supplied.",
    }
}

fn binding_label(binding: ReviewSourceBinding) -> &'static str {
    match binding {
        ReviewSourceBinding::MatchingRecordedSnapshot => "Recorded source matches.",
        ReviewSourceBinding::RecordedSourceChanged => {
            "Omitted: checkout differs from the recorded observation source."
        }
        ReviewSourceBinding::RecordedSourceUnavailable => {
            "Omitted: recorded source could not be authenticated."
        }
        ReviewSourceBinding::ByteLimitReached => {
            "Omitted: the selected source-byte limit was reached."
        }
    }
}
