use super::*;

pub(super) fn summary(config: &BatchScanConfig, width: usize) -> Vec<String> {
    let Some(generation) = config.context_generation.as_ref() else {
        return Vec::new();
    };
    let mut lines = vec![generation.action(config).into()];
    append_outcome(&mut lines, generation);
    lines.push("One scope proposal job · one worker · one attempt".into());
    lines.push(file_selection_line(
        generation
            .receipt
            .as_ref()
            .map(|receipt| &receipt.input)
            .unwrap_or(&generation.context_input),
        generation.receipt.is_some(),
    ));
    lines.push(
        super::diagnosis::scope_retention_label(
            generation.receipt.as_ref(),
            &generation.context_input,
        )
        .into(),
    );
    lines.extend(allowance_status_lines(config));
    lines.extend([
        format!("Total calls: {}", limit(config.study.max_provider_calls)),
        format!("Protected review: {}", limit(config.study.protected_review_calls)),
        "Dollar estimate: unavailable. No dollar ceiling is enforced.".into(),
        "Scope planning, context, scans and review share accounting. Internal turns and retries consume calls; existing commitments remain.".into(),
        "At most eight primary scopes and optional shared context. No tools, recursive subdivision, output repair or scan jobs.".into(),
        "Boundary acceptance and scan approval remain separate.".into(),
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
        lines.push(if generation.has_corrected_scopes() {
            "Original job remains failed. Enter reviews your corrected scope draft; boundary acceptance is separate. No new model request."
        } else {
            "Enter opens the recorded job. n prepares a replacement with separate approval. No automatic repair or rerun."
        }.into());
    }
    lines.extend(
        generation
            .scope_correction
            .as_ref()
            .and_then(|state| state.notice.clone()),
    );
}

fn architecture_line(generation: &StudyContextGeneration) -> String {
    let context = if generation.context_input["threatModelRef"].is_null() {
        "explicitly omitted"
    } else {
        "exact saved revision"
    };
    format!("Architecture context: {context}")
}

fn file_selection_line(input: &serde_json::Value, frozen: bool) -> String {
    let selection = input.get("fileSelection");
    let default = if frozen {
        "prefix-v1"
    } else {
        "root-balanced-v1"
    };
    let policy = match selection {
        None => Some(default),
        Some(value) => value.as_str(),
    };
    let label = match policy {
        Some("prefix-v1") => "recorded filename prefix",
        Some("root-balanced-v1") => "root files first, balanced directory groups",
        _ => return "Filename sample: unsupported saved option; prepare a corrected draft.".into(),
    };
    format!("Filename sample: {label}. At most 512 names and 16 KiB.")
}

pub(super) fn receipt_lines(
    receipt: &kuzushi_core::capabilities::campaign::ContextStudyReceipt,
) -> Vec<String> {
    let reasoning = receipt.input["thinkingLevel"]
        .as_str()
        .unwrap_or("recorded runtime setting");
    vec![
        format!("Model: {} · reasoning: {reasoning}", crate::app::display_model_selector(&receipt.model)),
        format!("Source: {}", receipt.source_identity),
        format!("Plan: {}", receipt.campaign_id),
        format!("Plan digest: {}", receipt.plan_sha256),
        format!("Requested output: {} tokens. Subscription OAuth may not enforce this ceiling.", receipt.input["maxOutputTokens"]),
        "Model data: at most 64 KiB, using the saved inventory and bounded architecture. Omitted rows and incomplete inventory are disclosed in the resulting scope draft.".into(),
        "Tab shows every exact proposal option. M chooses a model for a new draft.".into(),
    ]
}

#[cfg(test)]
mod tests;
