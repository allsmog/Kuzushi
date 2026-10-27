use super::*;

pub(super) fn receipt_lines(
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
