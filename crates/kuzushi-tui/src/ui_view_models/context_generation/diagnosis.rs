use crate::renderer::shared::text::wrap_text;
use kuzushi_core::capabilities::campaign::{ContextStudyReceipt, RejectedContextOutput};
use serde_json::Value;

pub(super) fn retention_label(
    receipt: Option<&ContextStudyReceipt>,
    input: &Value,
) -> &'static str {
    let enabled = receipt
        .map(|receipt| receipt.input["saveRejectedOutput"] == true)
        .unwrap_or_else(|| input["saveRejectedOutput"].as_bool().unwrap_or(true));
    if enabled {
        "Rejected output: bounded local diagnostic, at most 24 KiB. It may contain source or sensitive model text. s changes this choice before preparing the plan."
    } else {
        "Rejected output: not retained. s changes this choice before preparing the plan. Routine errors remain redacted."
    }
}

pub(super) fn scope_retention_label(
    receipt: Option<&ContextStudyReceipt>,
    input: &Value,
) -> &'static str {
    let enabled = receipt.map_or_else(
        || input["saveRejectedOutput"].as_bool().unwrap_or(true),
        |receipt| receipt.input["saveRejectedOutput"] == true,
    );
    if enabled {
        "Rejected scope output: retain at most 16 KiB locally. May contain source or sensitive text. s changes this choice before preparing the plan."
    } else {
        "Rejected scope output: not retained. s changes this choice before preparing the plan."
    }
}

pub(super) fn lines(
    output: Option<&Result<RejectedContextOutput, String>>,
    width: usize,
) -> Vec<String> {
    let mut lines = vec!["UNACCEPTED MODEL OUTPUT".into(),
        "Local diagnostic only. Untrusted text may contain source or sensitive information. Reading never accepts a result or starts work.".into()];
    match output {
        Some(Ok(output)) => {
            lines.extend([
                format!(
                    "Model: {}",
                    crate::app::display_model_selector(&output.model)
                ),
                format!("Recorded source: {}", output.source_identity),
                format!("Run: {}", output.run_id),
                format!("Artifact: {}", output.path.display()),
                String::new(),
            ]);
            lines.extend(output.text.lines().map(escape_controls));
        }
        Some(Err(error)) => lines.push(format!("Rejected output unavailable: {error}")),
        None => lines.push("No rejected output has been inspected.".into()),
    }
    lines.extend([
        "End of local diagnostic. d or Esc returns to the previous view.".into(),
        "This output is unaccepted.".into(),
    ]);
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&escape_controls(&line), width.max(1)))
        .collect()
}

pub(super) fn escape_controls(line: &str) -> String {
    line.chars()
        .map(|character| {
            if character.is_control() {
                character.escape_default().to_string()
            } else {
                character.to_string()
            }
        })
        .collect()
}
