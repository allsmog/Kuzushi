use super::*;
use kuzushi_core::findings::LessonGeneration;

pub(super) fn receipt_lines(receipt: &LessonGeneration, width: u16) -> Vec<Line<'static>> {
    let mut lines = wrapped(
        &format!(
            "Proposed by: {}",
            safe(&crate::app::display_model_selector(&receipt.model))
        ),
        width,
        theme::muted(),
    );
    lines.extend(wrapped(
        source_label(&receipt.source_capture),
        width,
        theme::primary(),
    ));
    if receipt.source_evidence_ref.is_some() {
        lines.extend(wrapped(
            "Supporting source: saved bundle",
            width,
            theme::muted(),
        ));
    }
    lines.extend(wrapped(
        &format!(
            "Evidence text: {} B · draft requests: {}\nProvider retries also count toward the allowance.\nGeneration run: {}\nPrompt: {}",
            receipt.input_bytes,
            receipt.synthesis_requests,
            safe(receipt.run_id.as_deref().unwrap_or("unrecorded")),
            safe(&receipt.prompt_sha256),
        ),
        width,
        theme::muted(),
    ));
    lines
}

fn source_label(state: &str) -> &'static str {
    match state {
        "included" => "Captured historical source supplied.",
        "not_recorded" => "Source omitted: no capture was recorded.",
        "unavailable_or_over_limit" => {
            "Source omitted: capture unavailable or over the byte limit."
        }
        _ => "Source capture status unavailable.",
    }
}

#[cfg(test)]
mod tests;
