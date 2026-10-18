//! A completion receipt links to full output instead of repeating its payload.
use crate::app::RunFocusReceipt;
use kuzushi_core::run_artifacts::RunResultSummary;

const COMPACT_RESULT_CHARS: usize = 96;

pub(in super::super) fn run_receipt_notice(
    receipt: &RunFocusReceipt,
    acknowledgement: Option<&str>,
) -> String {
    let summary = result_notice(receipt);
    match acknowledgement {
        Some(answer) => format!("{summary} · {answer}"),
        None => summary,
    }
}

fn result_notice(receipt: &RunFocusReceipt) -> String {
    let summary = format!("run receipt · {}", receipt.summary());
    match receipt.result_summaries.as_slice() {
        [result] if result.status == receipt.outcome => single_result_notice(result, &summary),
        _ => summary,
    }
}

fn single_result_notice(result: &RunResultSummary, receipt: &str) -> String {
    let name = kuzushi_core::modules::tool_display_name(&result.tool);
    match compact_result_text(result) {
        Some(text) => format!("{name}: {text} · {receipt}"),
        None => format!("{name} · {receipt} · full result: logs"),
    }
}

fn compact_result_text(result: &RunResultSummary) -> Option<&str> {
    if result.output_line_count > 1 {
        return None;
    }
    let text = result.summary.trim();
    if text.is_empty() || text.contains(['\n', '\r']) {
        return None;
    }
    text.chars()
        .nth(COMPACT_RESULT_CHARS)
        .is_none()
        .then_some(text)
}
