use serde_json::Value;

const MAX_RESULT_LOG_LINES: usize = 12;
const MAX_RESULT_LOG_BYTES: usize = 2_000;
const MAX_RECEIPT_FIELD_CHARS: usize = 180;

/// Curated output stays intact. Structured failures lead with their cause;
/// full machine payloads remain in the run artifacts and failure reader.
pub(super) fn rendered_tool_result(result: &Value) -> String {
    if let Some(output) = result.get("output").and_then(Value::as_str) {
        return output.to_string();
    }
    if let Some(receipt) = remedy_receipt(result) {
        return receipt;
    }
    if let Some(receipt) = generic_count_receipt(result) {
        return receipt;
    }
    let dumped = serde_json::to_string_pretty(result).unwrap_or_else(|_| result.to_string());
    clip_result_body(&dumped)
}

fn remedy_receipt(result: &Value) -> Option<String> {
    use kuzushi_core::ToolResultStatus;
    let status = match kuzushi_core::tool_result_status(result) {
        ToolResultStatus::Failed => "failed",
        ToolResultStatus::Partial => "partial",
        _ => return None,
    };
    let summary = result
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("tool result");
    let mut lines = vec![format!("{status} · {}", receipt_text(summary))];
    lines.extend(receipt_field(
        result,
        "Stage",
        "/fallback_context/failedStage",
    ));
    lines.extend(cause_receipt(result));
    lines.extend(receipt_field(result, "Warning", "/warnings/0"));
    lines.extend(problem_counts(result));
    lines.extend(receipt_field(
        result,
        "Next",
        "/fallback_context/recoveryOptions/0",
    ));
    lines.push(details_receipt(result).to_string());
    Some(lines.join("\n"))
}

fn receipt_field(result: &Value, label: &str, pointer: &str) -> Option<String> {
    let value = result.pointer(pointer)?.as_str()?;
    (!value.trim().is_empty()).then(|| format!("{label}: {}", receipt_text(value)))
}

fn cause_receipt(result: &Value) -> Option<String> {
    receipt_field(result, "Cause", "/fallback_context/cause")
        .or_else(|| receipt_field(result, "Cause", "/errors/0"))
        .or_else(|| receipt_field(result, "Cause", "/error"))
}

fn problem_counts(result: &Value) -> Option<String> {
    let errors = result
        .get("errors")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let warnings = result
        .get("warnings")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    (errors + warnings > 1).then(|| format!("Recorded: {errors} error(s), {warnings} warning(s)"))
}

fn details_receipt(result: &Value) -> &'static str {
    if result.get("fallback_context").is_some_and(Value::is_object) {
        "Details: failure · full payload in this run's result.json"
    } else {
        "Full payload: inspect this run's result.json"
    }
}

fn receipt_text(text: &str) -> String {
    let prefix = text
        .chars()
        .take(MAX_RECEIPT_FIELD_CHARS)
        .collect::<String>();
    let mut compact = prefix.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().nth(MAX_RECEIPT_FIELD_CHARS).is_some() {
        compact.push('…');
    }
    compact
}

fn clip_result_body(body: &str) -> String {
    let lines = body.lines().collect::<Vec<_>>();
    let line_clipped = lines.len() > MAX_RESULT_LOG_LINES;
    let mut clipped = lines
        .iter()
        .take(MAX_RESULT_LOG_LINES)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    let byte_clipped = clipped.len() > MAX_RESULT_LOG_BYTES;
    if byte_clipped {
        clipped.truncate(floor_char_boundary(&clipped, MAX_RESULT_LOG_BYTES));
    }
    if !line_clipped && !byte_clipped {
        return clipped;
    }
    let omitted = lines.len().saturating_sub(MAX_RESULT_LOG_LINES);
    format!("{clipped}\n… {omitted} more lines · full result in the run's result.json")
}

fn floor_char_boundary(text: &str, limit: usize) -> usize {
    (0..=limit)
        .rev()
        .find(|at| text.is_char_boundary(*at))
        .unwrap_or_default()
}

fn generic_count_receipt(result: &serde_json::Value) -> Option<String> {
    let count = result.pointer("/data/count")?.as_u64()?;
    Some(format!("completed · {count} records"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_tool_output_reaches_the_transcript_unchanged() {
        let result = serde_json::json!({"output": "completed · 3 findings"});

        assert_eq!(rendered_tool_result(&result), "completed · 3 findings");
    }

    #[test]
    fn triage_advisory_report_reaches_the_tui_transcript_unchanged() {
        let output = "triage complete\nCross-tool candidates: 1 cluster(s), report only; no verdict inheritance.\nReviewed refutation (human): 82% (9/11 reviewed; 11/37 emitted).";
        let result = serde_json::json!({"output": output});

        assert_eq!(rendered_tool_result(&result), output);
    }

    #[test]
    fn a_long_structured_artifact_is_clipped_with_a_pointer_to_the_full_record() {
        // A pretty-printed artifact used to expand into hundreds of transcript
        // rows and evict the run it belonged to.
        let records = (0..200)
            .map(|index| serde_json::json!({"id": index}))
            .collect::<Vec<_>>();
        let result = serde_json::json!({"data": {"records": records}});

        let rendered = rendered_tool_result(&result);

        assert!(
            rendered.lines().count() <= MAX_RESULT_LOG_LINES + 1,
            "rendered {} lines",
            rendered.lines().count()
        );
        assert!(rendered.contains("more lines · full result in the run's result.json"));
    }

    #[test]
    fn a_curated_tool_report_is_never_clipped_however_long_it_runs() {
        // A tool that writes `output` chose what the operator should read;
        // clipping it would cut the report off mid-narrative.
        let report = (0..40)
            .map(|index| format!("line-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let result = serde_json::json!({ "output": report });

        let rendered = rendered_tool_result(&result);

        assert!(rendered.contains("line-39"));
        assert!(!rendered.contains("full result in the run's result.json"));
    }

    #[test]
    fn one_enormous_dumped_line_is_clipped_by_bytes_even_though_it_is_a_single_line() {
        let result = serde_json::json!({"data": {"blob": "x".repeat(50_000)}});

        let rendered = rendered_tool_result(&result);

        assert!(rendered.len() < 50_000, "rendered {} bytes", rendered.len());
        assert!(rendered.contains("full result in the run's result.json"));
    }

    #[test]
    fn failed_receipt_keeps_the_cause_and_points_to_full_details() {
        let result = serde_json::json!({
            "status": "failed",
            "fallback_context": {
                "failedStage": "semgrep:scan",
                "cause": "semgrep binary missing",
                "recoveryOptions": ["Install the selected binary, then rerun."],
                "detail": "x".repeat(40_000),
            }
        });
        let rendered = rendered_tool_result(&result);
        assert!(rendered.contains("failed"));
        assert!(rendered.contains("Stage: semgrep:scan"));
        assert!(rendered.contains("Cause: semgrep binary missing"));
        assert!(rendered.contains("Next: Install the selected binary"));
        assert!(rendered.contains("Details: failure"));
        assert!(!rendered.contains("xxxx"));
        assert!(rendered.lines().count() <= 7);
    }

    #[test]
    fn partial_count_is_not_presented_as_completed() {
        let result = serde_json::json!({
            "status": "partial", "summary": "Some files were inspected",
            "data": {"count": 3}, "errors": ["Selected scope could not be read"],
            "warnings": ["Coverage is incomplete"]
        });
        let rendered = rendered_tool_result(&result);
        assert!(rendered.starts_with("partial"));
        assert!(rendered.contains("Selected scope could not be read"));
        assert!(rendered.contains("Coverage is incomplete"));
        assert!(!rendered.contains("completed"));
    }

    #[test]
    fn failure_fields_are_bounded_without_splitting_unicode() {
        let result = serde_json::json!({
            "status": "failed", "errors": ["é".repeat(50_000), "Other cause"]
        });
        let rendered = rendered_tool_result(&result);
        assert!(rendered.contains("…"));
        assert!(rendered.contains("2 error(s)"));
        assert!(rendered.len() < 1000);
    }

    #[test]
    fn failed_curated_output_keeps_its_explicit_narrative() {
        let output = "The selected scope could not be read.\nRetained observations: 3.";
        let result = serde_json::json!({"status":"failed", "output": output});
        assert_eq!(rendered_tool_result(&result), output);
    }

    #[test]
    fn clipping_never_splits_a_multibyte_character() {
        let result = serde_json::json!({"data": {"blob": "é".repeat(MAX_RESULT_LOG_BYTES)}});

        // Panics on a bad boundary; reaching the assert is the real check.
        assert!(rendered_tool_result(&result).len() <= MAX_RESULT_LOG_BYTES + 128);
    }
}
