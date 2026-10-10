//! The same recorded inspection receipt supplies shell and plain output.
use serde_json::Value;

pub(super) fn append_inspection_lines(receipts: &[Value], lines: &mut Vec<String>) {
    for receipt in receipts {
        lines.extend(inspection_lines(receipt));
    }
}

fn inspection_lines(receipt: &Value) -> Vec<String> {
    let engine = text_field(receipt, "/engine");
    if let Some(message) = receipt.get("message").and_then(Value::as_str) {
        return vec![format!("  {engine} inspection: {message}")];
    }
    vec![
        format!(
            "  {engine} inspection: {} ({})",
            text_field(receipt, "/target"),
            text_field(receipt, "/selection")
        ),
        format!(
            "    Job limits: {} entries, {} content bytes, {} bytes per file, {} findings",
            count_field(receipt, "/configuredLimits/maxEntries"),
            count_field(receipt, "/configuredLimits/maxTotalBytes"),
            count_field(receipt, "/configuredLimits/maxFileBytes"),
            count_field(receipt, "/configuredLimits/maxFindings")
        ),
        format!(
            "    Job consumed: {} entries, {} reserved content bytes, {} findings",
            count_field(receipt, "/totals/entriesReserved"),
            count_field(receipt, "/totals/contentBytesReserved"),
            count_field(receipt, "/totals/findings")
        ),
        "    Content reservations are conservative. Coverage gaps remain in the run receipt."
            .into(),
    ]
}

fn count_field(receipt: &Value, path: &str) -> String {
    receipt
        .pointer(path)
        .and_then(Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".into())
}

fn text_field<'a>(receipt: &'a Value, path: &str) -> &'a str {
    receipt
        .pointer(path)
        .and_then(Value::as_str)
        .unwrap_or("unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn uses_original_job_limits_and_cumulative_consumption() {
        let receipt = json!({"engine":"secret-scan","target":"service","selection":"exact-files",
            "inspection":{"maxTotalBytes":100},"configuredLimits":{"maxEntries":2,"maxTotalBytes":1024,"maxFileBytes":1024,"maxFindings":1},
            "totals":{"entriesReserved":2,"contentBytesReserved":900,"findings":1}});
        let lines = inspection_lines(&receipt).join("\n");
        assert!(lines.contains("1024 content bytes"));
        assert!(lines.contains("900 reserved content bytes"));
        assert!(!lines.contains("100 content bytes"));
    }

    #[test]
    fn absent_accounting_is_unavailable_and_failure_stays_visible() {
        assert!(inspection_lines(&json!({"engine":"secret-scan"}))
            .join("\n")
            .contains("unavailable entries"));
        assert_eq!(
            inspection_lines(&json!({"engine":"secret-scan","message":"Accounting unavailable"})),
            vec!["  secret-scan inspection: Accounting unavailable"]
        );
    }
}
