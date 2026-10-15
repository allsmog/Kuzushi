//! The same recorded inspection receipt supplies shell and plain output.
use serde_json::Value;

pub(in crate::modules) fn append_inspection_lines(receipts: &[Value], lines: &mut Vec<String>) {
    for receipt in receipts {
        lines.extend(inspection_lines(receipt));
    }
}

fn inspection_lines(receipt: &Value) -> Vec<String> {
    if let Some(lines) = engine_inspection_lines(receipt) {
        return lines;
    }
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

fn engine_inspection_lines(receipt: &Value) -> Option<Vec<String>> {
    match receipt.get("engine").and_then(Value::as_str)? {
        "semgrep" => Some(semgrep_inspection_lines(receipt)),
        "iac-scan" => Some(iac_inspection_lines(receipt)),
        "cargo-audit" => Some(cargo_audit_inspection_lines(receipt)),
        _ => None,
    }
}

fn cargo_audit_inspection_lines(receipt: &Value) -> Vec<String> {
    let mode = if receipt["offline"] == true {
        "offline; no database update or yanked-package check"
    } else {
        "enabled; database updates and yanked-package checks permitted"
    };
    let captures = receipt["capturedLockfiles"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    vec![
        "  cargo-audit lockfile inspection".into(),
        format!("    Job time allowance: {} ms; elapsed: {} ms",count_field(receipt,"/configuredLimits/timeoutMs"),count_field(receipt,"/elapsedMs")),
        format!("    Lockfile capture limit: {} bytes; captured: {captures}",count_field(receipt,"/configuredLimits/maxLockfileBytes")),
        format!("    Advisory network: {mode}"),
        format!("    Database: {}; stale database permitted: {}",text_field(receipt,"/advisoryDb"),receipt["allowStale"]),
        "    Captured lockfile hashes are in the run receipt. Database freshness is not established by the source SHA.".into(),
        format!("    Coverage: {}",text_field(receipt,"/coverage")),
    ]
}

fn semgrep_inspection_lines(receipt: &Value) -> Vec<String> {
    if let Some(message) = receipt.get("message").and_then(Value::as_str) {
        return vec![format!("  Semgrep time allowance: {message}")];
    }
    vec![
        format!(
            "  Semgrep subprocess time allowance: {} ms; elapsed {} ms",
            count_field(receipt, "/configuredLimits/timeoutMs"),
            count_field(receipt, "/elapsedMs")
        ),
        "    Shared across this job's roots and file batches. Source authentication is separate."
            .into(),
        format!("    Exact-file process limits: {} files; {} encoded argument bytes, including executable and fixed arguments.",
            count_field(receipt,"/exactFileBatching/maxFilesPerProcess"),
            count_field(receipt,"/exactFileBatching/maxEncodedArgumentBytes")),
        format!("    Semgrep scan workers within this job: {}. Supporting threads and source authentication are separate.", count_field(receipt,"/configuredLimits/jobs")),
        "    Deadline stops remaining subprocess work. Coverage gaps remain in the run receipt."
            .into(),
    ]
}

fn iac_inspection_lines(receipt: &Value) -> Vec<String> {
    if let Some(message) = receipt.get("message").and_then(Value::as_str) {
        return vec![
            format!("  iac-scan inspection: {message}"),
            iac_remaining_allowance(receipt),
        ];
    }
    vec![format!("  iac-scan inspection: {} (directory)", text_field(receipt, "/target")),
        format!("    Job limits: {} entries, {} content bytes, {} bytes per file",
            count_field(receipt, "/configuredLimits/maxEntries"),
            count_field(receipt, "/configuredLimits/maxTotalBytes"),
            count_field(receipt, "/configuredLimits/maxFileBytes")),
        format!("    Job consumed: {} entries, {} content bytes read",
            count_field(receipt, "/sharedJobAllowance/entriesUsed"),
            count_field(receipt, "/sharedJobAllowance/bytesRead")),
        format!("    Excluded: {} symlinks, {} ignored directories; depth limit {}",
            count_field(receipt, "/inspection/symlinksExcluded"),
            count_field(receipt, "/inspection/directoriesExcluded"),
            count_field(receipt, "/inspection/maxDepth")),
        "    Inspection limits do not bound source authentication. Coverage gaps remain in the run receipt.".into()]
}

fn iac_remaining_allowance(receipt: &Value) -> String {
    if receipt.get("unresolvedAllowance").is_some() {
        return format!(
            "    Unresolved allowance: {} entries, {} content bytes held",
            count_field(receipt, "/unresolvedAllowance/maxEntries"),
            count_field(receipt, "/unresolvedAllowance/maxTotalBytes")
        );
    }
    format!(
        "    Remaining allowance: {} entries, {} content bytes; root skipped",
        count_field(receipt, "/remainingAllowance/entries"),
        count_field(receipt, "/remainingAllowance/bytes")
    )
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

    #[test]
    fn semgrep_time_receipt_does_not_claim_source_coverage_or_zero_for_unknown_time() {
        let text = inspection_lines(
            &json!({"engine":"semgrep", "configuredLimits":{"timeoutMs":60000},"elapsedMs":null}),
        )
        .join("\n");
        assert!(text.contains("60000 ms; elapsed unavailable ms"));
        assert!(text.contains("Source authentication is separate"));
        assert!(!text.contains("entries") && !text.contains("elapsed 0 ms"));
    }
}
