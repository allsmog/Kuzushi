pub(super) fn canonical_severity(value: &str) -> String {
    match severity_key(value).as_str() {
        "critical" | "crit" => "critical",
        "high" | "error" => "high",
        "medium" | "med" | "warning" | "warn" => "medium",
        "low" => "low",
        "info" | "informational" | "note" => "info",
        "unknown" => "unknown",
        _ => value.trim(),
    }
    .to_string()
}

pub(super) fn severity_order(severity: &str) -> usize {
    match severity_key(severity).as_str() {
        "critical" | "crit" => 0,
        "high" | "error" => 1,
        "medium" | "med" | "warning" | "warn" => 2,
        "low" => 3,
        "info" | "informational" | "note" => 4,
        "unknown" => 5,
        _ => 6,
    }
}

fn severity_key(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}
