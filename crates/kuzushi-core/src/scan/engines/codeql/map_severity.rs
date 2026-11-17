use super::*;

pub(crate) fn map_codeql_severity(
    problem_severity: Option<&str>,
    result_level: Option<&str>,
) -> Severity {
    match problem_severity
        .and_then(non_empty_string)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("error") => return Severity::High,
        Some("warning") => return Severity::Medium,
        Some("recommendation") => return Severity::Low,
        _ => {}
    }

    match result_level
        .and_then(non_empty_string)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("error") => Severity::High,
        Some("warning") => Severity::Medium,
        Some("note") => Severity::Info,
        _ => Severity::Low,
    }
}

pub(crate) fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}
