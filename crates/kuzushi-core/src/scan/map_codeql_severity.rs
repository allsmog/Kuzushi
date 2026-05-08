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

pub(crate) fn normalize_artifact_uri(uri: &str) -> String {
    let mut normalized = if let Some(rest) = uri.strip_prefix("file://") {
        percent_decode(rest)
    } else {
        uri.to_string()
    };

    normalized = normalized.replace('\\', "/");
    while normalized.starts_with('/') {
        normalized.remove(0);
    }
    if normalized.len() > 3
        && normalized.as_bytes()[1] == b':'
        && normalized.as_bytes()[2] == b'/'
        && normalized.as_bytes()[0].is_ascii_alphabetic()
    {
        normalized = normalized[3..].to_string();
    }
    normalized
}

pub(crate) fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}
