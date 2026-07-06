use super::*;

pub(in crate::capabilities::carlini_threat_hunt) fn carlini_severity(value: &str) -> Severity {
    Severity::from_scanner_label(value)
}

pub(in crate::capabilities::carlini_threat_hunt) fn critical_count(threats: &[Value]) -> usize {
    threats
        .iter()
        .filter(|threat| {
            object_string_value(threat, &["impact"])
                .is_some_and(|impact| impact.eq_ignore_ascii_case("critical"))
        })
        .count()
}
