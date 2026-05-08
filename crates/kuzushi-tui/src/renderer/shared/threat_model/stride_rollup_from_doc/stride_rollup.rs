use super::*;

pub(crate) fn stride_rollup_from_doc(
    doc: &serde_json::Value,
) -> Option<Vec<(&'static str, Severity, &'static str, usize, String)>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let cats: [(&'static str, &'static str, &'static str); 6] = [
        ("S", "spoofing", "Spoofing"),
        ("T", "tampering", "Tampering"),
        ("R", "repudiation", "Repudiation"),
        ("I", "information-disclosure", "Info-disclosure"),
        ("D", "denial-of-service", "DoS"),
        ("E", "elevation-of-privilege", "Elev-of-priv"),
    ];
    let mut rows = Vec::with_capacity(6);
    for (letter, key, label) in cats {
        let matching: Vec<&serde_json::Value> = threats
            .iter()
            .filter(|t| {
                t.get("category")
                    .and_then(|c| c.as_str())
                    .map(|c| c.to_lowercase().replace('_', "-"))
                    .as_deref()
                    == Some(key)
            })
            .collect();
        let count = matching.len();
        let severity = matching
            .iter()
            .map(|t| {
                t.get("impact")
                    .and_then(|s| s.as_str())
                    .map(impact_to_severity)
                    .unwrap_or(Severity::Medium)
            })
            .max_by_key(|s| severity_rank(*s))
            .unwrap_or(Severity::Low);
        let description = matching
            .iter()
            .filter_map(|t| {
                t.get("title")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
            })
            .take(2)
            .collect::<Vec<_>>()
            .join(", ");
        rows.push((letter, severity, label, count, description));
    }
    Some(rows)
}
