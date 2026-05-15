use crate::ShellApp;
use kuzushi_core::Severity;

type StrideSpec = (&'static str, Severity, &'static str, usize, &'static str);

const CANONICAL_STRIDE_ROWS: [StrideSpec; 6] = [
    (
        "S",
        Severity::High,
        "Spoofing",
        2,
        "jwt without aud-claim, mailgun cname dangling",
    ),
    (
        "T",
        Severity::Medium,
        "Tampering",
        1,
        "worker pool reads unsigned amqp messages",
    ),
    ("R", Severity::Low, "Repudiation", 0, ""),
    (
        "I",
        Severity::Critical,
        "Info-disclosure",
        3,
        "plaintext PII at db→s3 boundary, debug logs",
    ),
    (
        "D",
        Severity::Medium,
        "DoS",
        1,
        "no rate-limit on /checkout/confirm",
    ),
    (
        "E",
        Severity::High,
        "Elev-of-priv",
        1,
        "admin subdomain shares jwt secret with api",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatStrideRow {
    pub(crate) letter: &'static str,
    pub(crate) severity: Severity,
    pub(crate) category: &'static str,
    pub(crate) count: usize,
    pub(crate) description: String,
}

pub(crate) fn threat_stride_rollup(app: &ShellApp) -> Vec<ThreatStrideRow> {
    super::threat_model_doc(app)
        .as_ref()
        .and_then(threat_stride_rollup_from_doc)
        .unwrap_or_else(canonical_stride_rollup)
}

pub(crate) fn threat_stride_rollup_from_doc(
    doc: &serde_json::Value,
) -> Option<Vec<ThreatStrideRow>> {
    let threats = non_empty_threats(doc)?;
    Some(
        stride_categories()
            .into_iter()
            .map(|category| row_for_category(category, threats))
            .collect(),
    )
}

fn non_empty_threats(doc: &serde_json::Value) -> Option<&[serde_json::Value]> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    Some(threats)
}

#[derive(Debug, Clone, Copy)]
struct StrideCategory {
    letter: &'static str,
    key: &'static str,
    label: &'static str,
}

fn stride_categories() -> [StrideCategory; 6] {
    [
        category("S", "spoofing", "Spoofing"),
        category("T", "tampering", "Tampering"),
        category("R", "repudiation", "Repudiation"),
        category("I", "information-disclosure", "Info-disclosure"),
        category("D", "denial-of-service", "DoS"),
        category("E", "elevation-of-privilege", "Elev-of-priv"),
    ]
}

fn category(letter: &'static str, key: &'static str, label: &'static str) -> StrideCategory {
    StrideCategory { letter, key, label }
}

fn row_for_category(category: StrideCategory, threats: &[serde_json::Value]) -> ThreatStrideRow {
    let matching = matching_threats(category.key, threats);
    ThreatStrideRow {
        letter: category.letter,
        severity: max_severity(&matching),
        category: category.label,
        count: matching.len(),
        description: threat_titles(&matching).join(", "),
    }
}

fn matching_threats<'a>(
    category_key: &str,
    threats: &'a [serde_json::Value],
) -> Vec<&'a serde_json::Value> {
    threats
        .iter()
        .filter(|threat| threat_matches(category_key, threat))
        .collect()
}

fn threat_matches(category_key: &str, threat: &serde_json::Value) -> bool {
    normalized_category(threat).as_deref() == Some(category_key)
}

fn normalized_category(threat: &serde_json::Value) -> Option<String> {
    threat
        .get("category")?
        .as_str()
        .map(|category| category.to_lowercase().replace('_', "-"))
}

fn max_severity(threats: &[&serde_json::Value]) -> Severity {
    threats
        .iter()
        .filter_map(|threat| threat_impact(threat))
        .max_by_key(|severity| super::threat_impact::severity_rank(*severity))
        .unwrap_or(Severity::Low)
}

fn threat_impact(threat: &serde_json::Value) -> Option<Severity> {
    threat
        .get("impact")?
        .as_str()
        .map(super::threat_impact::impact_to_severity)
}

fn threat_titles(threats: &[&serde_json::Value]) -> Vec<String> {
    threats
        .iter()
        .filter_map(|threat| threat.get("title")?.as_str().map(ToString::to_string))
        .take(2)
        .collect()
}

fn canonical_stride_rollup() -> Vec<ThreatStrideRow> {
    CANONICAL_STRIDE_ROWS
        .into_iter()
        .map(threat_stride_row_from_spec)
        .collect()
}

fn threat_stride_row_from_spec(
    (letter, severity, category, count, description): StrideSpec,
) -> ThreatStrideRow {
    ThreatStrideRow {
        letter,
        severity,
        category,
        count,
        description: description.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn threat_stride_rollup_from_doc_parses_real_threats() {
        let doc = json!({
            "threats": [
                {"id": "T-001", "category": "spoofing", "title": "spoofed login", "impact": "high"},
                {"id": "T-002", "category": "spoofing", "title": "stolen token", "impact": "medium"},
                {"id": "T-003", "category": "tampering", "title": "config tamper", "impact": "critical"},
                {"id": "T-004", "category": "information-disclosure", "title": "log leak", "impact": "low"}
            ]
        });

        let rollup = threat_stride_rollup_from_doc(&doc).expect("expected rollup");
        let total: usize = rollup.iter().map(|row| row.count).sum();

        assert_eq!(rollup.len(), 6);
        assert_eq!(total, 4);
        assert_eq!(rollup[0].letter, "S");
        assert_eq!(rollup[0].severity, Severity::High);
        assert_eq!(rollup[0].count, 2);
        assert!(rollup[0].description.contains("spoofed login"));
        assert!(rollup[0].description.contains("stolen token"));
        assert_eq!(rollup[1].severity, Severity::Critical);
        assert_eq!(rollup[1].description, "config tamper");
        assert_eq!(rollup[2].severity, Severity::Low);
        assert!(rollup[2].description.is_empty());
        assert_eq!(rollup[3].description, "log leak");
    }

    #[test]
    fn threat_stride_rollup_from_doc_returns_none_on_empty_or_missing_threats() {
        assert!(threat_stride_rollup_from_doc(&json!({})).is_none());
        assert!(threat_stride_rollup_from_doc(&json!({"threats": []})).is_none());
        assert!(threat_stride_rollup_from_doc(&json!({"threats": null})).is_none());
    }

    #[test]
    fn threat_stride_rollup_from_doc_normalizes_underscored_categories() {
        let doc = json!({
            "threats": [
                {"category": "denial_of_service", "title": "ddos", "impact": "medium"},
                {"category": "elevation_of_privilege", "title": "sudo bypass", "impact": "critical"}
            ]
        });

        let rollup = threat_stride_rollup_from_doc(&doc).expect("expected rollup");

        assert_eq!(rollup[4].letter, "D");
        assert_eq!(rollup[4].count, 1);
        assert_eq!(rollup[5].letter, "E");
        assert_eq!(rollup[5].count, 1);
        assert_eq!(rollup[5].severity, Severity::Critical);
    }
}
