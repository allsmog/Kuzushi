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
pub(crate) struct ThreatStrideModel {
    pub(crate) header: String,
    pub(crate) rows: Vec<ThreatStrideRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatStrideRow {
    pub(crate) tone: ThreatStrideTone,
    pub(crate) cells: [String; 4],
    pub(crate) detail: Option<String>,
    issue_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreatStrideTone {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

impl ThreatStrideTone {
    fn from_severity(severity: Severity) -> Self {
        match severity {
            Severity::Critical => Self::Critical,
            Severity::High => Self::High,
            Severity::Medium => Self::Medium,
            Severity::Low => Self::Low,
            Severity::Info => Self::Info,
            Severity::Unknown => Self::Unknown,
        }
    }
}

pub(crate) fn threat_stride_rollup(app: &ShellApp) -> ThreatStrideModel {
    super::threat_model_doc(app)
        .as_ref()
        .and_then(threat_stride_rollup_from_doc)
        .unwrap_or_else(canonical_stride_rollup)
}

pub(crate) fn threat_stride_rollup_from_doc(doc: &serde_json::Value) -> Option<ThreatStrideModel> {
    let threats = non_empty_threats(doc)?;
    let rows = stride_categories()
        .into_iter()
        .map(|category| row_for_category(category, threats))
        .collect();
    Some(threat_stride_model(rows))
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
    threat_stride_row(
        category.letter,
        max_severity(&matching),
        category.label,
        matching.len(),
        threat_titles(&matching).join(", "),
    )
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

fn canonical_stride_rollup() -> ThreatStrideModel {
    let rows = CANONICAL_STRIDE_ROWS
        .into_iter()
        .map(threat_stride_row_from_spec)
        .collect();
    threat_stride_model(rows)
}

fn threat_stride_row_from_spec(
    (letter, severity, category, count, description): StrideSpec,
) -> ThreatStrideRow {
    threat_stride_row(letter, severity, category, count, description.to_string())
}

fn threat_stride_row(
    letter: &str,
    severity: Severity,
    category: &str,
    count: usize,
    description: String,
) -> ThreatStrideRow {
    ThreatStrideRow {
        tone: ThreatStrideTone::from_severity(severity),
        cells: [
            letter.to_string(),
            category.to_string(),
            count.to_string(),
            issue_label(count).to_string(),
        ],
        detail: (!description.is_empty()).then_some(description),
        issue_count: count,
    }
}

fn issue_label(count: usize) -> &'static str {
    if count == 1 {
        "issue"
    } else {
        "issues"
    }
}

fn threat_stride_model(rows: Vec<ThreatStrideRow>) -> ThreatStrideModel {
    let issue_count: usize = rows.iter().map(|row| row.issue_count).sum();
    ThreatStrideModel {
        header: format!("STRIDE ROLLUP · {issue_count} issues"),
        rows,
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

        assert_eq!(rollup.header, "STRIDE ROLLUP · 4 issues");
        assert_eq!(rollup.rows.len(), 6);
        assert_eq!(rollup.rows[0].cells[0], "S");
        assert_eq!(rollup.rows[0].tone, ThreatStrideTone::High);
        assert_eq!(rollup.rows[0].cells[2], "2");
        assert_eq!(rollup.rows[0].cells[3], "issues");
        assert!(rollup.rows[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("spoofed login"));
        assert!(rollup.rows[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("stolen token"));
        assert_eq!(rollup.rows[1].tone, ThreatStrideTone::Critical);
        assert_eq!(rollup.rows[1].detail.as_deref(), Some("config tamper"));
        assert_eq!(rollup.rows[2].tone, ThreatStrideTone::Low);
        assert_eq!(rollup.rows[2].detail, None);
        assert_eq!(rollup.rows[3].detail.as_deref(), Some("log leak"));
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

        assert_eq!(rollup.rows[4].cells[0], "D");
        assert_eq!(rollup.rows[4].cells[2], "1");
        assert_eq!(rollup.rows[5].cells[0], "E");
        assert_eq!(rollup.rows[5].cells[2], "1");
        assert_eq!(rollup.rows[5].tone, ThreatStrideTone::Critical);
    }
}
