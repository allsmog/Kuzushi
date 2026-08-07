use super::threat_model::threat_model_absence_hint;
use crate::ShellApp;
use kuzushi_core::Severity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatStrideModel {
    pub(crate) header: String,
    pub(crate) rows: Vec<ThreatStrideRow>,
    /// Set only when no threat model backs the view; the rollup then names the
    /// missing artifact instead of showing categories it cannot measure.
    pub(crate) empty_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatStrideRow {
    pub(crate) tone: ThreatStrideTone,
    pub(crate) cells: [String; 4],
    pub(crate) detail: Option<String>,
    /// Full member rows (id · severity · title), one per matching threat —
    /// the rollup names every threat instead of a 2-title teaser string.
    pub(crate) members: Vec<ThreatStrideMember>,
    issue_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatStrideMember {
    pub(crate) tone: ThreatStrideTone,
    pub(crate) id: String,
    pub(crate) severity: String,
    pub(crate) title: String,
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
        .unwrap_or_else(|| empty_stride_rollup(app))
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
    let mut row = threat_stride_row(
        category.letter,
        max_severity(&matching),
        category.label,
        matching.len(),
        String::new(),
    );
    row.members = matching
        .iter()
        .map(|threat| stride_member(threat))
        .collect();
    row
}

fn stride_member(threat: &serde_json::Value) -> ThreatStrideMember {
    let severity = threat_impact(threat).unwrap_or(Severity::Unknown);
    ThreatStrideMember {
        tone: ThreatStrideTone::from_severity(severity),
        id: threat
            .get("displayId")
            .or_else(|| threat.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .to_string(),
        severity: severity.as_str().to_uppercase(),
        title: threat
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("untitled")
            .to_string(),
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

fn empty_stride_rollup(app: &ShellApp) -> ThreatStrideModel {
    ThreatStrideModel {
        header: "STRIDE ROLLUP".to_string(),
        rows: Vec::new(),
        empty_hint: Some(threat_model_absence_hint(app)),
    }
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
        members: Vec::new(),
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
        empty_hint: None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::threat_model::{
        app_with_threat_model_json, THREAT_MODEL_NO_THREATS_HINT, THREAT_MODEL_TARGETLESS_HINT,
    };
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
        let members = &rollup.rows[0].members;
        assert_eq!(members.len(), 2, "every matching threat gets a member row");
        assert_eq!(members[0].id, "T-001");
        assert_eq!(members[0].severity, "HIGH");
        assert_eq!(members[0].title, "spoofed login");
        assert_eq!(members[1].title, "stolen token");
        assert_eq!(rollup.rows[1].tone, ThreatStrideTone::Critical);
        assert_eq!(rollup.rows[1].members[0].title, "config tamper");
        assert_eq!(rollup.rows[2].tone, ThreatStrideTone::Low);
        assert!(rollup.rows[2].members.is_empty());
        assert_eq!(rollup.rows[3].members[0].title, "log leak");
    }

    #[test]
    fn threat_stride_rollup_from_doc_returns_none_on_empty_or_missing_threats() {
        assert!(threat_stride_rollup_from_doc(&json!({})).is_none());
        assert!(threat_stride_rollup_from_doc(&json!({"threats": []})).is_none());
        assert!(threat_stride_rollup_from_doc(&json!({"threats": null})).is_none());
    }

    #[test]
    fn threat_stride_rollup_without_a_target_is_empty_with_a_targetless_hint() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        let rollup = threat_stride_rollup(&app);

        assert_eq!(rollup.header, "STRIDE ROLLUP");
        assert!(rollup.rows.is_empty(), "no doc means no measured category");
        assert_eq!(
            rollup.empty_hint.as_deref(),
            Some(THREAT_MODEL_TARGETLESS_HINT)
        );
    }

    #[test]
    fn threat_stride_rollup_with_a_zero_threat_model_does_not_claim_the_model_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let app = app_with_threat_model_json(&temp, r#"{"threats": []}"#);

        let rollup = threat_stride_rollup(&app);

        assert_eq!(rollup.header, "STRIDE ROLLUP");
        assert!(
            rollup.rows.is_empty(),
            "no threat means no measured category"
        );
        assert_eq!(
            rollup.empty_hint.as_deref(),
            Some(THREAT_MODEL_NO_THREATS_HINT)
        );
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
