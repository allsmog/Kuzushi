use super::threat_model::threat_model_absence_hint;
use crate::ShellApp;
use kuzushi_core::Severity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatStoryModel {
    pub(crate) header: String,
    pub(crate) rows: Vec<ThreatStoryRow>,
    /// Set only when no threat model backs the view; the list then names the
    /// missing artifact instead of inventing attacker stories.
    pub(crate) empty_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatStoryRow {
    pub(crate) tone: ThreatStoryTone,
    pub(crate) cells: [String; 3],
    pub(crate) details: Vec<ThreatStoryDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatStoryDetail {
    pub(crate) label: &'static str,
    pub(crate) value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreatStoryTone {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

impl ThreatStoryTone {
    pub(crate) fn from_severity(severity: Severity) -> Self {
        match severity {
            Severity::Critical => Self::Critical,
            Severity::High => Self::High,
            Severity::Medium => Self::Medium,
            Severity::Low => Self::Low,
            Severity::Info => Self::Info,
            Severity::Unknown => Self::Unknown,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
            Self::Unknown => 0,
        }
    }
}

pub(crate) fn threat_story_model(app: &ShellApp) -> ThreatStoryModel {
    super::threat_model_doc(app)
        .as_ref()
        .and_then(threat_story_model_from_doc)
        .unwrap_or_else(|| empty_story_model(app))
}

pub(crate) fn threat_story_model_from_doc(doc: &serde_json::Value) -> Option<ThreatStoryModel> {
    let threats = non_empty_threats(doc)?;
    let mut rows: Vec<ThreatStoryRow> = threats.iter().filter_map(story_from_threat).collect();
    rows.sort_by_key(|story| std::cmp::Reverse(story.tone.rank()));
    Some(threat_story_model_from_rows(rows))
}

fn non_empty_threats(doc: &serde_json::Value) -> Option<&[serde_json::Value]> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    Some(threats)
}

fn story_from_threat(threat: &serde_json::Value) -> Option<ThreatStoryRow> {
    let listing_id = threat_listing_id(threat)?;
    let mut row = threat_story_row(
        listing_id.clone(),
        threat_severity(threat),
        string_field(threat, "title").unwrap_or_else(|| "untitled".to_string()),
        string_field(threat, "attackVector").unwrap_or_default(),
        first_affected_file_location(threat),
    );
    row.details.extend(artifact_id_details(threat, &listing_id));
    Some(row)
}

/// Cross-referencing threat-model.json must work in both directions: when
/// the listed id differs from the artifact's model-emitted `id`/`stableId`,
/// disclose them as detail rows instead of leaving the operator to guess.
fn artifact_id_details(threat: &serde_json::Value, listing_id: &str) -> Vec<ThreatStoryDetail> {
    let mut details = Vec::new();
    if let Some(id) = string_field(threat, "id").filter(|id| id != listing_id) {
        details.push(ThreatStoryDetail {
            label: "id     ",
            value: id,
        });
    }
    if let Some(stable) = string_field(threat, "stableId").filter(|id| id != listing_id) {
        details.push(ThreatStoryDetail {
            label: "stable ",
            value: stable,
        });
    }
    details
}

/// Harness display ids (T1..Tn) are stable across refines; prefer them over
/// the model-emitted id whenever the document carries one.
fn threat_listing_id(threat: &serde_json::Value) -> Option<String> {
    string_field(threat, "displayId").or_else(|| string_field(threat, "id"))
}

fn threat_severity(threat: &serde_json::Value) -> Severity {
    threat
        .get("impact")
        .and_then(serde_json::Value::as_str)
        .map(super::threat_impact::impact_to_severity)
        .unwrap_or(Severity::Medium)
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(ToString::to_string)
}

fn first_affected_file_location(threat: &serde_json::Value) -> String {
    threat
        .get("affectedFiles")
        .and_then(serde_json::Value::as_array)
        .and_then(|files| files.first())
        .map(format_affected_file)
        .unwrap_or_default()
}

fn format_affected_file(file: &serde_json::Value) -> String {
    let path = file
        .get("filePath")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let line = file
        .get("startLine")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    match (path.is_empty(), line) {
        (true, _) => String::new(),
        (false, 0) => path.to_string(),
        (false, _) => format!("{path}:{line}"),
    }
}

fn empty_story_model(app: &ShellApp) -> ThreatStoryModel {
    ThreatStoryModel {
        header: "ATTACKER STORIES".to_string(),
        rows: Vec::new(),
        empty_hint: Some(threat_model_absence_hint(app)),
    }
}

fn threat_story_model_from_rows(rows: Vec<ThreatStoryRow>) -> ThreatStoryModel {
    // Every story renders; the Threat view scrolls (pinned tabs) instead of
    // silently capping the list below the advertised count.
    ThreatStoryModel {
        header: format!("ATTACKER STORIES · {}", rows.len()),
        rows,
        empty_hint: None,
    }
}

fn threat_story_row(
    id: String,
    severity: Severity,
    title: String,
    attack: String,
    location: String,
) -> ThreatStoryRow {
    ThreatStoryRow {
        tone: ThreatStoryTone::from_severity(severity),
        cells: [id, severity.as_str().to_uppercase(), title],
        details: story_details(attack, location),
    }
}

fn story_details(attack: String, location: String) -> Vec<ThreatStoryDetail> {
    [
        story_detail("attack ", attack),
        story_detail("loc    ", location),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn story_detail(label: &'static str, value: String) -> Option<ThreatStoryDetail> {
    (!value.is_empty()).then_some(ThreatStoryDetail { label, value })
}

#[cfg(test)]
mod tests {
    use super::super::threat_model::{
        app_with_threat_model_json, THREAT_MODEL_NO_THREATS_HINT, THREAT_MODEL_TARGETLESS_HINT,
    };
    use super::*;
    use serde_json::json;

    #[test]
    fn threat_story_model_from_doc_sorts_by_impact_severity() {
        let doc = json!({
            "threats": [
                {"id": "T-001", "title": "low risk", "impact": "low", "category": "spoofing", "attackVector": "vec1"},
                {"id": "T-002", "title": "critical bug", "impact": "critical", "category": "tampering", "attackVector": "vec2",
                 "affectedFiles": [{"filePath": "src/api.rs", "startLine": 42}]},
                {"id": "T-003", "title": "high issue", "impact": "high", "category": "elevation_of_privilege"}
            ]
        });

        let model = threat_story_model_from_doc(&doc).expect("non-empty stories");

        assert_eq!(model.header, "ATTACKER STORIES · 3");
        assert_eq!(model.rows.len(), 3);
        assert_eq!(model.rows[0].cells[0], "T-002");
        assert_eq!(model.rows[0].tone, ThreatStoryTone::Critical);
        assert_eq!(model.rows[0].details[1].value, "src/api.rs:42");
        assert_eq!(model.rows[1].cells[0], "T-003");
        assert_eq!(model.rows[1].tone, ThreatStoryTone::High);
        assert_eq!(model.rows[2].cells[0], "T-001");
    }

    #[test]
    fn threat_story_model_renders_every_row_without_a_cap() {
        let doc = json!({
            "threats": [
                {"id": "T-001", "title": "one", "impact": "high"},
                {"id": "T-002", "title": "two", "impact": "high"},
                {"id": "T-003", "title": "three", "impact": "high"},
                {"id": "T-004", "title": "four", "impact": "high"},
                {"id": "T-005", "title": "five", "impact": "high"},
                {"id": "T-006", "title": "six", "impact": "high"},
                {"id": "T-007", "title": "seven", "impact": "high"},
                {"id": "T-008", "title": "eight", "impact": "high"},
                {"id": "T-009", "title": "nine", "impact": "high"}
            ]
        });

        let model = threat_story_model_from_doc(&doc).expect("non-empty stories");

        assert_eq!(model.header, "ATTACKER STORIES · 9");
        assert_eq!(model.rows.len(), 9);
        assert_eq!(model.rows[8].cells[0], "T-009");
    }

    fn new_contract_doc() -> serde_json::Value {
        json!({
            "assets": [{"asset": "backup catalog", "sensitivity": "critical"}],
            "recommendedMitigations": [
                {"mitigation": "pin CI actions", "threatIds": ["tm-abc"], "closesClass": "yes", "effort": "S"}
            ],
            "threats": [
                {"id": "model-emitted-1", "displayId": "T7", "stableId": "tm-abc",
                 "title": "wipeout", "impact": "existential"},
                {"id": "model-emitted-2", "title": "no display id yet", "impact": "low"}
            ]
        })
    }

    #[test]
    fn threat_story_rows_prefer_harness_display_ids_and_read_new_contract_docs() {
        let model = threat_story_model_from_doc(&new_contract_doc()).expect("non-empty stories");

        assert_eq!(
            model.rows[0].cells[0], "T7",
            "displayId wins over the model id"
        );
        assert_eq!(
            model.rows[0].tone,
            ThreatStoryTone::Critical,
            "existential renders critical"
        );
        assert_eq!(
            model.rows[1].cells[0], "model-emitted-2",
            "id fallback when displayId absent"
        );
    }

    #[test]
    fn threat_story_details_disclose_artifact_ids_when_they_differ() {
        let model = threat_story_model_from_doc(&new_contract_doc()).expect("non-empty stories");

        assert!(
            model.rows[0]
                .details
                .iter()
                .any(|detail| detail.value == "model-emitted-1"),
            "artifact id disclosed when it differs from the listing id"
        );
        assert!(
            model.rows[0]
                .details
                .iter()
                .any(|detail| detail.value == "tm-abc"),
            "stableId disclosed for cross-referencing the artifact"
        );
    }

    #[test]
    fn threat_story_model_without_a_target_is_empty_with_a_targetless_hint() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        let model = threat_story_model(&app);

        assert_eq!(model.header, "ATTACKER STORIES");
        assert!(model.rows.is_empty(), "no doc means no attacker story");
        assert_eq!(
            model.empty_hint.as_deref(),
            Some(THREAT_MODEL_TARGETLESS_HINT)
        );
    }

    #[test]
    fn threat_story_model_with_a_zero_threat_model_does_not_claim_the_model_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let app = app_with_threat_model_json(&temp, r#"{"threats": []}"#);

        let model = threat_story_model(&app);

        assert_eq!(model.header, "ATTACKER STORIES");
        assert!(model.rows.is_empty(), "no threat means no attacker story");
        assert_eq!(
            model.empty_hint.as_deref(),
            Some(THREAT_MODEL_NO_THREATS_HINT)
        );
    }

    #[test]
    fn threat_story_model_from_doc_returns_none_without_threats() {
        assert!(threat_story_model_from_doc(&json!({})).is_none());
        assert!(threat_story_model_from_doc(&json!({"threats": []})).is_none());
        assert!(threat_story_model_from_doc(&json!({"threats": null})).is_none());
    }
}
