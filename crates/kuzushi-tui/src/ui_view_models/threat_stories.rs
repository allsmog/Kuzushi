use crate::ShellApp;
use kuzushi_core::Severity;

const THREAT_STORY_VISIBLE_LIMIT: usize = 8;

type StorySpec = (
    &'static str,
    Severity,
    &'static str,
    &'static str,
    &'static str,
);

const CANONICAL_STORIES: [StorySpec; 4] = [
    (
        "T-001",
        Severity::Critical,
        "sql injection via order_id concatenation",
        "POST /orders/<id>",
        "apps/api/orders.rs:142",
    ),
    (
        "T-002",
        Severity::Critical,
        "prompt injection sink reads user body",
        "user message → llm context",
        "apps/web/agents/concierge.ts:88",
    ),
    (
        "T-003",
        Severity::High,
        "jwt verify accepts alg=none",
        "forged Authorization header",
        "apps/api/auth/jwt.rs:54",
    ),
    (
        "T-004",
        Severity::High,
        "shell exec from cron payload",
        "scheduled job pulls untrusted task",
        "jobs/worker.py:213",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatStoryModel {
    pub(crate) header: String,
    pub(crate) rows: Vec<ThreatStoryRow>,
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
        .unwrap_or_else(canonical_story_model)
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
    Some(threat_story_row(
        string_field(threat, "id")?,
        threat_severity(threat),
        string_field(threat, "title").unwrap_or_else(|| "untitled".to_string()),
        string_field(threat, "attackVector").unwrap_or_default(),
        first_affected_file_location(threat),
    ))
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

fn canonical_story_model() -> ThreatStoryModel {
    let rows = CANONICAL_STORIES
        .into_iter()
        .map(|(id, severity, title, attack, location)| {
            threat_story_row(
                id.to_string(),
                severity,
                title.to_string(),
                attack.to_string(),
                location.to_string(),
            )
        })
        .collect();
    threat_story_model_from_rows(rows)
}

fn threat_story_model_from_rows(rows: Vec<ThreatStoryRow>) -> ThreatStoryModel {
    let story_count = rows.len();
    ThreatStoryModel {
        header: format!("ATTACKER STORIES · {story_count}"),
        rows: rows.into_iter().take(THREAT_STORY_VISIBLE_LIMIT).collect(),
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
    fn threat_story_model_from_doc_caps_visible_rows() {
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
        assert_eq!(model.rows.len(), 8);
        assert_eq!(model.rows[7].cells[0], "T-008");
    }

    #[test]
    fn threat_story_model_from_doc_returns_none_without_threats() {
        assert!(threat_story_model_from_doc(&json!({})).is_none());
        assert!(threat_story_model_from_doc(&json!({"threats": []})).is_none());
        assert!(threat_story_model_from_doc(&json!({"threats": null})).is_none());
    }
}
