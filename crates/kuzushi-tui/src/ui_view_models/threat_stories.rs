use crate::ShellApp;
use kuzushi_core::Severity;

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
pub(crate) struct ThreatStoryRow {
    pub(crate) id: String,
    pub(crate) severity: Severity,
    pub(crate) title: String,
    pub(crate) attack: String,
    pub(crate) location: String,
}

pub(crate) fn threat_story_rows(app: &ShellApp) -> Vec<ThreatStoryRow> {
    super::threat_model_doc(app)
        .as_ref()
        .and_then(threat_story_rows_from_doc)
        .unwrap_or_else(canonical_story_rows)
}

pub(crate) fn threat_story_rows_from_doc(doc: &serde_json::Value) -> Option<Vec<ThreatStoryRow>> {
    let threats = non_empty_threats(doc)?;
    let mut rows: Vec<ThreatStoryRow> = threats.iter().filter_map(story_from_threat).collect();
    rows.sort_by_key(|story| {
        std::cmp::Reverse(super::threat_impact::severity_rank(story.severity))
    });
    Some(rows)
}

fn non_empty_threats(doc: &serde_json::Value) -> Option<&[serde_json::Value]> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    Some(threats)
}

fn story_from_threat(threat: &serde_json::Value) -> Option<ThreatStoryRow> {
    Some(ThreatStoryRow {
        id: string_field(threat, "id")?,
        severity: threat_severity(threat),
        title: string_field(threat, "title").unwrap_or_else(|| "untitled".to_string()),
        attack: string_field(threat, "attackVector").unwrap_or_default(),
        location: first_affected_file_location(threat),
    })
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

fn canonical_story_rows() -> Vec<ThreatStoryRow> {
    CANONICAL_STORIES
        .into_iter()
        .map(|(id, severity, title, attack, location)| ThreatStoryRow {
            id: id.to_string(),
            severity,
            title: title.to_string(),
            attack: attack.to_string(),
            location: location.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn threat_story_rows_from_doc_sorts_by_impact_severity() {
        let doc = json!({
            "threats": [
                {"id": "T-001", "title": "low risk", "impact": "low", "category": "spoofing", "attackVector": "vec1"},
                {"id": "T-002", "title": "critical bug", "impact": "critical", "category": "tampering", "attackVector": "vec2",
                 "affectedFiles": [{"filePath": "src/api.rs", "startLine": 42}]},
                {"id": "T-003", "title": "high issue", "impact": "high", "category": "elevation_of_privilege"}
            ]
        });

        let stories = threat_story_rows_from_doc(&doc).expect("non-empty stories");

        assert_eq!(stories.len(), 3);
        assert_eq!(stories[0].id, "T-002");
        assert_eq!(stories[0].severity, Severity::Critical);
        assert_eq!(stories[0].location, "src/api.rs:42");
        assert_eq!(stories[1].id, "T-003");
        assert_eq!(stories[1].severity, Severity::High);
        assert_eq!(stories[2].id, "T-001");
    }

    #[test]
    fn threat_story_rows_from_doc_returns_none_without_threats() {
        assert!(threat_story_rows_from_doc(&json!({})).is_none());
        assert!(threat_story_rows_from_doc(&json!({"threats": []})).is_none());
        assert!(threat_story_rows_from_doc(&json!({"threats": null})).is_none());
    }
}
