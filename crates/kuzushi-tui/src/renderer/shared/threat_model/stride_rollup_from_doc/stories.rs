use super::*;

/// `(id, severity, title, attack_vector, location)` — one attacker story.
pub(crate) type StoryRow = (String, Severity, String, String, String);

/// Extract attacker stories from the persisted threat model. Each `threats[]`
/// entry becomes one story, sorted by impact severity (highest first).
pub(crate) fn stories_from_doc(doc: &serde_json::Value) -> Option<Vec<StoryRow>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let mut rows: Vec<StoryRow> = threats
        .iter()
        .filter_map(|t| {
            let id = t.get("id").and_then(|v| v.as_str())?.to_string();
            let severity = t
                .get("impact")
                .and_then(|v| v.as_str())
                .map(impact_to_severity)
                .unwrap_or(Severity::Medium);
            let title = t
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("untitled")
                .to_string();
            let attack = t
                .get("attackVector")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let location = t
                .get("affectedFiles")
                .and_then(|v| v.as_array())
                .and_then(|files| files.first())
                .map(|f| {
                    let path = f.get("filePath").and_then(|v| v.as_str()).unwrap_or("");
                    let line = f.get("startLine").and_then(|v| v.as_u64()).unwrap_or(0);
                    if path.is_empty() {
                        String::new()
                    } else if line == 0 {
                        path.to_string()
                    } else {
                        format!("{path}:{line}")
                    }
                })
                .unwrap_or_default();
            Some((id, severity, title, attack, location))
        })
        .collect();
    rows.sort_by_key(|(_, sev, _, _, _)| std::cmp::Reverse(severity_rank(*sev)));
    Some(rows)
}

/// Fixture matching the canonical 4 attacker stories used when no real
/// threat model is loaded.
pub(crate) fn canonical_stories_fixture() -> Vec<StoryRow> {
    vec![
        (
            "T-001".to_string(),
            Severity::Critical,
            "sql injection via order_id concatenation".to_string(),
            "POST /orders/<id>".to_string(),
            "apps/api/orders.rs:142".to_string(),
        ),
        (
            "T-002".to_string(),
            Severity::Critical,
            "prompt injection sink reads user body".to_string(),
            "user message → llm context".to_string(),
            "apps/web/agents/concierge.ts:88".to_string(),
        ),
        (
            "T-003".to_string(),
            Severity::High,
            "jwt verify accepts alg=none".to_string(),
            "forged Authorization header".to_string(),
            "apps/api/auth/jwt.rs:54".to_string(),
        ),
        (
            "T-004".to_string(),
            Severity::High,
            "shell exec from cron payload".to_string(),
            "scheduled job pulls untrusted task".to_string(),
            "jobs/worker.py:213".to_string(),
        ),
    ]
}
