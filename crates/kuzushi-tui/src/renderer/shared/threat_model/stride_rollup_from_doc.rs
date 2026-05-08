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

/// `(severity, label, items)` — one criticality bucket of threat titles.
pub(crate) type ScopeBucket = (Severity, &'static str, Vec<String>);

/// Bucket threats from the persisted model by impact severity.
pub(crate) fn scope_buckets_from_doc(doc: &serde_json::Value) -> Option<Vec<ScopeBucket>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let mut buckets: Vec<ScopeBucket> = vec![
        (Severity::Critical, "critical", Vec::new()),
        (Severity::High, "high", Vec::new()),
        (Severity::Medium, "medium", Vec::new()),
        (Severity::Low, "low", Vec::new()),
    ];
    for t in threats {
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
        if let Some((_, _, items)) = buckets.iter_mut().find(|(sev, _, _)| *sev == severity) {
            items.push(title);
        }
    }
    Some(buckets)
}

/// Fixture used when no real threat model is loaded — matches the canonical
/// design content.
pub(crate) fn canonical_scope_buckets() -> Vec<ScopeBucket> {
    vec![
        (
            Severity::Critical,
            "critical",
            vec![
                "sql injection via order_id concatenation".to_string(),
                "prompt injection sink reads user body".to_string(),
            ],
        ),
        (
            Severity::High,
            "high",
            vec![
                "jwt verify accepts alg=none".to_string(),
                "shell exec from cron payload".to_string(),
                "path traversal in /assets/<file>".to_string(),
            ],
        ),
        (
            Severity::Medium,
            "medium",
            vec![
                "open redirect on /login?next=".to_string(),
                "csrf token not bound to session".to_string(),
                "unbounded regex on /search".to_string(),
            ],
        ),
        (
            Severity::Low,
            "low",
            vec![
                "cors allows null origin".to_string(),
                "cookie set without SameSite".to_string(),
                "console.log of req.body in handler".to_string(),
            ],
        ),
    ]
}

pub(crate) fn impact_to_severity(value: &str) -> Severity {
    match value.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
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
