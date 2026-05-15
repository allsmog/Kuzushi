use super::*;

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
