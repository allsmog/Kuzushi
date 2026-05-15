use crate::ShellApp;
use kuzushi_core::Severity;

type ScopeSpec = (Severity, &'static str, &'static [&'static str]);

const CANONICAL_SCOPE_BUCKETS: [ScopeSpec; 4] = [
    (
        Severity::Critical,
        "critical",
        &[
            "sql injection via order_id concatenation",
            "prompt injection sink reads user body",
        ],
    ),
    (
        Severity::High,
        "high",
        &[
            "jwt verify accepts alg=none",
            "shell exec from cron payload",
            "path traversal in /assets/<file>",
        ],
    ),
    (
        Severity::Medium,
        "medium",
        &[
            "open redirect on /login?next=",
            "csrf token not bound to session",
            "unbounded regex on /search",
        ],
    ),
    (
        Severity::Low,
        "low",
        &[
            "cors allows null origin",
            "cookie set without SameSite",
            "console.log of req.body in handler",
        ],
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatScopeBucket {
    pub(crate) severity: Severity,
    pub(crate) label: &'static str,
    pub(crate) items: Vec<String>,
}

pub(crate) fn threat_scope_buckets(app: &ShellApp) -> Vec<ThreatScopeBucket> {
    super::threat_model_doc(app)
        .as_ref()
        .and_then(threat_scope_buckets_from_doc)
        .unwrap_or_else(canonical_scope_buckets)
}

pub(crate) fn threat_scope_buckets_from_doc(
    doc: &serde_json::Value,
) -> Option<Vec<ThreatScopeBucket>> {
    let threats = non_empty_threats(doc)?;
    let mut buckets = empty_scope_buckets();
    for threat in threats {
        push_threat_into_bucket(&mut buckets, threat);
    }
    Some(buckets)
}

fn non_empty_threats(doc: &serde_json::Value) -> Option<&[serde_json::Value]> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    Some(threats)
}

fn empty_scope_buckets() -> Vec<ThreatScopeBucket> {
    CANONICAL_SCOPE_BUCKETS
        .iter()
        .map(|(severity, label, _)| ThreatScopeBucket {
            severity: *severity,
            label,
            items: Vec::new(),
        })
        .collect()
}

fn push_threat_into_bucket(buckets: &mut [ThreatScopeBucket], threat: &serde_json::Value) {
    let severity = threat_severity(threat);
    let title = threat_title(threat);
    if let Some(bucket) = buckets
        .iter_mut()
        .find(|bucket| bucket.severity == severity)
    {
        bucket.items.push(title);
    }
}

fn threat_severity(threat: &serde_json::Value) -> Severity {
    threat
        .get("impact")
        .and_then(serde_json::Value::as_str)
        .map(super::threat_impact::impact_to_severity)
        .unwrap_or(Severity::Medium)
}

fn threat_title(threat: &serde_json::Value) -> String {
    threat
        .get("title")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("untitled")
        .to_string()
}

fn canonical_scope_buckets() -> Vec<ThreatScopeBucket> {
    CANONICAL_SCOPE_BUCKETS
        .iter()
        .map(|(severity, label, items)| ThreatScopeBucket {
            severity: *severity,
            label,
            items: items.iter().map(ToString::to_string).collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn threat_scope_buckets_from_doc_groups_by_impact() {
        let doc = json!({
            "threats": [
                {"title": "a", "impact": "critical"},
                {"title": "b", "impact": "high"},
                {"title": "c", "impact": "high"},
                {"title": "d", "impact": "medium"}
            ]
        });

        let buckets = threat_scope_buckets_from_doc(&doc).expect("non-empty");

        assert_eq!(buckets[0].severity, Severity::Critical);
        assert_eq!(buckets[0].items.len(), 1);
        assert_eq!(buckets[1].severity, Severity::High);
        assert_eq!(buckets[1].items.len(), 2);
        assert_eq!(buckets[2].severity, Severity::Medium);
        assert_eq!(buckets[2].items.len(), 1);
        assert_eq!(buckets[3].severity, Severity::Low);
        assert!(buckets[3].items.is_empty());
    }

    #[test]
    fn threat_scope_buckets_from_doc_returns_none_without_threats() {
        assert!(threat_scope_buckets_from_doc(&json!({})).is_none());
        assert!(threat_scope_buckets_from_doc(&json!({"threats": []})).is_none());
        assert!(threat_scope_buckets_from_doc(&json!({"threats": null})).is_none());
    }
}
