use super::threat_model::THREAT_MODEL_EMPTY_HINT;
use crate::ShellApp;
use kuzushi_core::Severity;

const SCOPE_ITEM_LIMIT: usize = 4;

/// Bucket order and labels for real threats; the counts come from the doc.
const SCOPE_BUCKET_LABELS: [(Severity, &str); 4] = [
    (Severity::Critical, "critical"),
    (Severity::High, "high"),
    (Severity::Medium, "medium"),
    (Severity::Low, "low"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatScopeBucket {
    pub(crate) tone: ThreatScopeTone,
    pub(crate) header: String,
    pub(crate) visible_items: Vec<String>,
    pub(crate) overflow_label: Option<String>,
    pub(crate) item_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatScopeModel {
    pub(crate) header: String,
    pub(crate) buckets: Vec<ThreatScopeBucket>,
    /// Set only when no threat model backs the view; the buckets then name the
    /// missing artifact instead of inventing scoped issues.
    pub(crate) empty_hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreatScopeTone {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

impl ThreatScopeTone {
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
}

pub(crate) fn threat_scope_model(app: &ShellApp) -> ThreatScopeModel {
    super::threat_model_doc(app)
        .as_ref()
        .and_then(threat_scope_model_from_doc)
        .unwrap_or_else(empty_scope_model)
}

pub(crate) fn threat_scope_model_from_doc(doc: &serde_json::Value) -> Option<ThreatScopeModel> {
    threat_scope_buckets_from_doc(doc).map(threat_scope_model_from_buckets)
}

fn threat_scope_buckets_from_doc(doc: &serde_json::Value) -> Option<Vec<ThreatScopeBucket>> {
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
    SCOPE_BUCKET_LABELS
        .iter()
        .map(|(severity, label)| threat_scope_bucket(*severity, label, Vec::new()))
        .collect()
}

fn push_threat_into_bucket(buckets: &mut [ThreatScopeBucket], threat: &serde_json::Value) {
    let tone = ThreatScopeTone::from_severity(threat_severity(threat));
    let title = threat_title(threat);
    if let Some(bucket) = buckets.iter_mut().find(|bucket| bucket.tone == tone) {
        push_scope_item(bucket, title);
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

fn empty_scope_model() -> ThreatScopeModel {
    ThreatScopeModel {
        header: "SCOPE".to_string(),
        buckets: Vec::new(),
        empty_hint: Some(THREAT_MODEL_EMPTY_HINT.to_string()),
    }
}

fn threat_scope_model_from_buckets(buckets: Vec<ThreatScopeBucket>) -> ThreatScopeModel {
    let item_count: usize = buckets.iter().map(|bucket| bucket.item_count).sum();
    ThreatScopeModel {
        header: format!("SCOPE · {item_count} issues"),
        buckets: buckets
            .into_iter()
            .filter(|bucket| bucket.item_count > 0)
            .collect(),
        empty_hint: None,
    }
}

fn threat_scope_bucket(severity: Severity, label: &str, items: Vec<String>) -> ThreatScopeBucket {
    let item_count = items.len();
    ThreatScopeBucket {
        tone: ThreatScopeTone::from_severity(severity),
        header: format!("{} · {}", label.to_uppercase(), item_count),
        visible_items: items.iter().take(SCOPE_ITEM_LIMIT).cloned().collect(),
        overflow_label: overflow_label(item_count),
        item_count,
    }
}

fn push_scope_item(bucket: &mut ThreatScopeBucket, title: String) {
    bucket.item_count += 1;
    bucket.header = replace_count(&bucket.header, bucket.item_count);
    if bucket.visible_items.len() < SCOPE_ITEM_LIMIT {
        bucket.visible_items.push(title);
    }
    bucket.overflow_label = overflow_label(bucket.item_count);
}

fn replace_count(header: &str, count: usize) -> String {
    let Some((label, _)) = header.rsplit_once(" · ") else {
        return header.to_string();
    };
    format!("{label} · {count}")
}

fn overflow_label(item_count: usize) -> Option<String> {
    (item_count > SCOPE_ITEM_LIMIT).then(|| format!("… {} more", item_count - SCOPE_ITEM_LIMIT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn threat_scope_model_from_doc_groups_by_impact() {
        let doc = json!({
            "threats": [
                {"title": "a", "impact": "critical"},
                {"title": "b", "impact": "high"},
                {"title": "c", "impact": "high"},
                {"title": "e", "impact": "high"},
                {"title": "f", "impact": "high"},
                {"title": "g", "impact": "high"},
                {"title": "d", "impact": "medium"}
            ]
        });

        let model = threat_scope_model_from_doc(&doc).expect("non-empty");
        let buckets = &model.buckets;

        assert_eq!(model.header, "SCOPE · 7 issues");
        assert_eq!(buckets.len(), 3);
        assert_eq!(buckets[0].tone, ThreatScopeTone::Critical);
        assert_eq!(buckets[0].item_count, 1);
        assert_eq!(buckets[1].tone, ThreatScopeTone::High);
        assert_eq!(buckets[1].item_count, 5);
        assert_eq!(buckets[1].visible_items.len(), 4);
        assert_eq!(buckets[1].overflow_label.as_deref(), Some("… 1 more"));
        assert_eq!(buckets[2].tone, ThreatScopeTone::Medium);
        assert_eq!(buckets[2].item_count, 1);
    }

    #[test]
    fn threat_scope_model_without_a_doc_is_empty_with_a_hint() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        let model = threat_scope_model(&app);

        assert_eq!(model.header, "SCOPE");
        assert!(model.buckets.is_empty(), "no doc means no scoped issue");
        assert_eq!(model.empty_hint.as_deref(), Some(THREAT_MODEL_EMPTY_HINT));
    }

    #[test]
    fn threat_scope_model_from_doc_returns_none_without_threats() {
        assert!(threat_scope_model_from_doc(&json!({})).is_none());
        assert!(threat_scope_model_from_doc(&json!({"threats": []})).is_none());
        assert!(threat_scope_model_from_doc(&json!({"threats": null})).is_none());
    }
}
