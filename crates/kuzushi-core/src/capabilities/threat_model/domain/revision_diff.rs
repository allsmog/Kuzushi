//! Pure structural comparison of two persisted threat-model documents.
//!
//! Threats are matched by `stableId`, falling back to the display `id` only
//! when a threat carries no `stableId`. Threats with neither are counted as
//! unkeyed rather than guessed at. DFD elements are matched by `id`.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Threat fields whose change marks a matched threat as `changed`.
const COMPARED_THREAT_FIELDS: [&str; 7] = [
    "title",
    "impact",
    "likelihood",
    "category",
    "relatedCWEs",
    "targetElementIds",
    "status",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatModelDocumentDiff {
    pub threats: ThreatSetDiff,
    pub dfd: DfdElementDiff,
    pub coverage: CoverageComparison,
    pub methodology_changed: bool,
}

impl ThreatModelDocumentDiff {
    /// True when no threat, DFD element, coverage count, or methodology differs.
    pub fn is_empty(&self) -> bool {
        self.threats.is_empty()
            && self.dfd.is_empty()
            && self.coverage.from == self.coverage.to
            && !self.methodology_changed
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatSetDiff {
    pub added: Vec<ThreatSummary>,
    pub removed: Vec<ThreatSummary>,
    pub changed: Vec<ThreatFieldChange>,
    pub unkeyed: UnkeyedThreatCounts,
}

impl ThreatSetDiff {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatSummary {
    pub key: String,
    pub title: Option<String>,
    pub impact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatFieldChange {
    pub key: String,
    pub title: Option<String>,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnkeyedThreatCounts {
    pub from: usize,
    pub to: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DfdElementDiff {
    pub nodes_added: Vec<String>,
    pub nodes_removed: Vec<String>,
    pub flows_added: Vec<String>,
    pub flows_removed: Vec<String>,
    pub boundaries_added: Vec<String>,
    pub boundaries_removed: Vec<String>,
}

impl DfdElementDiff {
    fn is_empty(&self) -> bool {
        [
            &self.nodes_added,
            &self.nodes_removed,
            &self.flows_added,
            &self.flows_removed,
            &self.boundaries_added,
            &self.boundaries_removed,
        ]
        .iter()
        .all(|ids| ids.is_empty())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageComparison {
    pub from: CoverageCounts,
    pub to: CoverageCounts,
}

/// Entry-point coverage counts; `None` when the document does not record them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageCounts {
    pub considered: Option<u64>,
    pub covered: Option<u64>,
}

pub fn diff_threat_model_documents(from: &Value, to: &Value) -> ThreatModelDocumentDiff {
    ThreatModelDocumentDiff {
        threats: diff_threats(from, to),
        dfd: diff_dfd(from, to),
        coverage: CoverageComparison {
            from: coverage_counts(from),
            to: coverage_counts(to),
        },
        methodology_changed: document_methodology(from) != document_methodology(to),
    }
}

/// The document's declared methodology, lower-cased for comparison.
pub fn document_methodology(document: &Value) -> Option<String> {
    non_empty_text(document, "methodology").map(|value| value.to_ascii_lowercase())
}

pub fn document_threat_count(document: &Value) -> usize {
    threat_rows(document).len()
}

#[derive(Default)]
struct KeyedThreats<'a> {
    rows: Vec<(String, &'a Value)>,
    index: BTreeMap<String, &'a Value>,
    unkeyed: usize,
}

impl<'a> KeyedThreats<'a> {
    fn insert(&mut self, key: String, threat: &'a Value) {
        if self.index.contains_key(&key) {
            return;
        }
        self.index.insert(key.clone(), threat);
        self.rows.push((key, threat));
    }
}

fn diff_threats(from: &Value, to: &Value) -> ThreatSetDiff {
    let before = keyed_threats(from);
    let after = keyed_threats(to);
    ThreatSetDiff {
        added: missing_from(&after, &before),
        removed: missing_from(&before, &after),
        changed: changed_threats(&before, &after),
        unkeyed: UnkeyedThreatCounts {
            from: before.unkeyed,
            to: after.unkeyed,
        },
    }
}

fn keyed_threats(document: &Value) -> KeyedThreats<'_> {
    let mut keyed = KeyedThreats::default();
    for threat in threat_rows(document) {
        match threat_key(threat) {
            Some(key) => keyed.insert(key, threat),
            None => keyed.unkeyed += 1,
        }
    }
    keyed
}

fn threat_rows(document: &Value) -> &[Value] {
    document
        .get("threats")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn threat_key(threat: &Value) -> Option<String> {
    non_empty_text(threat, "stableId").or_else(|| non_empty_text(threat, "id"))
}

fn missing_from(source: &KeyedThreats<'_>, other: &KeyedThreats<'_>) -> Vec<ThreatSummary> {
    source
        .rows
        .iter()
        .filter(|(key, _)| !other.index.contains_key(key))
        .map(|(key, threat)| ThreatSummary {
            key: key.clone(),
            title: non_empty_text(threat, "title"),
            impact: non_empty_text(threat, "impact"),
        })
        .collect()
}

fn changed_threats(before: &KeyedThreats<'_>, after: &KeyedThreats<'_>) -> Vec<ThreatFieldChange> {
    after
        .rows
        .iter()
        .filter_map(|(key, threat)| {
            let previous = before.index.get(key)?;
            threat_change(key, previous, threat)
        })
        .collect()
}

fn threat_change(key: &str, before: &Value, after: &Value) -> Option<ThreatFieldChange> {
    let fields = COMPARED_THREAT_FIELDS
        .iter()
        .filter(|field| comparable_field(before, field) != comparable_field(after, field))
        .map(|field| (*field).to_string())
        .collect::<Vec<_>>();
    (!fields.is_empty()).then(|| ThreatFieldChange {
        key: key.to_string(),
        title: non_empty_text(after, "title"),
        fields,
    })
}

/// Normalized field value: list fields compare as string sets, and the
/// staged pipeline's `relatedCwe` spelling is the same field as `relatedCWEs`.
fn comparable_field(threat: &Value, field: &str) -> Option<Value> {
    match field {
        "relatedCWEs" => string_set(threat.get(field).or_else(|| threat.get("relatedCwe"))),
        "targetElementIds" => string_set(threat.get(field)),
        _ => threat.get(field).filter(|value| !value.is_null()).cloned(),
    }
}

fn string_set(value: Option<&Value>) -> Option<Value> {
    let members = string_members(value?);
    Some(json!(members.into_iter().collect::<BTreeSet<_>>()))
}

fn string_members(value: &Value) -> Vec<&str> {
    match value {
        Value::Array(rows) => rows.iter().filter_map(Value::as_str).collect(),
        Value::String(single) => vec![single.as_str()],
        _ => Vec::new(),
    }
}

fn diff_dfd(from: &Value, to: &Value) -> DfdElementDiff {
    let (nodes_added, nodes_removed) = id_delta(from, to, "/dfd/nodes");
    let (flows_added, flows_removed) = id_delta(from, to, "/dfd/flows");
    let (boundaries_added, boundaries_removed) = id_delta(from, to, "/dfd/trustBoundaries");
    DfdElementDiff {
        nodes_added,
        nodes_removed,
        flows_added,
        flows_removed,
        boundaries_added,
        boundaries_removed,
    }
}

fn id_delta(from: &Value, to: &Value, pointer: &str) -> (Vec<String>, Vec<String>) {
    let before = element_ids(from, pointer);
    let after = element_ids(to, pointer);
    (
        after.difference(&before).cloned().collect(),
        before.difference(&after).cloned().collect(),
    )
}

fn element_ids(document: &Value, pointer: &str) -> BTreeSet<String> {
    document
        .pointer(pointer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| non_empty_text(row, "id"))
        .collect()
}

fn coverage_counts(document: &Value) -> CoverageCounts {
    CoverageCounts {
        considered: coverage_count(document, "entryPointsConsidered"),
        covered: coverage_count(document, "entryPointsCovered"),
    }
}

fn coverage_count(document: &Value, field: &str) -> Option<u64> {
    document
        .get("coverage")
        .and_then(|coverage| coverage.get(field))
        .and_then(Value::as_u64)
}

fn non_empty_text(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(threats: Value, nodes: &[&str]) -> Value {
        let nodes = nodes.iter().map(|id| json!({"id": id})).collect::<Vec<_>>();
        json!({
            "version": "2.0",
            "methodology": "stride",
            "dfd": {"nodes": nodes, "flows": [], "trustBoundaries": []},
            "threats": threats,
            "coverage": {"entryPointsConsidered": 4, "entryPointsCovered": 2},
            "summary": {}
        })
    }

    fn threat(stable_id: &str, title: &str, impact: &str) -> Value {
        json!({
            "id": "T1",
            "stableId": stable_id,
            "title": title,
            "impact": impact,
            "likelihood": "likely",
            "category": "tampering",
            "relatedCWEs": ["CWE-89"],
            "targetElementIds": ["app", "db"],
            "status": "unmitigated"
        })
    }

    #[test]
    fn identical_documents_produce_an_empty_diff() {
        let doc = document(json!([threat("tm-a", "SQLi", "high")]), &["app"]);

        let diff = diff_threat_model_documents(&doc, &doc);

        assert!(diff.is_empty(), "{diff:?}");
        assert_eq!(diff.coverage.from.considered, Some(4));
        assert_eq!(diff.coverage.to.covered, Some(2));
    }

    #[test]
    fn reports_added_removed_and_changed_threats_by_stable_id() {
        let from = document(
            json!([threat("tm-a", "SQLi", "high"), threat("tm-b", "XSS", "medium")]),
            &["app"],
        );
        let mut edited = threat("tm-a", "SQLi in login", "critical");
        edited["targetElementIds"] = json!(["db", "app"]);
        let to = document(json!([edited, threat("tm-c", "SSRF", "high")]), &["app"]);

        let threats = diff_threat_model_documents(&from, &to).threats;

        assert_eq!(threats.added.len(), 1);
        assert_eq!(threats.added[0].key, "tm-c");
        assert_eq!(threats.added[0].impact.as_deref(), Some("high"));
        assert_eq!(threats.removed[0].title.as_deref(), Some("XSS"));
        assert_eq!(threats.changed.len(), 1);
        assert_eq!(threats.changed[0].fields, vec!["title", "impact"]);
    }

    #[test]
    fn falls_back_to_display_id_and_counts_unkeyed_threats() {
        let from = document(json!([{"id": "T9", "title": "Old"}, {"title": "orphan"}]), &[]);
        let to = document(json!([{"id": "T9", "title": "New"}]), &[]);

        let threats = diff_threat_model_documents(&from, &to).threats;

        assert_eq!(threats.changed[0].key, "T9");
        assert_eq!(threats.changed[0].fields, vec!["title"]);
        assert_eq!(threats.unkeyed, UnkeyedThreatCounts { from: 1, to: 0 });
    }

    #[test]
    fn related_cwe_spellings_compare_as_one_field() {
        let before = threat("tm-a", "SQLi", "high");
        let mut after = before.clone();
        after.as_object_mut().unwrap().remove("relatedCWEs");
        after["relatedCwe"] = json!(["CWE-89"]);

        let diff = diff_threat_model_documents(
            &document(json!([before]), &[]),
            &document(json!([after]), &[]),
        );

        assert!(diff.threats.changed.is_empty(), "{diff:?}");
    }

    #[test]
    fn reports_dfd_element_and_methodology_deltas() {
        let from = document(json!([]), &["app", "db"]);
        let mut to = document(json!([]), &["app", "cache"]);
        to["dfd"]["flows"] = json!([{"id": "F1"}]);
        to["dfd"]["trustBoundaries"] = json!([{"id": "TB1"}]);
        to["methodology"] = json!("pasta");

        let diff = diff_threat_model_documents(&from, &to);

        assert_eq!(diff.dfd.nodes_added, vec!["cache"]);
        assert_eq!(diff.dfd.nodes_removed, vec!["db"]);
        assert_eq!(diff.dfd.flows_added, vec!["F1"]);
        assert_eq!(diff.dfd.boundaries_added, vec!["TB1"]);
        assert!(diff.methodology_changed);
        assert!(!diff.is_empty());
    }
}
