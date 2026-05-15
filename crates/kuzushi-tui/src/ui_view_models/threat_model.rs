use crate::{ShellApp, ThreatPatch};
use std::path::PathBuf;

pub(crate) fn threat_model_doc(app: &ShellApp) -> Option<serde_json::Value> {
    let doc = kuzushi_core::load_persistent_threat_model(&threat_model_root(app))?;
    if doc.is_null() {
        return None;
    }
    Some(doc)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatSummaryReview {
    pub(crate) status: String,
    pub(crate) summary: String,
    pub(crate) threats: String,
    pub(crate) assets: String,
    pub(crate) actors: String,
    pub(crate) flows: String,
    pub(crate) trust_boundaries: String,
    pub(crate) assumptions: Vec<String>,
    pub(crate) missing_inputs: Vec<String>,
    pub(crate) proposed_changes: Vec<String>,
    pub(crate) limitations: Vec<String>,
}

pub(crate) fn threat_summary_review(app: &ShellApp) -> ThreatSummaryReview {
    ThreatSummaryReview::from_doc(
        threat_model_doc(app).as_ref(),
        app.pending_threat_patch.as_ref(),
    )
}

impl ThreatSummaryReview {
    fn from_doc(doc: Option<&serde_json::Value>, patch: Option<&ThreatPatch>) -> Self {
        let Some(doc) = doc else {
            return Self::unknown(patch);
        };
        Self {
            status: "current persisted model".to_string(),
            summary: doc_summary(doc),
            threats: count_label(array_len(doc.get("threats")), "threat"),
            assets: count_label(node_count(doc), "asset"),
            actors: count_label(actor_count(doc), "actor"),
            flows: count_label(array_len(doc.pointer("/dfd/flows")), "data flow"),
            trust_boundaries: count_label(
                array_len(doc.pointer("/dfd/trustBoundaries")),
                "trust boundary",
            ),
            assumptions: string_list(doc, &["/assumptions", "/metadata/assumptions"]),
            missing_inputs: string_list(
                doc,
                &[
                    "/missingInputs",
                    "/missing_inputs",
                    "/metadata/missingInputs",
                ],
            ),
            proposed_changes: proposed_changes(patch),
            limitations: evidence_limitations(doc),
        }
    }

    fn unknown(patch: Option<&ThreatPatch>) -> Self {
        Self {
            status: "unknown".to_string(),
            summary: "unknown - no persisted threat model found".to_string(),
            threats: "unknown".to_string(),
            assets: "unknown".to_string(),
            actors: "unknown".to_string(),
            flows: "unknown".to_string(),
            trust_boundaries: "unknown".to_string(),
            assumptions: vec!["unknown - build or import a threat model first".to_string()],
            missing_inputs: vec!["unknown".to_string()],
            proposed_changes: proposed_changes(patch),
            limitations: vec![
                "unknown evidence coverage until a threat model artifact exists".to_string(),
            ],
        }
    }
}

fn threat_model_root(app: &ShellApp) -> PathBuf {
    app.target
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn doc_summary(doc: &serde_json::Value) -> String {
    doc.pointer("/summary/text")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            doc.pointer("/summary/description")
                .and_then(serde_json::Value::as_str)
        })
        .map(ToString::to_string)
        .unwrap_or_else(|| "current threat model loaded; narrative summary unknown".to_string())
}

fn node_count(doc: &serde_json::Value) -> Option<usize> {
    array_len(doc.pointer("/dfd/nodes"))
}

fn actor_count(doc: &serde_json::Value) -> Option<usize> {
    let nodes = doc.pointer("/dfd/nodes")?.as_array()?;
    Some(
        nodes
            .iter()
            .filter(|node| {
                node.get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|kind| kind == "external-entity" || kind == "actor")
            })
            .count(),
    )
}

fn array_len(value: Option<&serde_json::Value>) -> Option<usize> {
    value.and_then(serde_json::Value::as_array).map(Vec::len)
}

fn count_label(count: Option<usize>, singular: &str) -> String {
    match count {
        Some(1) => format!("1 {singular}"),
        Some(count) => format!("{count} {singular}s"),
        None => "unknown".to_string(),
    }
}

fn string_list(doc: &serde_json::Value, pointers: &[&str]) -> Vec<String> {
    pointers
        .iter()
        .find_map(|pointer| doc.pointer(pointer).and_then(serde_json::Value::as_array))
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn proposed_changes(patch: Option<&ThreatPatch>) -> Vec<String> {
    match patch {
        Some(patch) => {
            let mut changes = vec![patch.summary.clone()];
            changes.extend(
                patch
                    .unsupported
                    .iter()
                    .map(|note| format!("unsupported: {note}")),
            );
            changes
        }
        None => vec!["none pending".to_string()],
    }
}

fn evidence_limitations(doc: &serde_json::Value) -> Vec<String> {
    let anchors = array_len(doc.pointer("/evidenceAnchors"))
        .or_else(|| array_len(doc.pointer("/evidence/anchors")));
    let mut limits = vec![
        "threat model is review context, not exploit proof".to_string(),
        "downstream findings still require source evidence and verification".to_string(),
    ];
    if anchors.unwrap_or(0) == 0 {
        limits.push("evidence anchors unknown".to_string());
    }
    limits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreatPatch;
    use serde_json::json;

    #[test]
    fn threat_summary_review_shapes_persisted_doc() {
        let doc = json!({
            "summary": {"text": "checkout threat model"},
            "dfd": {
                "nodes": [
                    {"type": "external-entity"},
                    {"type": "actor"},
                    {"type": "process"}
                ],
                "flows": [{"id": "flow-1"}],
                "trustBoundaries": [{"id": "edge"}]
            },
            "threats": [{"id": "T-1"}, {"id": "T-2"}],
            "assumptions": ["cookies are in scope"],
            "missingInputs": ["network diagram"]
        });

        let review = ThreatSummaryReview::from_doc(Some(&doc), None);

        assert_eq!(review.status, "current persisted model");
        assert_eq!(review.summary, "checkout threat model");
        assert_eq!(review.threats, "2 threats");
        assert_eq!(review.assets, "3 assets");
        assert_eq!(review.actors, "2 actors");
        assert_eq!(review.flows, "1 data flow");
        assert_eq!(review.trust_boundaries, "1 trust boundary");
        assert_eq!(review.assumptions, vec!["cookies are in scope"]);
        assert_eq!(review.missing_inputs, vec!["network diagram"]);
        assert!(review
            .limitations
            .iter()
            .any(|line| line.contains("not exploit proof")));
    }

    #[test]
    fn threat_summary_review_includes_pending_patch_notes_when_unknown() {
        let patch = ThreatPatch {
            goal: "regen".to_string(),
            summary: "add tenant boundary".to_string(),
            patch: json!({}),
            unsupported: vec!["needs runtime traces".to_string()],
        };

        let review = ThreatSummaryReview::from_doc(None, Some(&patch));

        assert_eq!(review.summary, "unknown - no persisted threat model found");
        assert_eq!(
            review.proposed_changes,
            vec![
                "add tenant boundary".to_string(),
                "unsupported: needs runtime traces".to_string()
            ]
        );
    }
}
