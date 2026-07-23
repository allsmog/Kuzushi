use crate::app::JsonFileState;
use crate::{ShellApp, ThreatPatch, ViewDataState};
use std::path::PathBuf;

pub(crate) fn threat_model_doc(app: &ShellApp) -> Option<serde_json::Value> {
    match read_threat_model_artifact(app) {
        ThreatModelArtifact::Present(doc) if !doc.is_null() => Some(doc),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatSummaryReview {
    pub(crate) status: String,
    pub(crate) summary: String,
    pub(crate) threats: String,
    pub(crate) assets: String,
    pub(crate) nodes: String,
    pub(crate) actors: String,
    pub(crate) flows: String,
    pub(crate) trust_boundaries: String,
    pub(crate) assumptions: Vec<String>,
    pub(crate) missing_inputs: Vec<String>,
    pub(crate) proposed_changes: Vec<String>,
    pub(crate) limitations: Vec<String>,
}

pub(crate) fn threat_summary_review(app: &ShellApp) -> ThreatSummaryReview {
    let patch = app.engagement.pending_threat_patch();
    match read_threat_model_artifact(app) {
        ThreatModelArtifact::Present(doc) if !doc.is_null() => {
            ThreatSummaryReview::from_doc(Some(&doc), patch)
        }
        ThreatModelArtifact::Malformed => ThreatSummaryReview::malformed(patch),
        ThreatModelArtifact::NonFile => ThreatSummaryReview::non_file(patch),
        ThreatModelArtifact::Targetless => ThreatSummaryReview::targetless(patch),
        _ => ThreatSummaryReview::unknown(patch),
    }
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
            // The document-level assets table is the asset count; DFD nodes
            // are a separate statistic (conflating them read "assets 13"
            // against an artifact with 6 assets).
            assets: count_label(asset_count(doc), "asset"),
            nodes: count_label(node_count(doc), "node"),
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
            status: "no threat model artifact".to_string(),
            summary: "build or import a threat model to populate this view".to_string(),
            threats: "—".to_string(),
            assets: "—".to_string(),
            nodes: "—".to_string(),
            actors: "—".to_string(),
            flows: "—".to_string(),
            trust_boundaries: "—".to_string(),
            assumptions: vec!["build or import a threat model first".to_string()],
            missing_inputs: vec!["—".to_string()],
            proposed_changes: proposed_changes(patch),
            limitations: vec![
                "evidence coverage is unknown until a threat model artifact exists".to_string(),
            ],
        }
    }

    fn targetless(patch: Option<&ThreatPatch>) -> Self {
        Self {
            status: "no target selected".to_string(),
            summary: "select a target before loading threat-model artifacts".to_string(),
            threats: "—".to_string(),
            assets: "—".to_string(),
            nodes: "—".to_string(),
            actors: "—".to_string(),
            flows: "—".to_string(),
            trust_boundaries: "—".to_string(),
            assumptions: vec!["targetless browsing does not inspect cwd".to_string()],
            missing_inputs: vec!["target <path> (or target .)".to_string()],
            proposed_changes: proposed_changes(patch),
            limitations: vec!["no workspace artifacts were read".to_string()],
        }
    }

    fn malformed(patch: Option<&ThreatPatch>) -> Self {
        Self {
            status: "malformed".to_string(),
            summary: format!("malformed {}", threat_model_relative_path()),
            threats: "unknown".to_string(),
            assets: "unknown".to_string(),
            nodes: "unknown".to_string(),
            actors: "unknown".to_string(),
            flows: "unknown".to_string(),
            trust_boundaries: "unknown".to_string(),
            assumptions: vec!["threat-model artifact could not be parsed".to_string()],
            missing_inputs: vec![format!("valid {}", threat_model_file_name())],
            proposed_changes: proposed_changes(patch),
            limitations: vec![
                "threat model artifact is malformed; do not infer threats from it".to_string(),
            ],
        }
    }

    fn non_file(patch: Option<&ThreatPatch>) -> Self {
        Self {
            status: "malformed".to_string(),
            summary: format!("{} is not a file", threat_model_relative_path()),
            threats: "unknown".to_string(),
            assets: "unknown".to_string(),
            nodes: "unknown".to_string(),
            actors: "unknown".to_string(),
            flows: "unknown".to_string(),
            trust_boundaries: "unknown".to_string(),
            assumptions: vec!["threat-model artifact path is not a file".to_string()],
            missing_inputs: vec![format!("valid {} file", threat_model_file_name())],
            proposed_changes: proposed_changes(patch),
            limitations: vec![
                "threat model artifact path is invalid; do not infer threats from it".to_string(),
            ],
        }
    }
}

fn read_threat_model_artifact(app: &ShellApp) -> ThreatModelArtifact {
    let Some(root) = app.target() else {
        return ThreatModelArtifact::Targetless;
    };
    let path = threat_model_artifact_path(root);
    match app.workbench_cache().borrow().cached_json_file(root, &path) {
        ViewDataState::Ready(JsonFileState::Present(value)) if value.is_object() => {
            ThreatModelArtifact::Present(value)
        }
        ViewDataState::Ready(JsonFileState::Present(_))
        | ViewDataState::Ready(JsonFileState::Malformed)
        | ViewDataState::Ready(JsonFileState::Unreadable) => ThreatModelArtifact::Malformed,
        ViewDataState::Ready(JsonFileState::NonFile) => ThreatModelArtifact::NonFile,
        ViewDataState::Ready(JsonFileState::Missing)
        | ViewDataState::NotRequested
        | ViewDataState::Loading => ThreatModelArtifact::Missing,
    }
}

fn threat_model_artifact_path(root: impl AsRef<std::path::Path>) -> PathBuf {
    kuzushi_core::capabilities::persistent_threat_model_path(root.as_ref())
}

pub(crate) fn threat_model_relative_path() -> String {
    threat_model_artifact_path("").display().to_string()
}

fn threat_model_file_name() -> String {
    threat_model_artifact_path("")
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("threat-model.json")
        .to_string()
}

enum ThreatModelArtifact {
    Present(serde_json::Value),
    Malformed,
    NonFile,
    Missing,
    Targetless,
}

fn doc_summary(doc: &serde_json::Value) -> String {
    doc.pointer("/summary/text")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            doc.pointer("/summary/description")
                .and_then(serde_json::Value::as_str)
        })
        .map(ToString::to_string)
        .or_else(|| structured_summary_rollup(doc))
        .unwrap_or_else(|| "current threat model loaded; narrative summary unknown".to_string())
}

/// The contract's `/summary` is a structured rollup (total / bySeverity /
/// byCategory), not prose — render the rollup instead of claiming the
/// narrative summary is unknown.
fn structured_summary_rollup(doc: &serde_json::Value) -> Option<String> {
    let summary = doc.get("summary")?.as_object()?;
    let total = summary.get("total").and_then(serde_json::Value::as_u64)?;
    let mut parts = vec![format!("{total} threats")];
    if let Some(severity) = rollup_counts(summary.get("bySeverity")) {
        parts.push(severity);
    }
    if let Some(category) = rollup_counts(summary.get("byCategory")) {
        parts.push(category);
    }
    Some(parts.join(" — "))
}

fn rollup_counts(value: Option<&serde_json::Value>) -> Option<String> {
    let counts = value?.as_object()?;
    let rendered = counts
        .iter()
        .filter_map(|(name, count)| {
            count
                .as_u64()
                .filter(|count| *count > 0)
                .map(|count| format!("{count} {name}"))
        })
        .collect::<Vec<_>>()
        .join(" · ");
    (!rendered.is_empty()).then_some(rendered)
}

fn node_count(doc: &serde_json::Value) -> Option<usize> {
    array_len(doc.pointer("/dfd/nodes"))
}

/// Prefer the document's own assets table; older documents without one fall
/// back to the DFD node count (the pre-contract behavior).
fn asset_count(doc: &serde_json::Value) -> Option<usize> {
    array_len(doc.get("assets")).or_else(|| node_count(doc))
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

fn count_label(count: Option<usize>, _singular: &str) -> String {
    match count {
        Some(count) => format!("{count}"),
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
        assert_eq!(review.threats, "2");
        assert_eq!(review.assets, "3", "no assets table falls back to nodes");
        assert_eq!(review.nodes, "3");
        assert_eq!(review.actors, "2");
        assert_eq!(review.flows, "1");
        assert_eq!(review.trust_boundaries, "1");
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

        assert_eq!(
            review.summary,
            "build or import a threat model to populate this view"
        );
        assert_eq!(
            review.proposed_changes,
            vec![
                "add tenant boundary".to_string(),
                "unsupported: needs runtime traces".to_string()
            ]
        );
    }

    #[test]
    fn threat_summary_review_surfaces_malformed_persistent_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let artifact_path = threat_model_artifact_path(temp.path());
        std::fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        std::fs::write(artifact_path, "{not-json").unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        let review = threat_summary_review(&app);

        assert_eq!(review.status, "malformed");
        assert_eq!(
            review.summary,
            format!("malformed {}", threat_model_relative_path())
        );
        assert_eq!(
            review.assumptions,
            vec!["threat-model artifact could not be parsed"]
        );
        assert!(review
            .limitations
            .iter()
            .any(|line| line.contains("do not infer threats")));
    }

    #[test]
    fn threat_summary_review_surfaces_non_object_persistent_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let artifact_path = threat_model_artifact_path(temp.path());
        std::fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        std::fs::write(artifact_path, "[]").unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        let review = threat_summary_review(&app);

        assert_eq!(review.status, "malformed");
        assert_eq!(
            review.summary,
            format!("malformed {}", threat_model_relative_path())
        );
        assert_eq!(
            review.assumptions,
            vec!["threat-model artifact could not be parsed"]
        );
    }

    #[test]
    fn threat_summary_review_surfaces_non_file_persistent_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let artifact_path = threat_model_artifact_path(temp.path());
        std::fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        std::fs::create_dir(artifact_path).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        let review = threat_summary_review(&app);

        assert_eq!(review.status, "malformed");
        assert_eq!(
            review.summary,
            format!("{} is not a file", threat_model_relative_path())
        );
        assert_eq!(
            review.missing_inputs,
            vec![format!("valid {} file", threat_model_file_name())]
        );
        assert_eq!(
            review.assumptions,
            vec!["threat-model artifact path is not a file".to_string()]
        );
    }

    #[test]
    fn threat_model_artifact_path_uses_workspace_state_root() {
        let root = std::path::Path::new("/repo");

        assert_eq!(
            threat_model_artifact_path(root),
            kuzushi_core::capabilities::persistent_threat_model_path(root)
        );
    }

    #[test]
    fn targetless_threat_model_view_does_not_read_cwd_artifacts() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        let review = threat_summary_review(&app);

        assert_eq!(review.status, "no target selected");
        assert!(review.summary.contains("select a target"));
        assert_eq!(review.limitations, vec!["no workspace artifacts were read"]);
    }
}
