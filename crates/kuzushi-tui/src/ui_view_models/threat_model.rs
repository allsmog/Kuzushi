use crate::app::{JsonFileState, ProjectScopeTreeState, ThreatModelStoreState};
use crate::{ShellApp, ThreatPatch, ViewDataState};
use kuzushi_core::capabilities::threat_model::{
    ThreatModelId, ThreatModelManifest, ThreatModelMetadata, ThreatModelRef, ThreatModelRevisionId,
    ThreatModelRevisionMetadata,
};
use std::path::PathBuf;

mod map_context;
pub(crate) use map_context::map_context_run_refs;
pub(crate) use map_context::recorded_map_context_issue;

pub(crate) const THREAT_MODEL_EMPTY_HINT: &str =
    "build or import a threat model to populate this view";
pub(crate) const THREAT_MODEL_NO_THREATS_HINT: &str = "current threat model records no threats";
pub(crate) const THREAT_MODEL_MALFORMED_HINT: &str = "threat-model artifact could not be parsed";
pub(crate) const THREAT_MODEL_NON_FILE_HINT: &str = "threat-model artifact path is not a file";
pub(crate) const THREAT_MODEL_TARGETLESS_HINT: &str =
    "select a target before loading threat-model artifacts";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatModelHeadRow {
    pub(crate) model_id: ThreatModelId,
    pub(crate) revision_id: ThreatModelRevisionId,
    pub(crate) sha256: String,
    pub(crate) label: String,
    pub(crate) methodology: String,
    pub(crate) scope: String,
    pub(crate) scope_status: String,
    pub(crate) verification: String,
    pub(crate) active_lineage: bool,
    pub(crate) active_head: bool,
    pub(crate) active_revision_id: Option<ThreatModelRevisionId>,
    pub(crate) active_sha256: Option<String>,
    pub(crate) active_verification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatModelPickerModel {
    pub(crate) rows: Vec<ThreatModelHeadRow>,
    pub(crate) active_index: Option<usize>,
    pub(crate) status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatModelFreshnessModel {
    pub(crate) verdict: String,
    pub(crate) document_sha256: Option<String>,
    pub(crate) current_sha256: Option<String>,
    pub(crate) requires_attention: bool,
}

impl ThreatModelPickerModel {
    pub(crate) fn header_chip(&self) -> Option<String> {
        let index = self.active_index?;
        let row = self.rows.get(index)?;
        Some(format!(
            "model {}/{} · {} · {} · {}{}",
            index + 1,
            self.rows.len(),
            row.label,
            row.methodology,
            row.active_verification
                .as_deref()
                .unwrap_or(row.verification.as_str()),
            scope_header_suffix(&row.scope_status),
        ))
    }

    pub(crate) fn cycle_ref(&self, reverse: bool) -> Option<ThreatModelRef> {
        let count = self.rows.len();
        if count == 0 {
            return None;
        }
        let index = cycle_model_index(self.active_index, count, reverse);
        let row = &self.rows[index];
        Some(ThreatModelRef {
            model_id: row.model_id.clone(),
            revision_id: row.revision_id.clone(),
            sha256: row.sha256.clone(),
        })
    }
}

pub(crate) fn threat_model_picker(app: &ShellApp) -> ThreatModelPickerModel {
    let Some(root) = app.target() else {
        return empty_picker(THREAT_MODEL_TARGETLESS_HINT);
    };
    match app
        .workbench_cache()
        .borrow()
        .cached_threat_model_store(Some(root))
    {
        ViewDataState::Ready(ThreatModelStoreState::Ready { manifest, .. }) => {
            bind_active_mirror(app, picker_from_manifest(&manifest, Some(app)))
        }
        ViewDataState::Ready(ThreatModelStoreState::Legacy) => {
            empty_picker("no immutable threat-model lineages")
        }
        ViewDataState::Ready(ThreatModelStoreState::Invalid(error)) => {
            empty_picker(&format!("threat-model integrity error: {error}"))
        }
        ViewDataState::NotRequested | ViewDataState::Loading => {
            empty_picker("checking threat-model lineages…")
        }
    }
}

pub(crate) fn threat_model_freshness(app: &ShellApp) -> ThreatModelFreshnessModel {
    if let Some(freshness) = map_context::recorded_map_freshness(app) {
        return freshness;
    }
    let picker = threat_model_picker(app);
    let Some(index) = picker.active_index else {
        return legacy_threat_model_freshness(app);
    };
    let row = &picker.rows[index];
    let verdict = row
        .active_verification
        .clone()
        .unwrap_or_else(|| "unverified".to_string());
    ThreatModelFreshnessModel {
        requires_attention: matches!(
            verdict.as_str(),
            "failed" | "stale" | "verification stale" | "manual edit"
        ),
        verdict,
        document_sha256: row.active_sha256.clone(),
        current_sha256: active_mirror_sha256(app).or_else(|| row.active_sha256.clone()),
    }
}

#[cfg(test)]
fn picker_from_value(value: serde_json::Value) -> ThreatModelPickerModel {
    let manifest = serde_json::from_value::<ThreatModelManifest>(value);
    match manifest {
        Ok(manifest) if manifest.schema_version == 1 => picker_from_manifest(&manifest, None),
        Ok(_) => empty_picker("threat-model manifest version is unsupported"),
        Err(_) => empty_picker("threat-model manifest is incompatible"),
    }
}

fn bind_active_mirror(
    app: &ShellApp,
    mut picker: ThreatModelPickerModel,
) -> ThreatModelPickerModel {
    let Some(index) = picker.active_index else {
        return picker;
    };
    let row = &mut picker.rows[index];
    match active_mirror_state(app) {
        ViewDataState::Ready(JsonFileState::Present(_)) => {
            if active_mirror_sha256(app).as_deref() != row.active_sha256.as_deref() {
                row.active_verification = Some("manual edit".to_string());
            }
        }
        ViewDataState::Ready(
            JsonFileState::Malformed | JsonFileState::Unreadable | JsonFileState::NonFile,
        ) => {
            row.active_verification = Some("manual edit".to_string());
            picker.status =
                "compatibility mirror cannot be adopted; inspect the file or discard --force"
                    .to_string();
        }
        ViewDataState::Ready(JsonFileState::Missing)
        | ViewDataState::NotRequested
        | ViewDataState::Loading => {}
    }
    picker
}

fn picker_from_manifest(
    manifest: &ThreatModelManifest,
    app: Option<&ShellApp>,
) -> ThreatModelPickerModel {
    let rows = manifest
        .models
        .iter()
        .filter_map(|model| {
            head_row(
                model,
                manifest.active.as_ref(),
                scope_status(app, &model.scope),
            )
        })
        .collect::<Vec<_>>();
    let active_index = rows.iter().position(|row| row.active_lineage);
    let status = if rows.is_empty() {
        "no immutable threat-model lineages".to_string()
    } else {
        format!("{} model lineage(s)", rows.len())
    };
    ThreatModelPickerModel {
        rows,
        active_index,
        status,
    }
}

fn head_row(
    model: &ThreatModelMetadata,
    active: Option<&ThreatModelRef>,
    scope_status: String,
) -> Option<ThreatModelHeadRow> {
    let head = model
        .revisions
        .iter()
        .find(|revision| revision.revision_id == model.head_revision)?;
    let active_lineage = active.is_some_and(|active| active.model_id == model.model_id);
    let active_revision = active.filter(|_| active_lineage).and_then(|active| {
        model
            .revisions
            .iter()
            .find(|revision| revision.revision_id == active.revision_id)
    });
    Some(ThreatModelHeadRow {
        model_id: model.model_id.clone(),
        revision_id: head.revision_id.clone(),
        sha256: head.sha256.clone(),
        label: model.label.clone(),
        methodology: model.methodology.clone(),
        scope: model.scope.rel_path.display().to_string(),
        scope_status,
        verification: verification_label(head),
        active_lineage,
        active_head: active_lineage
            && active.is_some_and(|active| active.revision_id == head.revision_id),
        active_revision_id: active_revision.map(|revision| revision.revision_id.clone()),
        active_sha256: active_revision.map(|revision| revision.sha256.clone()),
        active_verification: active_revision.map(verification_label),
    })
}

fn scope_status(app: Option<&ShellApp>, scope: &kuzushi_core::ScopeRef) -> String {
    let Some(app) = app else {
        return "scope status unavailable".to_string();
    };
    let state = app
        .workbench_cache()
        .borrow()
        .cached_project_scope_tree(app.target());
    match state {
        ViewDataState::Ready(ProjectScopeTreeState::Persisted(tree)) => {
            scope_status_from_tree(scope, Some(&tree))
        }
        ViewDataState::Ready(ProjectScopeTreeState::RootOnly) => {
            scope_status_from_tree(scope, None)
        }
        ViewDataState::Ready(ProjectScopeTreeState::Unreadable(_)) => {
            "scope status unavailable".to_string()
        }
        ViewDataState::NotRequested | ViewDataState::Loading => "checking scope…".to_string(),
    }
}

fn scope_status_from_tree(
    scope: &kuzushi_core::ScopeRef,
    tree: Option<&kuzushi_core::NestedProjectScopeTree>,
) -> String {
    use kuzushi_core::capabilities::threat_model::ScopeBindingStatus;
    match kuzushi_core::capabilities::threat_model::classify_scope_binding(scope, tree) {
        Ok(ScopeBindingStatus::Exact) => "current".to_string(),
        Ok(ScopeBindingStatus::StaleDecomposition) => "stale · decomposition changed".to_string(),
        Ok(ScopeBindingStatus::Missing) => "stale · scope missing".to_string(),
        Err(_) => "scope status unavailable".to_string(),
    }
}

fn scope_header_suffix(status: &str) -> String {
    status
        .starts_with("stale")
        .then(|| format!(" · {status}"))
        .unwrap_or_default()
}

pub(crate) fn verification_label(revision: &ThreatModelRevisionMetadata) -> String {
    revision.verification.as_ref().map_or_else(
        || "unverified".to_string(),
        |verification| {
            if verification.document_sha256 == revision.sha256 {
                verification.verdict.clone()
            } else {
                "verification stale".to_string()
            }
        },
    )
}

fn cycle_model_index(active: Option<usize>, count: usize, reverse: bool) -> usize {
    match (active, reverse) {
        (Some(0), true) | (None, true) => count - 1,
        (Some(index), true) => index - 1,
        (Some(index), false) => (index + 1) % count,
        (None, false) => 0,
    }
}

fn empty_picker(status: &str) -> ThreatModelPickerModel {
    ThreatModelPickerModel {
        rows: Vec::new(),
        active_index: None,
        status: status.to_string(),
    }
}

fn legacy_threat_model_freshness(app: &ShellApp) -> ThreatModelFreshnessModel {
    let verdict = threat_model_doc(app)
        .and_then(|doc| {
            doc.pointer("/verification/verdict")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unverified".to_string());
    ThreatModelFreshnessModel {
        requires_attention: matches!(verdict.as_str(), "failed" | "stale"),
        verdict,
        document_sha256: active_mirror_sha256(app),
        current_sha256: active_mirror_sha256(app),
    }
}

fn active_mirror_sha256(app: &ShellApp) -> Option<String> {
    let root = app.target()?;
    let path = threat_model_artifact_path(root);
    app.workbench_cache()
        .borrow()
        .cached_json_file_content_sha256(&path)
}

fn active_mirror_state(app: &ShellApp) -> ViewDataState<JsonFileState> {
    let Some(root) = app.target() else {
        return ViewDataState::NotRequested;
    };
    let path = threat_model_artifact_path(root);
    app.workbench_cache().borrow().cached_json_file(root, &path)
}

pub(crate) fn threat_model_doc(app: &ShellApp) -> Option<serde_json::Value> {
    match read_threat_model_artifact(app) {
        ThreatModelArtifact::Present(doc) if !doc.is_null() => Some(doc),
        _ => None,
    }
}

/// Why a threat-derived view has nothing to project. A `Present` artifact only
/// reaches here when its `threats` array is empty, so the hint must not claim
/// the model is missing.
pub(crate) fn threat_model_absence_hint(app: &ShellApp) -> String {
    match read_threat_model_artifact(app) {
        ThreatModelArtifact::Present(_) => THREAT_MODEL_NO_THREATS_HINT.to_string(),
        ThreatModelArtifact::Invalid(error) => format!("threat-model integrity error: {error}"),
        ThreatModelArtifact::Unavailable(reason) => reason,
        ThreatModelArtifact::Malformed => THREAT_MODEL_MALFORMED_HINT.to_string(),
        ThreatModelArtifact::NonFile => THREAT_MODEL_NON_FILE_HINT.to_string(),
        ThreatModelArtifact::Targetless => THREAT_MODEL_TARGETLESS_HINT.to_string(),
        ThreatModelArtifact::Missing => THREAT_MODEL_EMPTY_HINT.to_string(),
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
    let status = map_context::recorded_map_summary_status(app);
    let patch = status
        .is_none()
        .then(|| app.engagement.pending_threat_patch())
        .flatten();
    match read_threat_model_artifact(app) {
        ThreatModelArtifact::Present(doc) if !doc.is_null() => {
            let mut review = ThreatSummaryReview::from_doc(Some(&doc), patch);
            if let Some(status) = status {
                review.status = status.into();
            }
            review
        }
        ThreatModelArtifact::Malformed => ThreatSummaryReview::malformed(patch),
        ThreatModelArtifact::Invalid(error) => ThreatSummaryReview::invalid(patch, &error),
        ThreatModelArtifact::Unavailable(reason) => {
            let mut review = ThreatSummaryReview::unknown(patch);
            review.status = "recorded Map context unavailable".into();
            review.summary = reason;
            review
        }
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
            summary: THREAT_MODEL_EMPTY_HINT.to_string(),
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
            summary: THREAT_MODEL_TARGETLESS_HINT.to_string(),
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
            assumptions: vec![THREAT_MODEL_MALFORMED_HINT.to_string()],
            missing_inputs: vec![format!("valid {}", threat_model_file_name())],
            proposed_changes: proposed_changes(patch),
            limitations: vec![
                "threat model artifact is malformed; do not infer threats from it".to_string(),
            ],
        }
    }

    fn invalid(patch: Option<&ThreatPatch>, error: &str) -> Self {
        let mut review = Self::malformed(patch);
        review.status = "integrity error".to_string();
        review.summary = format!("authoritative threat-model store is invalid: {error}");
        review.assumptions = vec!["no threat-model content was trusted".to_string()];
        review.limitations = vec![
            "repair the manifest or active immutable object before using Map evidence".to_string(),
        ];
        review
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
            assumptions: vec![THREAT_MODEL_NON_FILE_HINT.to_string()],
            missing_inputs: vec![format!("valid {} file", threat_model_file_name())],
            proposed_changes: proposed_changes(patch),
            limitations: vec![
                "threat model artifact path is invalid; do not infer threats from it".to_string(),
            ],
        }
    }
}

fn read_threat_model_artifact(app: &ShellApp) -> ThreatModelArtifact {
    if let Some(artifact) = map_context::recorded_map_artifact(app) {
        return artifact;
    }
    let Some(root) = app.target() else {
        return ThreatModelArtifact::Targetless;
    };
    match app
        .workbench_cache()
        .borrow()
        .cached_threat_model_store(Some(root))
    {
        ViewDataState::Ready(ThreatModelStoreState::Ready {
            active: Some(active),
            ..
        }) => return ThreatModelArtifact::Present(active.document),
        ViewDataState::Ready(ThreatModelStoreState::Ready { active: None, .. }) => {
            return ThreatModelArtifact::Missing;
        }
        ViewDataState::Ready(ThreatModelStoreState::Invalid(error)) => {
            return ThreatModelArtifact::Invalid(error);
        }
        ViewDataState::NotRequested | ViewDataState::Loading => {
            return ThreatModelArtifact::Missing;
        }
        ViewDataState::Ready(ThreatModelStoreState::Legacy) => {}
    }
    read_legacy_threat_model_artifact(app, root)
}

fn read_legacy_threat_model_artifact(
    app: &ShellApp,
    root: &std::path::Path,
) -> ThreatModelArtifact {
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

/// Materializes a target whose persisted threat-model artifact holds
/// `contents`, hydrated so the workbench cache serves it.
#[cfg(test)]
pub(crate) fn app_with_threat_model_json(temp: &tempfile::TempDir, contents: &str) -> ShellApp {
    let artifact_path = threat_model_artifact_path(temp.path());
    std::fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
    std::fs::write(artifact_path, contents).unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();
    app
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
    Invalid(String),
    Unavailable(String),
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

/// Actors the model names: its own `actors` table when it has one, else the
/// distinct `threats[].actor` values, else the DFD's actor/external-entity
/// nodes. A model that names none of these has not modeled actors, which is
/// `unknown`, not a measured zero.
fn actor_count(doc: &serde_json::Value) -> Option<usize> {
    array_len(doc.get("actors"))
        .or_else(|| distinct_threat_actor_count(doc))
        .or_else(|| dfd_actor_node_count(doc))
}

fn distinct_threat_actor_count(doc: &serde_json::Value) -> Option<usize> {
    let actors = doc
        .get("threats")?
        .as_array()?
        .iter()
        .filter_map(|threat| threat.get("actor").and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|actor| !actor.is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    (!actors.is_empty()).then_some(actors.len())
}

fn dfd_actor_node_count(doc: &serde_json::Value) -> Option<usize> {
    let nodes = doc.pointer("/dfd/nodes")?.as_array()?;
    let count = nodes
        .iter()
        .filter(|node| {
            node.get("type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind == "external-entity" || kind == "actor")
        })
        .count();
    (count > 0).then_some(count)
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

    #[test]
    fn actors_come_from_the_model_before_any_fallback() {
        let threats = serde_json::json!({
            "threats": [
                {"actor": "adjacent_network"},
                {"actor": "adjacent_network"},
                {"actor": "remote_attacker"}
            ],
            "dfd": {"nodes": [{"type": "process"}]}
        });
        assert_eq!(actor_count(&threats), Some(2));

        let table = serde_json::json!({"actors": [{}, {}, {}], "threats": [{"actor": "a"}]});
        assert_eq!(actor_count(&table), Some(3));

        let dfd = serde_json::json!({"dfd": {"nodes": [{"type": "external-entity"}]}});
        assert_eq!(actor_count(&dfd), Some(1));
    }

    #[test]
    fn a_model_that_names_no_actor_reports_unknown_not_zero() {
        let doc = serde_json::json!({
            "threats": [{"title": "no actor field"}],
            "dfd": {"nodes": [{"type": "process"}]}
        });
        assert_eq!(count_label(actor_count(&doc), "actor"), "unknown");
    }
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
        let app = app_with_threat_model_json(&temp, "{not-json");

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
        let app = app_with_threat_model_json(&temp, "[]");

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
    fn threat_model_absence_hint_names_the_targetless_state() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        assert_eq!(
            threat_model_absence_hint(&app),
            THREAT_MODEL_TARGETLESS_HINT
        );
    }

    #[test]
    fn threat_model_absence_hint_names_a_missing_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        assert_eq!(threat_model_absence_hint(&app), THREAT_MODEL_EMPTY_HINT);
    }

    #[test]
    fn threat_model_absence_hint_keeps_a_zero_threat_model_present() {
        let temp = tempfile::tempdir().unwrap();
        let app = app_with_threat_model_json(&temp, r#"{"threats": []}"#);

        assert_eq!(
            threat_model_absence_hint(&app),
            THREAT_MODEL_NO_THREATS_HINT
        );
    }

    #[test]
    fn threat_model_absence_hint_names_a_malformed_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let app = app_with_threat_model_json(&temp, "{not-json");

        assert_eq!(threat_model_absence_hint(&app), THREAT_MODEL_MALFORMED_HINT);
    }

    #[test]
    fn targetless_threat_model_view_does_not_read_cwd_artifacts() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        let review = threat_summary_review(&app);

        assert_eq!(review.status, "no target selected");
        assert!(review.summary.contains("select a target"));
        assert_eq!(review.limitations, vec!["no workspace artifacts were read"]);
    }

    #[test]
    fn picker_enumerates_heads_and_cycles_from_the_active_lineage() {
        let picker = picker_from_value(model_manifest_fixture("verified", "sha256:aaaa"));

        assert_eq!(picker.rows.len(), 2);
        assert_eq!(picker.active_index, Some(0));
        assert_eq!(
            picker.header_chip().as_deref(),
            Some("model 1/2 · Root STRIDE · stride · verified")
        );
        assert_eq!(
            picker.cycle_ref(false).unwrap().model_id.as_str(),
            "tm_22222222222222222222222222222222"
        );
        assert_eq!(
            picker.cycle_ref(true).unwrap().model_id.as_str(),
            "tm_22222222222222222222222222222222"
        );
    }

    #[test]
    fn picker_never_reuses_a_verdict_computed_for_another_document() {
        let picker = picker_from_value(model_manifest_fixture("verified", "sha256:other"));

        assert_eq!(picker.rows[0].verification, "verification stale");
        assert_eq!(
            picker.header_chip().as_deref(),
            Some("model 1/2 · Root STRIDE · stride · verification stale")
        );
    }

    #[test]
    fn scope_status_discloses_changed_and_missing_decompositions() {
        let root = tempfile::tempdir().unwrap();
        let current =
            kuzushi_core::capabilities::threat_model::current_scope_ref_for_path(root.path(), ".")
                .unwrap()
                .unwrap();
        assert_eq!(scope_status_from_tree(&current, None), "current");

        let mut changed = current.clone();
        changed.project_model_sha256 = format!("sha256:{}", "2".repeat(64));
        assert_eq!(
            scope_status_from_tree(&changed, None),
            "stale · decomposition changed"
        );

        let mut missing = current;
        missing.scope_id = "removed-scope".to_string();
        assert_eq!(
            scope_status_from_tree(&missing, None),
            "stale · scope missing"
        );
    }

    #[test]
    fn divergent_compatibility_mirror_is_not_presented_as_verified() {
        let temp = tempfile::tempdir().unwrap();
        commit_test_model(temp.path(), "stride");
        let mirror = threat_model_artifact_path(temp.path());
        std::fs::write(
            &mirror,
            r#"{"verification":{"verdict":"verified"},"manual":"edit"}"#,
        )
        .unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        let picker = threat_model_picker(&app);
        let freshness = threat_model_freshness(&app);

        assert_eq!(
            picker.rows[0].active_verification.as_deref(),
            Some("manual edit")
        );
        assert_eq!(freshness.verdict, "manual edit");
        assert!(freshness.requires_attention);
        assert_ne!(freshness.document_sha256, freshness.current_sha256);
    }

    #[test]
    fn malformed_compatibility_mirror_is_reported_as_an_unadoptable_manual_edit() {
        let temp = tempfile::tempdir().unwrap();
        commit_test_model(temp.path(), "stride");
        std::fs::write(threat_model_artifact_path(temp.path()), b"{not-json").unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        let picker = threat_model_picker(&app);
        let freshness = threat_model_freshness(&app);

        assert_eq!(
            picker.rows[0].active_verification.as_deref(),
            Some("manual edit")
        );
        assert!(picker.status.contains("cannot be adopted"));
        assert_eq!(freshness.verdict, "manual edit");
        assert!(freshness.requires_attention);
        assert!(
            threat_model_doc(&app).is_some(),
            "the immutable object stays authoritative"
        );
    }

    #[test]
    fn corrupt_active_object_fails_closed_in_every_threat_projection() {
        let temp = tempfile::tempdir().unwrap();
        let model_ref = commit_test_model(temp.path(), "stride");
        let object =
            kuzushi_core::threat_model_object_path(temp.path(), &model_ref.sha256).unwrap();
        std::fs::write(object, b"corrupt").unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        assert!(threat_model_doc(&app).is_none());
        assert!(threat_model_picker(&app).status.contains("integrity error"));
        assert_eq!(threat_summary_review(&app).status, "integrity error");
        assert!(threat_model_absence_hint(&app).contains("integrity error"));
    }

    #[test]
    fn explicit_dfd_refresh_reloads_model_authority_and_refuses_corrupt_revisions() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_latest_threat_model_for_dfd();
        assert!(threat_model_doc(&app).is_none());

        commit_test_model(temp.path(), "stride");
        app.hydrate_latest_threat_model_for_dfd();
        assert_eq!(threat_model_doc(&app).unwrap()["methodology"], "stride");

        let active = commit_test_model(temp.path(), "pasta");
        app.hydrate_latest_threat_model_for_dfd();
        assert_eq!(threat_model_doc(&app).unwrap()["methodology"], "pasta");

        let object = kuzushi_core::threat_model_object_path(temp.path(), &active.sha256).unwrap();
        std::fs::write(object, b"corrupt").unwrap();
        app.hydrate_latest_threat_model_for_dfd();
        assert!(threat_model_doc(&app).is_none());
        assert!(threat_model_absence_hint(&app).contains("integrity error"));
    }

    fn commit_test_model(root: &std::path::Path, methodology: &str) -> ThreatModelRef {
        let scope = kuzushi_core::capabilities::threat_model::current_scope_ref_for_path(root, ".")
            .unwrap()
            .unwrap();
        let document = json!({
            "version": "2.0",
            "methodology": methodology,
            "dfd": {"nodes": [{"id": "app"}], "flows": [], "trustBoundaries": []},
            "threats": [],
            "summary": {},
            "verification": {"verdict": "verified"}
        });
        kuzushi_core::capabilities::threat_model::commit_threat_model_revision(
            root,
            &document,
            kuzushi_core::capabilities::threat_model::ThreatModelCommit {
                model_id: None,
                new_model: false,
                label: "Root STRIDE".to_string(),
                scope,
                methodology: methodology.to_string(),
                source: kuzushi_core::capabilities::threat_model::ThreatModelRevisionSource::Build,
                source_revision_id: None,
                run_id: None,
                activate: Some(true),
                actor: "test".to_string(),
            },
        )
        .unwrap()
        .model_ref
    }

    fn model_manifest_fixture(verdict: &str, verified_sha: &str) -> serde_json::Value {
        json!({
            "schemaVersion": 1,
            "generation": 3,
            "active": {
                "modelId": "tm_11111111111111111111111111111111",
                "revisionId": "tmr_11111111111111111111111111111111",
                "sha256": "sha256:aaaa"
            },
            "models": [
                model_fixture(
                    "tm_11111111111111111111111111111111",
                    "tmr_11111111111111111111111111111111",
                    "sha256:aaaa",
                    "Root STRIDE",
                    "stride",
                    Some(json!({
                        "verdict": verdict,
                        "documentSha256": verified_sha
                    }))
                ),
                model_fixture(
                    "tm_22222222222222222222222222222222",
                    "tmr_22222222222222222222222222222222",
                    "sha256:bbbb",
                    "Payments PASTA",
                    "pasta",
                    None
                )
            ]
        })
    }

    fn model_fixture(
        model_id: &str,
        revision_id: &str,
        sha256: &str,
        label: &str,
        methodology: &str,
        verification: Option<serde_json::Value>,
    ) -> serde_json::Value {
        json!({
            "modelId": model_id,
            "label": label,
            "scope": {
                "scopeId": "root",
                "relPath": ".",
                "projectModelSha256": "sha256:scope",
                "targetRevision": "abc123"
            },
            "methodology": methodology,
            "createdAt": "2026-08-27T00:00:00Z",
            "headRevision": revision_id,
            "revisions": [{
                "revisionId": revision_id,
                "sha256": sha256,
                "createdAt": "2026-08-27T00:00:00Z",
                "source": "build",
                "verification": verification
            }]
        })
    }
}
