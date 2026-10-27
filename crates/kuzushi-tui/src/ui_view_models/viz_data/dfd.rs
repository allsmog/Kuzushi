use super::super::threat_dfd_diagram::{
    parse_flows, parse_nodes, zones_in_order, DfdFlow, DfdNode,
};
use crate::{DfdModelCacheKey, ShellApp};

mod evidence;
mod evidence_display;
mod overview;
pub(crate) use overview::{
    dfd_overview, dfd_overview_component_at, dfd_overview_component_count, display_target,
    DfdContextCounts, DfdOverview, DfdOverviewComponent, DfdOverviewFlow, DfdOverviewZone,
    DfdZoneFlow,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DfdKind {
    Entity,
    Process,
    Store,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdNodeModel {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub zone: String,
    pub kind: DfdKind,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdFlowModel {
    pub key: String,
    pub from_id: String,
    pub to_id: String,
    pub from: String,
    pub to: String,
    pub crosses: bool,
    pub label: String,
    pub boundary_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdBoundaryModel {
    pub key: String,
    pub name: String,
    pub inner_zone: String,
    pub outer_zone: String,
    pub crossing_flow_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DfdSecurityKind {
    EntryPoint,
    RoleGate,
    ExternalSink,
    TrustedCaller,
    Asset,
    Threat,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdSecurityItem {
    pub key: String,
    pub kind: DfdSecurityKind,
    pub label: String,
    pub detail: String,
    pub evidence: String,
    pub evidence_paths: Vec<String>,
    pub file_paths: Vec<String>,
    pub target_element_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DfdLinkState {
    Complete,
    #[default]
    LegacyNeedsRebuild,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct DfdModel {
    pub target_name: String,
    pub system_context: Option<String>,
    pub zones: Vec<String>,
    pub nodes: Vec<DfdNodeModel>,
    pub flows: Vec<DfdFlowModel>,
    pub boundaries: Vec<DfdBoundaryModel>,
    pub security_context: Vec<DfdSecurityItem>,
    pub element_file_paths: std::collections::BTreeMap<String, Vec<String>>,
    pub link_state: DfdLinkState,
    pub review_only: bool,
    pub empty_hint: Option<String>,
}

pub(crate) fn dfd_model(app: &ShellApp) -> DfdModel {
    let doc = super::super::threat_model_doc(app);
    if doc.is_none() && super::super::map_context_run_refs(app).is_some() {
        return empty_dfd(super::super::threat_model_absence_hint(app));
    }
    let key = DfdModelCacheKey::from_threat_doc(doc.as_ref());
    if let Some(cached) = app.workbench_cache().borrow().dfd_model(&key) {
        return cached;
    }
    let model = dfd_model_from_doc(doc.as_ref(), app.target());
    app.workbench_cache()
        .borrow_mut()
        .cache_dfd_model(key, model.clone());
    model
}

/// Whether the DFD has no topology to show — the question the scene footers ask
/// every frame. Served from the cached model without cloning it. The threat
/// document itself is still cloned by `threat_model_doc`, which every viz_data
/// builder shares; only that shared read can remove the remaining copy.
pub(crate) fn dfd_model_is_empty(app: &ShellApp) -> bool {
    let doc = super::super::threat_model_doc(app);
    let key = DfdModelCacheKey::from_threat_doc(doc.as_ref());
    if let Some(is_empty) = app.workbench_cache().borrow().dfd_model_is_empty(&key) {
        return is_empty;
    }
    dfd_model(app).empty_hint.is_some()
}

pub(crate) fn dfd_model_from_doc(
    doc: Option<&serde_json::Value>,
    target: Option<&std::path::Path>,
) -> DfdModel {
    let Some(doc) = doc else {
        return empty_dfd("no threat model yet — run `threat-model:build` to populate");
    };
    if let Some(hint) = unavailable_topology_hint(doc, target) {
        return empty_dfd(hint);
    }
    let nodes = parse_nodes(doc);
    if nodes.is_empty() {
        return empty_dfd("threat model has no data-flow diagram yet");
    }
    let flows = parse_flows(doc, &nodes);
    let links = kuzushi_core::capabilities::security_context_link_report(doc);
    let link_state = if links.is_complete() {
        DfdLinkState::Complete
    } else {
        DfdLinkState::LegacyNeedsRebuild
    };
    DfdModel {
        target_name: target_name(target),
        system_context: system_context(doc),
        zones: zones_in_order(&nodes),
        nodes: project_dfd_nodes(&nodes),
        flows: project_dfd_flows(&flows),
        boundaries: project_boundaries(doc),
        security_context: project_security_context(doc, link_state),
        element_file_paths: evidence::element_file_paths(doc),
        link_state,
        review_only: deterministic_review_only(doc),
        empty_hint: None,
    }
}

fn unavailable_topology_hint(
    doc: &serde_json::Value,
    target: Option<&std::path::Path>,
) -> Option<String> {
    if kuzushi_core::workflow_attempts::threat_model_is_scope_placeholder_only(doc) {
        return Some(scope_placeholder_hint(target));
    }
    let available = kuzushi_core::workflow_attempts::threat_model_has_concrete_dfd(doc)
        || kuzushi_core::workflow_attempts::threat_model_has_recorded_component(doc);
    (!available).then(|| "No recorded components or data flows. Add source or design context before mapping relationships.".into())
}

impl DfdModel {
    pub(crate) fn file_paths_for_selection(
        &self,
        selection: usize,
        context_row: Option<usize>,
    ) -> Vec<String> {
        let rows = dfd_security_items_for_selection(self, selection);
        if let Some(index) = context_row {
            return rows
                .get(index)
                .map(|row| row.file_paths.clone())
                .unwrap_or_default();
        }
        rows.into_iter()
            .flat_map(|row| row.file_paths.clone())
            .chain(self.direct_files_for_selection(selection).iter().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn direct_files_for_selection(&self, selection: usize) -> &[String] {
        let key = match dfd_selected_item(self, selection) {
            Some(DfdSelected::Node(node)) => &node.key,
            Some(DfdSelected::Flow(flow)) => &flow.key,
            Some(DfdSelected::Boundary(boundary)) => &boundary.key,
            None => return &[],
        };
        self.element_file_paths
            .get(key)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(crate) fn topology_notice(&self) -> Option<&'static str> {
        (!self.nodes.is_empty() && self.flows.is_empty()).then_some(
            "Component map only. No data flows are recorded; relationships remain unknown.",
        )
    }
    pub(crate) fn evidence_notice(&self) -> Option<&'static str> {
        self.review_only.then_some(
            "Partial deterministic Map. Artifact review only; no model or empirical verification.",
        )
    }
}

fn deterministic_review_only(doc: &serde_json::Value) -> bool {
    doc.pointer("/degradation/mode")
        .and_then(serde_json::Value::as_str)
        == Some("deterministic-no-runtime")
}

fn empty_dfd(hint: impl Into<String>) -> DfdModel {
    DfdModel {
        empty_hint: Some(hint.into()),
        ..Default::default()
    }
}

fn target_name(target: Option<&std::path::Path>) -> String {
    target
        .and_then(std::path::Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "modeled system".to_string())
}

fn system_context(doc: &serde_json::Value) -> Option<String> {
    ["systemContext", "system_context", "context", "description"]
        .into_iter()
        .find_map(|key| string_field(doc, key))
}

fn project_dfd_nodes(nodes: &[DfdNode]) -> Vec<DfdNodeModel> {
    nodes
        .iter()
        .map(|node| DfdNodeModel {
            key: node.id.clone(),
            name: node.name.clone(),
            description: node.description.clone(),
            purpose: node.purpose.clone(),
            zone: node.zone.clone(),
            kind: dfd_kind(&node.kind),
        })
        .collect()
}

fn project_dfd_flows(flows: &[DfdFlow]) -> Vec<DfdFlowModel> {
    flows
        .iter()
        .map(|flow| DfdFlowModel {
            key: flow.id.clone(),
            from_id: flow.source_id.clone(),
            to_id: flow.target_id.clone(),
            from: flow.source.clone(),
            to: flow.target.clone(),
            crosses: flow.crosses,
            label: flow.label.clone(),
            boundary_ids: flow.boundary_ids.clone(),
        })
        .collect()
}

fn project_boundaries(doc: &serde_json::Value) -> Vec<DfdBoundaryModel> {
    rows_at(doc, "/dfd/trustBoundaries")
        .filter_map(boundary_from_value)
        .collect()
}

fn boundary_from_value(value: &serde_json::Value) -> Option<DfdBoundaryModel> {
    Some(DfdBoundaryModel {
        key: string_field(value, "id")?,
        name: string_field(value, "name").unwrap_or_else(|| "Trust boundary".to_string()),
        inner_zone: string_field(value, "innerZone").unwrap_or_else(|| "unknown".to_string()),
        outer_zone: string_field(value, "outerZone").unwrap_or_else(|| "unknown".to_string()),
        crossing_flow_ids: string_array(value, "crossingFlowIds"),
    })
}

fn project_security_context(
    doc: &serde_json::Value,
    link_state: DfdLinkState,
) -> Vec<DfdSecurityItem> {
    if link_state != DfdLinkState::Complete {
        return Vec::new();
    }
    security_collections()
        .into_iter()
        .flat_map(|(kind, pointer)| {
            rows_at(doc, pointer).filter_map(move |row| security_item_from_value(row, kind))
        })
        .collect()
}

fn security_collections() -> [(DfdSecurityKind, &'static str); 6] {
    [
        (DfdSecurityKind::EntryPoint, "/attackSurface/entryPoints"),
        (DfdSecurityKind::RoleGate, "/attackSurface/roleGates"),
        (
            DfdSecurityKind::ExternalSink,
            "/attackSurface/externalSinks",
        ),
        (
            DfdSecurityKind::TrustedCaller,
            "/attackSurface/trustedCallers",
        ),
        (DfdSecurityKind::Asset, "/assets"),
        (DfdSecurityKind::Threat, "/threats"),
    ]
}

fn security_item_from_value(
    value: &serde_json::Value,
    kind: DfdSecurityKind,
) -> Option<DfdSecurityItem> {
    let evidence = evidence::security_evidence(value);
    Some(DfdSecurityItem {
        key: string_field(value, "id")?,
        kind,
        label: security_label(value, kind),
        detail: security_detail(value, kind),
        evidence: string_field(value, "evidence")
            .or_else(|| evidence.references.first().cloned())
            .unwrap_or_default(),
        evidence_paths: evidence.references,
        file_paths: evidence.files,
        target_element_ids: string_array(value, "targetElementIds"),
    })
}

fn security_label(value: &serde_json::Value, kind: DfdSecurityKind) -> String {
    let fields = match kind {
        DfdSecurityKind::EntryPoint => &["name", "title", "handler", "route"][..],
        DfdSecurityKind::RoleGate => &["check", "guarded"][..],
        DfdSecurityKind::ExternalSink => &["name", "context"][..],
        DfdSecurityKind::TrustedCaller => &["role", "purpose"][..],
        DfdSecurityKind::Asset => &["asset", "name"][..],
        DfdSecurityKind::Threat => &["title", "description"][..],
    };
    first_string(value, fields).unwrap_or_else(|| "unnamed".to_string())
}

fn security_detail(value: &serde_json::Value, kind: DfdSecurityKind) -> String {
    let fields = match kind {
        DfdSecurityKind::EntryPoint => &["description", "route", "path"][..],
        DfdSecurityKind::RoleGate => &["guarded", "description"][..],
        DfdSecurityKind::ExternalSink => &["context", "category"][..],
        DfdSecurityKind::TrustedCaller => &["purpose", "description"][..],
        DfdSecurityKind::Asset => &["description", "sensitivity"][..],
        DfdSecurityKind::Threat => &["description", "recommendedMitigation"][..],
    };
    first_string(value, fields).unwrap_or_default()
}

fn first_string(value: &serde_json::Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| string_field(value, field))
}

pub(super) fn string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}

pub(super) fn string_array(value: &serde_json::Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(ToString::to_string)
        .collect()
}

pub(super) fn rows_at<'a>(
    doc: &'a serde_json::Value,
    pointer: &str,
) -> impl Iterator<Item = &'a serde_json::Value> {
    doc.pointer(pointer)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
}

/// Selection cursor item over flattened nodes, flows, then boundaries.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum DfdSelected<'a> {
    Node(&'a DfdNodeModel),
    Flow(&'a DfdFlowModel),
    Boundary(&'a DfdBoundaryModel),
}

pub(crate) fn dfd_selectable_count(model: &DfdModel) -> usize {
    model.nodes.len() + model.flows.len() + model.boundaries.len()
}

pub(crate) fn dfd_selection_for_key(model: &DfdModel, key: &str) -> Option<usize> {
    if let Some(index) = model.nodes.iter().position(|node| node.key == key) {
        return Some(index);
    }
    if let Some(index) = model.flows.iter().position(|flow| flow.key == key) {
        return Some(model.nodes.len() + index);
    }
    model
        .boundaries
        .iter()
        .position(|boundary| boundary.key == key)
        .map(|index| model.nodes.len() + model.flows.len() + index)
}

pub(crate) fn dfd_selected_item(model: &DfdModel, index: usize) -> Option<DfdSelected<'_>> {
    if let Some(node) = model.nodes.get(index) {
        return Some(DfdSelected::Node(node));
    }
    if let Some(flow) = model.flows.get(index.wrapping_sub(model.nodes.len())) {
        return Some(DfdSelected::Flow(flow));
    }
    model
        .boundaries
        .get(index.wrapping_sub(model.nodes.len() + model.flows.len()))
        .map(DfdSelected::Boundary)
}

pub(crate) fn dfd_security_items_for_selection(
    model: &DfdModel,
    index: usize,
) -> Vec<&DfdSecurityItem> {
    let targets = selected_context_ids(model, index);
    model
        .security_context
        .iter()
        .filter(|item| {
            item.target_element_ids
                .iter()
                .any(|target| targets.contains(target))
        })
        .collect()
}

fn selected_context_ids(model: &DfdModel, index: usize) -> Vec<String> {
    match dfd_selected_item(model, index) {
        Some(DfdSelected::Node(node)) => vec![node.key.clone()],
        Some(DfdSelected::Flow(flow)) => {
            let mut ids = vec![flow.key.clone()];
            ids.extend(flow.boundary_ids.iter().cloned());
            ids
        }
        Some(DfdSelected::Boundary(boundary)) => {
            let mut ids = vec![boundary.key.clone()];
            ids.extend(boundary.crossing_flow_ids.iter().cloned());
            ids
        }
        None => Vec::new(),
    }
}

fn scope_placeholder_hint(target: Option<&std::path::Path>) -> String {
    target.map_or_else(
        || "threat model contains only a generated repository-scope placeholder".to_string(),
        kuzushi_core::workflow_attempts::insufficient_map_evidence_message,
    )
}

fn dfd_kind(raw: &str) -> DfdKind {
    let kind = raw.to_ascii_lowercase();
    if kind.contains("entity") || kind.contains("actor") || kind.contains("external") {
        DfdKind::Entity
    } else if kind.contains("store") || kind.contains("data") {
        DfdKind::Store
    } else {
        DfdKind::Process
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_named_component_without_flows_remains_visible_without_fabricated_relationships() {
        let document = serde_json::json!({"systemContext":"Owned dependency metadata; no runtime behavior is established.","dfd":{"nodes":[{"id":"lock","name":"Declared lockfile","type":"data-store","trustZone":"repository","description":"Cargo.lock declares dependency versions.","purpose":"Supports owner review."}],"flows":[],"trustBoundaries":[]},"threats":[]});
        let model = super::dfd_model_from_doc(Some(&document), None);
        assert!(model.empty_hint.is_none());
        assert_eq!(model.nodes.len(), 1);
        assert_eq!(model.nodes[0].name, "Declared lockfile");
        assert!(model.flows.is_empty());
        assert!(model
            .topology_notice()
            .unwrap()
            .contains("relationships remain unknown"));
        assert_eq!(super::dfd_selectable_count(&model), 1);
        let overview = super::dfd_overview(&model);
        assert!(overview.executive_summary.contains("no runtime behavior"));
        assert_eq!(super::dfd_overview_component_count(&overview), 1);
        assert!(overview.zone_flows.is_empty());
    }

    #[test]
    fn synthetic_scope_node_with_a_stored_claim_does_not_become_a_component_map() {
        let document = serde_json::json!({"dfd":{"nodes":[{"id":"app","name":"Application","description":"Repository application boundary"}],"flows":[]},"threats":[{"title":"Unassessed claim"}]});
        let model = super::dfd_model_from_doc(Some(&document), None);
        assert!(model.empty_hint.is_some());
        assert!(model.nodes.is_empty());
    }
    #[test]
    fn deterministic_map_retains_a_read_only_evidence_notice_with_its_real_topology() {
        let document = serde_json::json!({"degradation":{"mode":"deterministic-no-runtime"},"dfd":{"nodes":[{"id":"N1","name":"Health service","type":"process","trustZone":"internal"},{"id":"N2","name":"HTTP client","type":"external_entity","trustZone":"external"}],"flows":[{"id":"F1","from":"N2","to":"N1","data":"health requests"}],"trustBoundaries":[]}});
        let model = super::dfd_model_from_doc(Some(&document), None);
        assert!(model.review_only);
        assert!(model
            .evidence_notice()
            .unwrap()
            .contains("no model or empirical verification"));
        assert_eq!(model.nodes.len(), 2);
    }
    use super::*;
    use kuzushi_core::{capabilities::persistent_threat_model_path, V2Config, WorkspaceTarget};

    #[test]
    fn selection_for_key_covers_nodes_flows_and_boundaries() {
        let model = DfdModel {
            nodes: vec![DfdNodeModel {
                key: "N1".into(),
                name: "API".into(),
                description: None,
                purpose: None,
                zone: "app".into(),
                kind: DfdKind::Process,
            }],
            flows: vec![DfdFlowModel {
                key: "F1".into(),
                from_id: "N1".into(),
                to_id: "N1".into(),
                from: "API".into(),
                to: "API".into(),
                crosses: true,
                label: "loop".into(),
                boundary_ids: vec!["TB1".into()],
            }],
            boundaries: vec![DfdBoundaryModel {
                key: "TB1".into(),
                name: "edge".into(),
                inner_zone: "app".into(),
                outer_zone: "internet".into(),
                crossing_flow_ids: vec!["F1".into()],
            }],
            ..Default::default()
        };

        assert_eq!(dfd_selection_for_key(&model, "N1"), Some(0));
        assert_eq!(dfd_selection_for_key(&model, "F1"), Some(1));
        assert_eq!(dfd_selection_for_key(&model, "TB1"), Some(2));
        assert_eq!(dfd_selection_for_key(&model, "missing"), None);
    }

    #[test]
    fn dfd_model_refreshes_when_threat_doc_version_changes() {
        let temp = tempfile::tempdir().unwrap();
        write_threat_model(temp.path(), "api");
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();

        assert_eq!(dfd_model(&app).nodes[0].name, "api");
        write_threat_model(temp.path(), "worker");
        app.workbench_cache()
            .borrow_mut()
            .invalidate_workspace_files();
        app.invalidate_view_hydration();
        app.hydrate_all_view_data_for_test();
        assert_eq!(dfd_model(&app).nodes[0].name, "worker");
    }

    #[test]
    fn generated_repository_scope_placeholder_is_an_empty_dfd() {
        let temp = tempfile::tempdir().unwrap();
        let path = persistent_threat_model_path(temp.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            serde_json::json!({
                "dfd": {
                    "nodes": [{
                        "id": "n1",
                        "name": "fixture repository scope",
                        "trustZone": "analysis-scope",
                        "type": "process"
                    }],
                    "flows": []
                },
                "threats": []
            })
            .to_string(),
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();

        let model = dfd_model(&app);

        assert!(model.nodes.is_empty());
        assert!(model.flows.is_empty());
        let target = workspace.root().display().to_string();
        assert!(model
            .empty_hint
            .as_deref()
            .is_some_and(|hint| hint.contains(&target)));
    }

    #[test]
    fn linked_security_context_attaches_to_exact_dfd_elements() {
        let doc = linked_document();
        let model = dfd_model_from_doc(Some(&doc), None);

        assert_eq!(model.link_state, DfdLinkState::Complete);
        assert_eq!(model.boundaries.len(), 1);
        let api_items = dfd_security_items_for_selection(&model, 1);
        assert_eq!(
            api_items
                .iter()
                .map(|item| item.key.as_str())
                .collect::<Vec<_>>(),
            ["AS-oauth", "A-token"]
        );
        let flow_items = dfd_security_items_for_selection(&model, model.nodes.len());
        assert_eq!(
            flow_items
                .iter()
                .map(|item| item.key.as_str())
                .collect::<Vec<_>>(),
            ["T-callback"]
        );
    }

    #[test]
    fn structured_security_evidence_exposes_all_repository_paths() {
        let mut doc = linked_document();
        doc["attackSurface"]["entryPoints"][0]["path"] =
            serde_json::json!("services/api/src/oauth.rs");
        doc["threats"][0]["affectedFiles"] = serde_json::json!([
            "services/api/src/callback.rs",
            {"path": "services/api/src/session.rs"}
        ]);
        doc["threats"][0]["evidenceRefs"] = serde_json::json!([
            {"source": "services/api/src/router.rs:42"},
            {"filePath": "services/api/src/token.rs"}
        ]);

        let model = dfd_model_from_doc(Some(&doc), None);
        let entry = model
            .security_context
            .iter()
            .find(|item| item.key == "AS-oauth")
            .unwrap();
        let threat = model
            .security_context
            .iter()
            .find(|item| item.key == "T-callback")
            .unwrap();

        assert_eq!(entry.evidence_paths, ["services/api/src/oauth.rs"]);
        assert_eq!(
            threat.evidence_paths,
            [
                "services/api/src/callback.rs",
                "services/api/src/router.rs:42",
                "services/api/src/session.rs",
                "services/api/src/token.rs",
            ]
        );
    }

    #[test]
    fn legacy_links_keep_topology_but_suppress_the_overlay() {
        let mut doc = linked_document();
        doc["attackSurface"]["entryPoints"][0]
            .as_object_mut()
            .unwrap()
            .remove("targetElementIds");

        let model = dfd_model_from_doc(Some(&doc), None);

        assert_eq!(model.nodes.len(), 2);
        assert_eq!(model.flows.len(), 1);
        assert_eq!(model.link_state, DfdLinkState::LegacyNeedsRebuild);
        assert!(model.security_context.is_empty());
    }

    fn linked_document() -> serde_json::Value {
        serde_json::json!({
            "dfd": {
                "nodes": [
                    {"id": "user", "name": "Browser", "trustZone": "internet"},
                    {"id": "api", "name": "OAuth callback", "trustZone": "app"}
                ],
                "flows": [{
                    "id": "callback",
                    "sourceId": "user",
                    "targetId": "api",
                    "description": "callback",
                    "trustBoundaryIds": ["edge"]
                }],
                "trustBoundaries": [{
                    "id": "edge",
                    "name": "Internet edge",
                    "innerZone": "app",
                    "outerZone": "internet",
                    "crossingFlowIds": ["callback"]
                }]
            },
            "attackSurface": {
                "entryPoints": [{
                    "id": "AS-oauth",
                    "name": "oauth_callback",
                    "targetElementIds": ["api"]
                }]
            },
            "assets": [{
                "id": "A-token",
                "asset": "OAuth token",
                "targetElementIds": ["api"]
            }],
            "threats": [{
                "id": "T-callback",
                "title": "Callback confusion",
                "targetElementIds": ["callback"]
            }]
        })
    }

    fn write_threat_model(root: &std::path::Path, node: &str) {
        let path = persistent_threat_model_path(root);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            serde_json::json!({
                "dfd": {
                    "nodes": [
                        {
                            "id": "node-a",
                            "name": node,
                            "trustZone": "app",
                            "type": "process"
                        },
                        {
                            "id": "node-b",
                            "name": "store",
                            "trustZone": "data",
                            "type": "data-store"
                        }
                    ],
                    "flows": [{
                        "id": "flow",
                        "sourceId": "node-a",
                        "targetId": "node-b",
                        "description": "write"
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();
    }
}
