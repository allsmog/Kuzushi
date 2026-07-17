use super::super::threat_dfd_diagram::{
    parse_flows, parse_nodes, zones_in_order, DfdFlow, DfdNode,
};
use crate::{DfdModelCacheKey, ShellApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DfdKind {
    Entity,
    Process,
    Store,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdNodeModel {
    pub name: String,
    pub zone: String,
    pub kind: DfdKind,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdFlowModel {
    pub from: String,
    pub to: String,
    pub crosses: bool,
    pub label: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct DfdModel {
    pub zones: Vec<String>,
    pub nodes: Vec<DfdNodeModel>,
    pub flows: Vec<DfdFlowModel>,
    pub empty_hint: Option<String>,
}

pub(crate) fn dfd_model(app: &ShellApp) -> DfdModel {
    let doc = super::super::threat_model_doc(app);
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

fn dfd_model_from_doc(
    doc: Option<&serde_json::Value>,
    target: Option<&std::path::Path>,
) -> DfdModel {
    let Some(doc) = doc else {
        return empty_dfd("no threat model yet — run `threat-model:build` to populate");
    };
    if kuzushi_core::workflow_attempts::threat_model_is_scope_placeholder_only(doc) {
        return empty_dfd(scope_placeholder_hint(target));
    }
    if !kuzushi_core::workflow_attempts::threat_model_has_concrete_dfd(doc) {
        return empty_dfd(
            "threat model has no concrete topology yet — add design evidence and rebuild",
        );
    }
    let nodes = parse_nodes(doc);
    if nodes.is_empty() {
        return empty_dfd("threat model has no data-flow diagram yet");
    }
    let flows = parse_flows(doc, &nodes);
    DfdModel {
        zones: zones_in_order(&nodes),
        nodes: project_dfd_nodes(&nodes),
        flows: project_dfd_flows(&flows),
        empty_hint: None,
    }
}

fn empty_dfd(hint: impl Into<String>) -> DfdModel {
    DfdModel {
        empty_hint: Some(hint.into()),
        ..Default::default()
    }
}

fn project_dfd_nodes(nodes: &[DfdNode]) -> Vec<DfdNodeModel> {
    nodes
        .iter()
        .map(|node| DfdNodeModel {
            name: node.name.clone(),
            zone: node.zone.clone(),
            kind: dfd_kind(&node.kind),
        })
        .collect()
}

fn project_dfd_flows(flows: &[DfdFlow]) -> Vec<DfdFlowModel> {
    flows
        .iter()
        .map(|flow| DfdFlowModel {
            from: flow.source.clone(),
            to: flow.target.clone(),
            crosses: flow.crosses,
            label: flow.label.clone(),
        })
        .collect()
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
    use super::*;
    use kuzushi_core::{capabilities::persistent_threat_model_path, V2Config, WorkspaceTarget};

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
