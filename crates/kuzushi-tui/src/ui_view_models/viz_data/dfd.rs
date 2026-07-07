use super::super::threat_dfd_diagram::{parse_flows, parse_nodes, zones_in_order};
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
    if let Some(cached) = app.workbench_cache.borrow().dfd_model(&key) {
        return cached;
    }
    let model = dfd_model_from_doc(doc.as_ref());
    app.workbench_cache
        .borrow_mut()
        .cache_dfd_model(key, model.clone());
    model
}

fn dfd_model_from_doc(doc: Option<&serde_json::Value>) -> DfdModel {
    let Some(doc) = doc else {
        return DfdModel {
            empty_hint: Some(
                "no threat model yet — run `threat-model:build` to populate".to_string(),
            ),
            ..Default::default()
        };
    };
    let nodes = parse_nodes(doc);
    if nodes.is_empty() {
        return DfdModel {
            empty_hint: Some("threat model has no data-flow diagram yet".to_string()),
            ..Default::default()
        };
    }
    let flows = parse_flows(doc, &nodes);
    let zones = zones_in_order(&nodes);
    DfdModel {
        nodes: nodes
            .iter()
            .map(|n| DfdNodeModel {
                name: n.name.clone(),
                zone: n.zone.clone(),
                kind: dfd_kind(&n.kind),
            })
            .collect(),
        flows: flows
            .iter()
            .map(|f| DfdFlowModel {
                from: f.source.clone(),
                to: f.target.clone(),
                crosses: f.crosses,
                label: f.label.clone(),
            })
            .collect(),
        zones,
        empty_hint: None,
    }
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
        let app = ShellApp::new(V2Config::default(), Some(&workspace));

        assert_eq!(dfd_model(&app).nodes[0].name, "api");
        write_threat_model(temp.path(), "worker");
        assert_eq!(dfd_model(&app).nodes[0].name, "worker");
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
                            "id": "node",
                            "name": node,
                            "trustZone": "app",
                            "type": "process"
                        }
                    ],
                    "flows": []
                }
            })
            .to_string(),
        )
        .unwrap();
    }
}
