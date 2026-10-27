use super::*;
use serde_json::json;

fn graph(ids: &[&str], flows: &[(&str, &str)]) -> DfdModel {
    let nodes = ids.iter().enumerate().map(|(i,id)| json!({"id":id,"name":format!("Owned component {i}"),"description":"Owned recorded topology fixture","trustZone":"owned","type":"process"})).collect::<Vec<_>>();
    let flows = flows.iter().enumerate().map(|(i,(from,to))| json!({"id":format!("flow-{i}"),"sourceId":from,"targetId":to,"description":"Owned recorded transfer"})).collect::<Vec<_>>();
    super::super::dfd_model_from_doc(
        Some(&json!({"dfd":{"nodes":nodes,"flows":flows,"trustBoundaries":[]}})),
        None,
    )
}

#[test]
fn empty_and_component_only_models_keep_their_distinct_meaning() {
    assert!(DfdModel::default().topology_notice().is_none());
    let model = graph(&["owned"], &[]);
    assert!(model
        .topology_notice()
        .unwrap()
        .contains("Component map only"));
    assert!(model.component_topology_notice("owned").is_some());
    assert!(model.component_topology_notice("missing").is_none());
}

#[test]
fn inbound_outbound_and_self_flows_are_recorded_membership() {
    let model = graph(
        &["caller", "receiver", "records", "self"],
        &[
            ("caller", "receiver"),
            ("receiver", "records"),
            ("self", "self"),
        ],
    );
    assert!(model.topology_notice().is_none());
    for node in &model.nodes {
        assert!(model.component_topology_notice(&node.key).is_none());
    }
    let overview = super::super::dfd_overview(&model);
    assert!(overview
        .zones
        .iter()
        .flat_map(|z| &z.components)
        .all(|c| c.topology_notice().is_none()));
    assert_eq!(model.flows.len(), 3);
}

#[test]
fn literal_ids_unknown_endpoints_and_duplicate_rows_do_not_gain_connections() {
    let ids = ["literal", " literal ", "λ", "repeat", "repeat"];
    let model = graph(&ids, &[("literal", "literal"), ("unknown", "missing")]);
    assert!(model
        .topology_notice()
        .unwrap()
        .contains("4 components have no recorded flows"));
    assert!(model.component_topology_notice("literal").is_none());
    assert!(model.component_topology_notice(" literal ").is_some());
    assert!(model.component_topology_notice("λ").is_some());
    assert!(model.component_topology_notice("unknown").is_none());
    assert_eq!(
        model
            .nodes
            .iter()
            .map(|n| n.key.as_str())
            .collect::<Vec<_>>(),
        ids
    );
    assert_eq!(model.flows.len(), 2);
}

#[test]
fn fallback_summary_reports_inventory_without_claiming_every_node_exchanges_data() {
    let model = graph(&["source", "target", "standalone"], &[("source", "target")]);
    let summary = super::super::dfd_overview(&model).executive_summary;
    assert!(
        summary.contains("stored diagram records 3 components, 1 flow and 1 trust zone"),
        "{summary}"
    );
    assert!(!summary.contains("exchange data"));
    assert!(!summary.contains("primary process"));
}
