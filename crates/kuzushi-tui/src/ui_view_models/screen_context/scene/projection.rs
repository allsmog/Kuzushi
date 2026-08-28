use super::labels::{bounded_text, dfd_kind_label, security_kind_label};
use crate::scene3d::VizPage;
use crate::ui_view_models::{
    dfd_overview, dfd_overview_component_at, dfd_security_items_for_selection, dfd_selected_item,
    dfd_selection_for_key, DfdBoundaryModel, DfdFlowModel, DfdModel, DfdNodeModel, DfdSecurityItem,
    DfdSelected,
};
use serde_json::{json, Value};

const ONE_HOP_LIMIT: usize = 12;
const SECURITY_ROW_LIMIT: usize = 12;

pub(super) fn selected_scene_item(
    topology: &DfdModel,
    page: VizPage,
    dfd_selection: usize,
    summary_selection: usize,
) -> (Option<Value>, Option<usize>) {
    if page == VizPage::Summary {
        return selected_summary_component(topology, summary_selection);
    }
    if page != VizPage::Dfd {
        return (None, None);
    }
    (
        dfd_selected_item(topology, dfd_selection).map(selected_value),
        dfd_selected_item(topology, dfd_selection).map(|_| dfd_selection),
    )
}

fn selected_summary_component(
    topology: &DfdModel,
    selection: usize,
) -> (Option<Value>, Option<usize>) {
    let overview = dfd_overview(topology);
    let Some((zone, component)) = dfd_overview_component_at(&overview, selection) else {
        return (None, None);
    };
    let value = json!({
        "kind": "component",
        "id": component.key,
        "name": bounded_text(&component.name),
        "description": component.description.as_deref().map(bounded_text),
        "purpose": component.purpose.as_deref().map(bounded_text),
        "zone": bounded_text(&zone.name),
    });
    (Some(value), dfd_selection_for_key(topology, &component.key))
}

fn selected_value(selected: DfdSelected<'_>) -> Value {
    match selected {
        DfdSelected::Node(node) => node_value(node),
        DfdSelected::Flow(flow) => flow_value(flow),
        DfdSelected::Boundary(boundary) => boundary_value(boundary),
    }
}

fn node_value(node: &DfdNodeModel) -> Value {
    json!({
        "kind": "node",
        "id": node.key,
        "name": bounded_text(&node.name),
        "description": node.description.as_deref().map(bounded_text),
        "purpose": node.purpose.as_deref().map(bounded_text),
        "zone": bounded_text(&node.zone),
        "nodeKind": dfd_kind_label(node.kind),
    })
}

fn flow_value(flow: &DfdFlowModel) -> Value {
    json!({
        "kind": "flow",
        "id": flow.key,
        "sourceId": flow.from_id,
        "targetId": flow.to_id,
        "source": bounded_text(&flow.from),
        "target": bounded_text(&flow.to),
        "description": bounded_text(&flow.label),
        "crossesBoundary": flow.crosses,
        "trustBoundaryIds": flow.boundary_ids,
    })
}

fn boundary_value(boundary: &DfdBoundaryModel) -> Value {
    json!({
        "kind": "trust-boundary",
        "id": boundary.key,
        "name": bounded_text(&boundary.name),
        "innerZone": bounded_text(&boundary.inner_zone),
        "outerZone": bounded_text(&boundary.outer_zone),
        "crossingFlowIds": boundary.crossing_flow_ids,
    })
}

pub(super) fn one_hop_neighbors(
    topology: &DfdModel,
    selection: Option<usize>,
) -> (Vec<Value>, usize) {
    let Some(selected) = selection.and_then(|index| dfd_selected_item(topology, index)) else {
        return (Vec::new(), 0);
    };
    let all = match selected {
        DfdSelected::Node(node) => node_neighbors(topology, node),
        DfdSelected::Flow(flow) => flow_neighbors(topology, flow),
        DfdSelected::Boundary(boundary) => boundary_neighbors(topology, boundary),
    };
    let omitted = all.len().saturating_sub(ONE_HOP_LIMIT);
    (all.into_iter().take(ONE_HOP_LIMIT).collect(), omitted)
}

fn node_neighbors(topology: &DfdModel, node: &DfdNodeModel) -> Vec<Value> {
    topology
        .flows
        .iter()
        .filter(|flow| flow.from_id == node.key || flow.to_id == node.key)
        .flat_map(|flow| {
            let peer_id = if flow.from_id == node.key {
                &flow.to_id
            } else {
                &flow.from_id
            };
            let peer = topology
                .nodes
                .iter()
                .find(|candidate| candidate.key.as_str() == peer_id.as_str());
            std::iter::once(flow_value(flow)).chain(peer.map(node_value))
        })
        .collect()
}

fn flow_neighbors(topology: &DfdModel, flow: &DfdFlowModel) -> Vec<Value> {
    let nodes = topology
        .nodes
        .iter()
        .filter(|node| node.key == flow.from_id || node.key == flow.to_id)
        .map(node_value);
    let boundaries = topology
        .boundaries
        .iter()
        .filter(|boundary| flow.boundary_ids.contains(&boundary.key))
        .map(boundary_value);
    nodes.chain(boundaries).collect()
}

fn boundary_neighbors(topology: &DfdModel, boundary: &DfdBoundaryModel) -> Vec<Value> {
    topology
        .flows
        .iter()
        .filter(|flow| boundary.crossing_flow_ids.contains(&flow.key))
        .map(flow_value)
        .collect()
}

pub(super) fn security_rows(topology: &DfdModel, selection: Option<usize>) -> (Vec<Value>, usize) {
    let rows = selection
        .map(|index| dfd_security_items_for_selection(topology, index))
        .unwrap_or_default();
    let omitted = rows.len().saturating_sub(SECURITY_ROW_LIMIT);
    (
        rows.into_iter()
            .take(SECURITY_ROW_LIMIT)
            .map(security_value)
            .collect(),
        omitted,
    )
}

fn security_value(item: &DfdSecurityItem) -> Value {
    json!({
        "id": item.key,
        "kind": security_kind_label(item.kind),
        "label": bounded_text(&item.label),
        "detail": bounded_text(&item.detail),
        "evidence": bounded_text(&item.evidence),
        "targetElementIds": item.target_element_ids,
    })
}
