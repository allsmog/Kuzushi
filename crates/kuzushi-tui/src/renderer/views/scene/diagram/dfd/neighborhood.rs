use super::*;

pub(super) struct SelectedFlow<'a> {
    pub(super) flow: &'a DfdFlowModel,
    pub(super) hidden: usize,
    pub(super) kind: &'static str,
}

pub(super) fn selected_flow(diagram: &DfdDiagram) -> Option<SelectedFlow<'_>> {
    let selection = diagram
        .selection
        .or_else(|| (!diagram.model.nodes.is_empty()).then_some(0))?;
    match dfd_selected_item(&diagram.model, selection)? {
        DfdSelected::Flow(flow) => Some(SelectedFlow {
            flow,
            hidden: 0,
            kind: "selected flow",
        }),
        DfdSelected::Boundary(boundary) => boundary_flow(&diagram.model, boundary),
        DfdSelected::Node(node) => node_flow(&diagram.model, node),
    }
}

fn boundary_flow<'a>(model: &'a DfdModel, boundary: &DfdBoundaryModel) -> Option<SelectedFlow<'a>> {
    let flows = model
        .flows
        .iter()
        .filter(|flow| flow_crosses_boundary(flow, boundary))
        .collect::<Vec<_>>();
    Some(SelectedFlow {
        flow: *flows.first()?,
        hidden: flows.len().saturating_sub(1),
        kind: "boundary flow",
    })
}

fn node_flow<'a>(model: &'a DfdModel, node: &DfdNodeModel) -> Option<SelectedFlow<'a>> {
    let flows = model
        .flows
        .iter()
        .filter(|flow| flow.from_id == node.key || flow.to_id == node.key)
        .collect::<Vec<_>>();
    let flow = flows
        .iter()
        .find(|flow| flow.from_id == node.key)
        .or_else(|| flows.first())?;
    Some(SelectedFlow {
        flow,
        hidden: flows.len().saturating_sub(1),
        kind: "node neighborhood",
    })
}
