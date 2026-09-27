use super::super::super::*;
use crate::renderer::fit;
use crate::ui_view_models::DfdSelected;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

const MAX_BRANCHES: usize = 5;
const SOURCE_Y: u16 = 1;
const TARGET_Y: u16 = 5;
const NODE_H: u16 = 3;

pub(super) fn render_if_selected(diagram: &DfdDiagram, buf: &mut Buffer, area: Rect) -> bool {
    let Some(boundary) = selected_boundary(diagram) else {
        return false;
    };
    let flows = boundary_flows(diagram, boundary);
    if flows.is_empty() {
        return false;
    }
    draw_context_label(buf, area, flows.len());
    if common_source(&flows).is_some() {
        render_fan_out(diagram, buf, area, &flows);
    } else {
        render_flow_pair(diagram, buf, area, &flows);
    }
    true
}

pub(super) fn content_height_if_selected(diagram: &DfdDiagram, area: Rect) -> Option<u16> {
    let boundary = selected_boundary(diagram)?;
    let flows = boundary_flows(diagram, boundary);
    if flows.is_empty() {
        return None;
    }
    let height = if common_source(&flows).is_some() {
        fan_out_content_height(area.height, flows.len())
    } else {
        flow_pair_content_height(flows.len())
    };
    Some(height.min(area.height))
}

fn selected_boundary(diagram: &DfdDiagram) -> Option<&DfdBoundaryModel> {
    match diagram
        .selection
        .and_then(|index| dfd_selected_item(&diagram.model, index))
    {
        Some(DfdSelected::Boundary(boundary)) => Some(boundary),
        _ => None,
    }
}

fn boundary_flows<'a>(
    diagram: &'a DfdDiagram,
    boundary: &DfdBoundaryModel,
) -> Vec<&'a DfdFlowModel> {
    diagram
        .model
        .flows
        .iter()
        .filter(|flow| flow_crosses_boundary(flow, boundary))
        .collect()
}

fn common_source<'a>(flows: &'a [&DfdFlowModel]) -> Option<&'a str> {
    let source = flows.first()?.from_id.as_str();
    flows
        .iter()
        .all(|flow| flow.from_id == source)
        .then_some(source)
}

fn render_fan_out(diagram: &DfdDiagram, buf: &mut Buffer, area: Rect, flows: &[&DfdFlowModel]) {
    let visible = branch_capacity(area.height, flows.len());
    draw_node(
        diagram,
        buf,
        area,
        &flows[0].from_id,
        None,
        Rect::new(1, SOURCE_Y, area.width.saturating_sub(2), NODE_H),
    );
    draw_branch_trunk(buf, area, visible);
    for (index, flow) in flows.iter().take(visible).enumerate() {
        draw_target_branch(diagram, buf, area, flow, index, visible);
    }
    let legend_y = fan_out_legend_y(visible, flows.len());
    draw_hidden_count(buf, area, legend_y.saturating_sub(1), flows.len(), visible);
    diagram.draw_legend(buf, area, legend_y);
}

fn draw_branch_trunk(buf: &mut Buffer, area: Rect, visible: usize) {
    let trunk_x = 3;
    let last_y = target_center_y(visible.saturating_sub(1));
    vrun(
        buf,
        area,
        trunk_x,
        SOURCE_Y + NODE_H,
        last_y + 1,
        selection_color(),
    );
}

fn draw_target_branch(
    diagram: &DfdDiagram,
    buf: &mut Buffer,
    area: Rect,
    flow: &DfdFlowModel,
    index: usize,
    visible: usize,
) {
    let target_x = 9;
    let y = TARGET_Y + index as u16 * NODE_H;
    let center_y = y + NODE_H / 2;
    connector_h(
        buf,
        area,
        (3, center_y),
        (target_x, center_y),
        selection_color(),
    );
    put(
        buf,
        area,
        3,
        center_y,
        if index + 1 == visible { "└" } else { "├" },
        selection_color(),
    );
    draw_node(
        diagram,
        buf,
        area,
        &flow.to_id,
        Some(&flow.key),
        Rect::new(target_x, y, area.width.saturating_sub(target_x + 1), NODE_H),
    );
}

fn render_flow_pair(diagram: &DfdDiagram, buf: &mut Buffer, area: Rect, flows: &[&DfdFlowModel]) {
    let flow = flows[0];
    let width = area.width.saturating_sub(2);
    draw_node(
        diagram,
        buf,
        area,
        &flow.from_id,
        None,
        Rect::new(1, SOURCE_Y, width, NODE_H),
    );
    draw_vertical_flow(buf, area, flow, SOURCE_Y + NODE_H, TARGET_Y);
    draw_node(
        diagram,
        buf,
        area,
        &flow.to_id,
        None,
        Rect::new(1, TARGET_Y, width, NODE_H),
    );
    draw_hidden_count(buf, area, 8, flows.len(), 1);
    diagram.draw_legend(buf, area, flow_pair_content_height(flows.len()) - 1);
}

fn draw_vertical_flow(buf: &mut Buffer, area: Rect, flow: &DfdFlowModel, from_y: u16, to_y: u16) {
    let connector_x = area.width.saturating_sub(4).max(2);
    connector_v(
        buf,
        area,
        (connector_x, from_y),
        (connector_x, to_y),
        selection_color(),
    );
    text(
        buf,
        area,
        2,
        from_y,
        &fit(&flow.key, connector_x.saturating_sub(3) as usize),
        selection_color(),
    );
}

fn draw_node(
    diagram: &DfdDiagram,
    buf: &mut Buffer,
    area: Rect,
    node_id: &str,
    flow_id: Option<&str>,
    rect: Rect,
) {
    let label = crate::renderer::shared::text::fit_words(
        &node_graph_label(diagram, node_id, flow_id),
        rect.width.saturating_sub(3) as usize,
    );
    boxed(
        buf,
        area,
        rect.x,
        rect.y,
        rect.width,
        rect.height,
        &label,
        selection_color(),
        selection_color(),
    );
}

fn node_graph_label(diagram: &DfdDiagram, node_id: &str, flow_id: Option<&str>) -> String {
    let Some(node) = diagram.model.nodes.iter().find(|node| node.key == node_id) else {
        return node_id.to_string();
    };
    let prefix = flow_id.map_or(String::new(), |id| format!("{id} · "));
    format!(
        "{prefix}{} · {}",
        node_label(node),
        node.zone.to_uppercase()
    )
}

fn branch_capacity(height: u16, total: usize) -> usize {
    let available = height.saturating_sub(7) / NODE_H;
    total.min(MAX_BRANCHES).min(available.max(1) as usize)
}

fn target_center_y(index: usize) -> u16 {
    TARGET_Y + index as u16 * NODE_H + NODE_H / 2
}

fn fan_out_legend_y(visible: usize, total: usize) -> u16 {
    let after_targets = TARGET_Y + visible as u16 * NODE_H;
    after_targets + u16::from(total > visible)
}

fn fan_out_content_height(height: u16, total: usize) -> u16 {
    fan_out_legend_y(branch_capacity(height, total), total) + 1
}

fn flow_pair_content_height(total: usize) -> u16 {
    9 + u16::from(total > 1)
}

fn draw_hidden_count(buf: &mut Buffer, area: Rect, y: u16, total: usize, visible: usize) {
    let hidden = total.saturating_sub(visible);
    if hidden > 0 {
        text(
            buf,
            area,
            2,
            y,
            &format!("+{hidden} more crossing flows"),
            diagram_muted(),
        );
    }
}

fn draw_context_label(buf: &mut Buffer, area: Rect, flow_count: usize) {
    let value = format!("selected boundary · {flow_count} crossing flows");
    text(
        buf,
        area,
        1,
        0,
        &fit(&value, area.width.saturating_sub(1) as usize),
        diagram_muted(),
    );
}
