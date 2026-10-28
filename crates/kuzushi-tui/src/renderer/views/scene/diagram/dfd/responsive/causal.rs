use super::super::neighborhood::{selected_flow, SelectedFlow};
use super::super::*;
use super::{context_name, context_node_label};
use crate::renderer::fit;
use crate::ui_view_models::DfdSelected;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

const NODE_H: u16 = 3;
const NORMAL_MIN_HEIGHT: u16 = 11;

pub(super) fn render(diagram: &DfdDiagram, buf: &mut Buffer, area: Rect) {
    if let Some(selected) = selected_flow(diagram) {
        render_flow_graph(diagram, buf, area, &selected);
    } else {
        render_single_node(diagram, buf, area);
    }
}

pub(super) fn content_height(diagram: &DfdDiagram, area: Rect) -> u16 {
    if selected_flow(diagram).is_none() {
        return 7.min(area.height);
    }
    if area.height < NORMAL_MIN_HEIGHT {
        return 8.min(area.height);
    }
    let hidden = selected_flow(diagram).is_some_and(|selected| selected.hidden > 0);
    (10 + u16::from(hidden)).min(area.height)
}

fn render_flow_graph(
    diagram: &DfdDiagram,
    buf: &mut Buffer,
    area: Rect,
    selected: &SelectedFlow<'_>,
) {
    if area.height < NORMAL_MIN_HEIGHT {
        render_compact_flow_graph(diagram, buf, area, selected);
        return;
    }
    draw_graph_title(buf, area, selected);
    draw_node_box(diagram, buf, area, &selected.flow.from_id, 1);
    draw_flow_connector(buf, area, selected.flow, 4, 6);
    draw_node_box(diagram, buf, area, &selected.flow.to_id, 6);
    let legend_y = 10 + u16::from(selected.hidden > 0) - 1;
    draw_hidden_flows(buf, area, 9, selected.hidden);
    diagram.draw_legend(buf, area, legend_y);
}

fn render_compact_flow_graph(
    diagram: &DfdDiagram,
    buf: &mut Buffer,
    area: Rect,
    selected: &SelectedFlow<'_>,
) {
    draw_node_box(diagram, buf, area, &selected.flow.from_id, 0);
    put(buf, area, area.width / 2, 3, "▼", selection_color());
    draw_node_box(diagram, buf, area, &selected.flow.to_id, 4);
    diagram.draw_legend(buf, area, 7);
}

fn render_single_node(diagram: &DfdDiagram, buf: &mut Buffer, area: Rect) {
    text(
        buf,
        area,
        1,
        0,
        "causal diagram · selected node",
        diagram_muted(),
    );
    let Some(node) = selected_node(diagram) else {
        text(buf, area, 2, 2, "no DFD node selected", diagram_muted());
        return;
    };
    draw_node_box(diagram, buf, area, &node.key, 1);
    text(buf, area, 2, 4, "no recorded flows", diagram_muted());
    diagram.draw_legend(buf, area, 5);
}

fn draw_graph_title(buf: &mut Buffer, area: Rect, selected: &SelectedFlow<'_>) {
    let value = format!("causal diagram · {} · {}", selected.kind, selected.flow.key);
    text(
        buf,
        area,
        1,
        0,
        &fit(&value, area.width.saturating_sub(1) as usize),
        diagram_muted(),
    );
}

fn draw_node_box(diagram: &DfdDiagram, buf: &mut Buffer, area: Rect, node_id: &str, y: u16) {
    let label = crate::renderer::shared::text::fit_words(
        &graph_node_label(diagram, node_id),
        area.width.saturating_sub(3) as usize,
    );
    boxed(
        buf,
        area,
        0,
        y,
        area.width,
        NODE_H,
        &label,
        selection_color(),
        selection_color(),
    );
}

fn graph_node_label(diagram: &DfdDiagram, node_id: &str) -> String {
    let Some(node) = diagram.model.nodes.iter().find(|node| node.key == node_id) else {
        return node_id.to_string();
    };
    let count = security_context_count(&diagram.model, &node.key);
    let name = if selected_node(diagram).is_some_and(|selected| selected.key == node.key) {
        format!("◆ {}", context_name(&node.name, count))
    } else {
        context_node_label(node, count)
    };
    format!("{name} · {}", node.zone.to_uppercase())
}

fn draw_flow_connector(buf: &mut Buffer, area: Rect, flow: &DfdFlowModel, from_y: u16, to_y: u16) {
    let connector_x = area.width.saturating_sub(4).max(2);
    connector_v(
        buf,
        area,
        (connector_x, from_y),
        (connector_x, to_y),
        selection_color(),
    );
    let label = format!("{} · {}", nonempty(&flow.label), flow.key);
    text(
        buf,
        area,
        2,
        from_y,
        &fit(&label, connector_x.saturating_sub(3) as usize),
        selection_color(),
    );
}

fn draw_hidden_flows(buf: &mut Buffer, area: Rect, y: u16, hidden: usize) {
    if hidden > 0 {
        text(
            buf,
            area,
            2,
            y,
            &format!("+{hidden} adjacent flows"),
            diagram_muted(),
        );
    }
}

fn selected_node(diagram: &DfdDiagram) -> Option<&DfdNodeModel> {
    match selected_item(diagram)? {
        DfdSelected::Node(node) => Some(node),
        _ => None,
    }
}

fn selected_item(diagram: &DfdDiagram) -> Option<DfdSelected<'_>> {
    let selection = diagram
        .selection
        .or_else(|| (!diagram.model.nodes.is_empty()).then_some(0));
    selection.and_then(|index| dfd_selected_item(&diagram.model, index))
}
