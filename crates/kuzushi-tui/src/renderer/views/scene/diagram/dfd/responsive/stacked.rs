use super::super::*;
use super::context_node_label;
use crate::renderer::fit;
use crate::ui_view_models::DfdSelected;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

mod boundary;

const MAX_ZONES: usize = 3;

pub(super) fn render(diagram: &DfdDiagram, buf: &mut Buffer, area: Rect) {
    if boundary::render_if_selected(diagram, buf, area) {
        return;
    }
    let zones = visible_zones(diagram, area);
    draw_page_label(buf, area, &zones, diagram.model.zones.len());
    let mut y = 1;
    for (position, zone_index) in zones.iter().copied().enumerate() {
        if position > 0 {
            render_connection(diagram, buf, area, zones[position - 1], zone_index, y);
            y = y.saturating_add(1);
        }
        let height = zone_height(diagram, zone_index);
        render_zone(diagram, buf, area, zone_index, y, height);
        y = y.saturating_add(height);
    }
    diagram.draw_legend(buf, area, y.min(area.height.saturating_sub(1)));
}

pub(super) fn content_height(diagram: &DfdDiagram, area: Rect) -> u16 {
    if let Some(height) = boundary::content_height_if_selected(diagram, area) {
        return height;
    }
    let zones = visible_zones(diagram, area);
    let panels = zones
        .iter()
        .map(|zone_index| zone_height(diagram, *zone_index))
        .sum::<u16>();
    let separators = zones.len().saturating_sub(1) as u16;
    (2 + panels + separators).min(area.height)
}

fn visible_zones(diagram: &DfdDiagram, area: Rect) -> Vec<usize> {
    let candidates = ordered_zone_candidates(diagram);
    let budget = area.height.saturating_sub(2);
    let mut used: u16 = 0;
    let mut visible = Vec::new();
    for zone_index in candidates {
        let separator = u16::from(!visible.is_empty());
        let required = separator + zone_height(diagram, zone_index);
        if !visible.is_empty() && used.saturating_add(required) > budget {
            break;
        }
        visible.push(zone_index);
        used = used.saturating_add(required);
        if visible.len() == MAX_ZONES {
            break;
        }
    }
    visible
}

fn ordered_zone_candidates(diagram: &DfdDiagram) -> Vec<usize> {
    let mut zones = selected_context_zones(&diagram.model, diagram.selection);
    if !zones.is_empty() {
        return zones;
    }
    for zone_index in 0..diagram.model.zones.len() {
        zones = push_unique(zones, zone_index);
    }
    zones
}

fn zone_height(diagram: &DfdDiagram, zone_index: usize) -> u16 {
    let indices = zone_node_indices(&diagram.model.nodes, &diagram.model.zones[zone_index]);
    let slice = diagram.zone_slice(&indices);
    2 + slice.node_indices.len() as u16 + u16::from(slice.note.is_some())
}

fn render_zone(
    diagram: &DfdDiagram,
    buf: &mut Buffer,
    area: Rect,
    zone_index: usize,
    y: u16,
    height: u16,
) {
    let zone = &diagram.model.zones[zone_index];
    let indices = zone_node_indices(&diagram.model.nodes, zone);
    let slice = diagram.zone_slice(&indices);
    let lines = node_lines(diagram, &slice, area.width.saturating_sub(2) as usize);
    let title = format!(
        " {} · {}/{} ",
        zone.to_uppercase(),
        slice.node_indices.len(),
        indices.len()
    );
    let rect = Rect::new(area.x, area.y + y, area.width, height);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(diagram_style(zone_border(diagram, &slice)))
        .title(Span::styled(title, diagram_style(diagram_subtle())));
    Paragraph::new(lines).block(block).render(rect, buf);
}

fn node_lines(diagram: &DfdDiagram, slice: &ZoneSlice, width: usize) -> Vec<Line<'static>> {
    let mut lines = slice
        .node_indices
        .iter()
        .map(|index| node_line(diagram, *index, width))
        .collect::<Vec<_>>();
    if let Some(note) = &slice.note {
        lines.push(Line::styled(
            fit(note, width),
            diagram_style(diagram_muted()),
        ));
    }
    lines
}

fn node_line(diagram: &DfdDiagram, node_index: usize, width: usize) -> Line<'static> {
    let node = &diagram.model.nodes[node_index];
    let selected = diagram.selection == Some(node_index);
    let marker = if selected { "› " } else { "· " };
    let count = security_context_count(&diagram.model, &node.key);
    let text = fit(
        &format!("{marker}{}", context_node_label(node, count)),
        width,
    );
    let color = if selected {
        selection_color()
    } else {
        node_color(node.kind)
    };
    Line::styled(text, diagram_style(color))
}

fn zone_border(diagram: &DfdDiagram, slice: &ZoneSlice) -> Color {
    if diagram
        .selection
        .is_some_and(|selected| slice.node_indices.contains(&selected))
    {
        return selection_color();
    }
    diagram_subtle()
}

fn render_connection(
    diagram: &DfdDiagram,
    buf: &mut Buffer,
    area: Rect,
    first_zone: usize,
    second_zone: usize,
    y: u16,
) {
    let flows = relevant_flows_between(diagram, first_zone, second_zone);
    let label = connection_label(&flows);
    text(
        buf,
        area,
        2,
        y,
        &fit(&label, area.width.saturating_sub(3) as usize),
        diagram_muted(),
    );
}

fn relevant_flows_between<'a>(
    diagram: &'a DfdDiagram,
    first_zone: usize,
    second_zone: usize,
) -> Vec<&'a DfdFlowModel> {
    diagram
        .model
        .flows
        .iter()
        .filter(|flow| flow_connects_zones(&diagram.model, flow, first_zone, second_zone))
        .filter(|flow| selected_item_owns_flow(diagram, flow))
        .collect()
}

fn flow_connects_zones(
    model: &DfdModel,
    flow: &DfdFlowModel,
    first_zone: usize,
    second_zone: usize,
) -> bool {
    let from = zone_index_for_node(model, &flow.from_id);
    let to = zone_index_for_node(model, &flow.to_id);
    matches!(
        (from, to),
        (Some(a), Some(b))
            if (a == first_zone && b == second_zone)
                || (a == second_zone && b == first_zone)
    )
}

fn selected_item_owns_flow(diagram: &DfdDiagram, flow: &DfdFlowModel) -> bool {
    match diagram
        .selection
        .and_then(|index| dfd_selected_item(&diagram.model, index))
    {
        Some(DfdSelected::Node(node)) => flow.from_id == node.key || flow.to_id == node.key,
        Some(DfdSelected::Flow(selected)) => selected.key == flow.key,
        Some(DfdSelected::Boundary(boundary)) => flow_crosses_boundary(flow, boundary),
        None => false,
    }
}

fn connection_label(flows: &[&DfdFlowModel]) -> String {
    let Some(flow) = flows.first() else {
        return "│".to_string();
    };
    let crossing = if flow.crosses { " · boundary" } else { "" };
    let more = if flows.len() > 1 {
        format!(" · +{} other flows", flows.len() - 1)
    } else {
        String::new()
    };
    format!("▼ {}{crossing}{more}", nonempty(&flow.label))
}

fn draw_page_label(buf: &mut Buffer, area: Rect, zones: &[usize], total: usize) {
    let shown = zones
        .iter()
        .map(|index| (index + 1).to_string())
        .collect::<Vec<_>>()
        .join(",");
    let label = format!("showing zones {shown} of {total} · j/k follows selection");
    text(
        buf,
        area,
        1,
        0,
        &fit(&label, area.width.saturating_sub(1) as usize),
        diagram_muted(),
    );
}
