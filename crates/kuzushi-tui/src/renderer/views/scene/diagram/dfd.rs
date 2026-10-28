//! Data-flow diagram: one trust-zone panel per zone (sized to the width),
//! rounded node boxes stacked inside, joined by crisp orthogonal connectors
//! routed between node anchors. Boundary-crossing flows are amber + arrowed;
//! in-zone flows are muted. Driven by the real threat-model `DfdModel`.
//!
//! Layout is computed first (pure placements + per-zone paging), then flows
//! are drawn UNDER the node boxes: connectors never cut through a box
//! interior. `j`/`k` cycle an inspector cursor over nodes then flows; the
//! selected item is highlighted and described in the strip under the legend.

use super::*;
use crate::theme;
use crate::ui_view_models::{
    dfd_security_items_for_selection, dfd_selectable_count, dfd_selected_item,
    dfd_selection_for_key, DfdBoundaryModel, DfdFlowModel, DfdKind, DfdLinkState, DfdModel,
    DfdNodeModel, DfdSecurityKind, DfdSelected,
};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};
use std::collections::HashMap;

mod detail_reading;
mod focus;
use detail_reading::detail_scroll_bounds;
pub(crate) use detail_reading::DfdDetailScroll;
mod neighborhood;
mod overview;
pub(crate) use overview::summary_reading_rows;
mod responsive;

const GAP: u16 = 2;
const PREFERRED_ZONE_W: u16 = 30;
const MIN_ZONE_W: u16 = 22;
const MAX_NODE_W: u16 = 40;
const NODE_H: u16 = 3;
const NODE_VGAP: u16 = 1;
const DETAIL_GAP: u16 = 1;
/// Nodes shown per zone page; denser zones page (anchored to the selection)
/// instead of silently dropping topology.
const ZONE_PAGE_SIZE: usize = 4;

pub(crate) struct DfdDiagram {
    pub model: DfdModel,
    /// Cursor over the flattened nodes, flows, and boundaries;
    /// `None` renders the plain diagram without highlight or inspector.
    pub selection: Option<usize>,
    /// Requested first row in the wrapped inspector panel.
    pub detail_scroll: usize,
    /// Replace the topology with the selected element's local security graph.
    pub focused: bool,
    /// Cursor over the security annotations in the focused graph.
    pub context_selection: usize,
}

pub(crate) struct DfdSummary {
    pub model: DfdModel,
    pub component_selection: usize,
    pub scroll: i32,
}

impl Widget for DfdSummary {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if let Some(hint) = &self.model.empty_hint {
            let (hint, guidance) = dfd_empty_copy(area.width, hint);
            render_empty_state_panel(
                buf,
                area,
                "no system summary",
                hint,
                &[("threat-model:build", guidance)],
            );
            return;
        }
        overview::render(
            buf,
            area,
            &self.model,
            self.component_selection,
            self.scroll,
        );
    }
}

struct Anchor {
    col: usize,
    cx: u16,
    top: u16,
    bottom: u16,
    left: u16,
    right: u16,
}

impl Anchor {
    fn mid(&self) -> u16 {
        (self.top + self.bottom) / 2
    }
}

/// One visible node's computed position (pure layout output).
struct NodePlacement {
    node_index: usize,
    zi: usize,
    cx: u16,
    left: u16,
    y: u16,
}

struct PageNote {
    x: u16,
    y: u16,
    text: String,
}

struct ZoneSlice {
    node_indices: Vec<usize>,
    note: Option<String>,
}

struct DetailContent {
    kind: &'static str,
    lines: Vec<Line<'static>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DfdRegions {
    graph: Option<Rect>,
    detail: Option<Rect>,
}

impl Widget for DfdDiagram {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if self.render_special_state(area, buf) {
            return;
        }
        self.render_topology(area, buf);
    }
}

impl DfdDiagram {
    fn render_special_state(&self, area: Rect, buf: &mut Buffer) -> bool {
        if let Some(hint) = &self.model.empty_hint {
            let (hint, guidance) = dfd_empty_copy(area.width, hint);
            render_empty_state_panel(
                buf,
                area,
                "no data-flow diagram",
                hint,
                &[("threat-model:build", guidance)],
            );
            return true;
        }
        if self.focused {
            focus::render(
                buf,
                area,
                &self.model,
                self.selection.unwrap_or_default(),
                self.context_selection,
            );
            return true;
        }
        false
    }

    fn render_topology(&self, area: Rect, buf: &mut Buffer) {
        let layout = responsive::topology_layout(area);
        if self.selection.is_none() {
            self.draw_topology_graph(buf, area, layout);
            return;
        }
        let regions = dfd_regions(area, layout);
        self.render_topology_regions(area, buf, layout, regions);
    }

    fn render_topology_regions(
        &self,
        area: Rect,
        buf: &mut Buffer,
        layout: responsive::DfdTopologyLayout,
        regions: DfdRegions,
    ) {
        if let Some(graph_area) = regions.graph {
            self.draw_topology_graph(buf, graph_area, layout);
        }
        if let Some(detail_area) = positioned_detail_area(self, area, layout, regions) {
            self.draw_detail_panel(
                buf,
                detail_area,
                layout == responsive::DfdTopologyLayout::DetailOnly,
            );
        } else {
            text(
                buf,
                area,
                1,
                0,
                &format!(
                    "{:<width$}",
                    "Resize to read selected details",
                    width = area.width.saturating_sub(1) as usize
                ),
                diagram_muted(),
            );
        }
    }

    fn draw_topology_graph(
        &self,
        buf: &mut Buffer,
        area: Rect,
        layout: responsive::DfdTopologyLayout,
    ) {
        match layout {
            responsive::DfdTopologyLayout::WideLanes => self.draw_graph(buf, area),
            responsive::DfdTopologyLayout::StackedZones => {
                responsive::render_stacked(self, buf, area)
            }
            responsive::DfdTopologyLayout::CausalPath => responsive::render_causal(self, buf, area),
            responsive::DfdTopologyLayout::DetailOnly => {}
        }
    }
}

fn positioned_detail_area(
    diagram: &DfdDiagram,
    area: Rect,
    layout: responsive::DfdTopologyLayout,
    regions: DfdRegions,
) -> Option<Rect> {
    let mut detail = regions.detail?;
    let Some(graph) = regions.graph else {
        return Some(detail);
    };
    let Some(content_height) = responsive::compact_content_height(diagram, layout, graph) else {
        return Some(detail);
    };
    detail.y = detail
        .y
        .min(area.y + content_height.saturating_add(DETAIL_GAP));
    Some(detail)
}

fn dfd_regions(area: Rect, layout: responsive::DfdTopologyLayout) -> DfdRegions {
    match layout {
        responsive::DfdTopologyLayout::WideLanes => wide_dfd_regions(area),
        responsive::DfdTopologyLayout::StackedZones => stacked_dfd_regions(area),
        responsive::DfdTopologyLayout::CausalPath => causal_dfd_regions(area),
        responsive::DfdTopologyLayout::DetailOnly => DfdRegions {
            graph: None,
            detail: Some(area),
        },
    }
}

fn wide_dfd_regions(area: Rect) -> DfdRegions {
    let detail_w = (area.width / 3).clamp(34, 46);
    let graph_w = area.width.saturating_sub(detail_w + DETAIL_GAP);
    let graph = Rect {
        width: graph_w,
        ..area
    };
    let detail = Rect {
        x: area.x + graph_w + DETAIL_GAP,
        width: detail_w,
        ..area
    };
    DfdRegions {
        graph: Some(graph),
        detail: Some(detail),
    }
}

fn stacked_dfd_regions(area: Rect) -> DfdRegions {
    let detail_h = (area.height / 4).clamp(5, 8);
    let graph_h = area.height.saturating_sub(detail_h + DETAIL_GAP);
    let graph = Rect {
        height: graph_h,
        ..area
    };
    let detail = Rect {
        y: area.y + graph_h + DETAIL_GAP,
        height: detail_h,
        ..area
    };
    DfdRegions {
        graph: Some(graph),
        detail: Some(detail),
    }
}

fn causal_dfd_regions(area: Rect) -> DfdRegions {
    if area.height < 14 {
        return DfdRegions {
            graph: Some(area),
            detail: None,
        };
    }
    let detail_h = (area.height / 4).clamp(5, 7);
    let graph_h = area.height.saturating_sub(detail_h + DETAIL_GAP);
    DfdRegions {
        graph: Some(Rect {
            height: graph_h,
            ..area
        }),
        detail: Some(Rect {
            y: area.y + graph_h + DETAIL_GAP,
            height: detail_h,
            ..area
        }),
    }
}

impl DfdDiagram {
    fn draw_graph(&self, buf: &mut Buffer, area: Rect) {
        let visible_zones = visible_zone_indices(&self.model, self.selection, area.width);
        let zone_count = visible_zones.len().max(1) as u16;
        let zone_w = (area.width.saturating_sub((zone_count - 1) * GAP)) / zone_count;
        if zone_w < 8 || area.height < 7 {
            text(
                buf,
                area,
                1,
                0,
                "diagram compacted; use the detail panel",
                diagram_muted(),
            );
            return;
        }
        let zone_h = self.content_zone_height(&visible_zones, area.height.saturating_sub(2));
        let zx = |i: u16| i * (zone_w + GAP);

        draw_zone_page_label(buf, area, &visible_zones, self.model.zones.len());
        self.draw_zone_panels(buf, area, zone_w, zone_h, &visible_zones, &zx);
        let nbw = zone_w.saturating_sub(2).clamp(8, MAX_NODE_W);
        let (placements, notes) = self.layout_nodes(zone_w, zone_h, nbw, &visible_zones, &zx);
        let anchors = anchor_map(&self.model, &placements, nbw);
        self.draw_flows(buf, area, &anchors);
        self.draw_node_boxes(buf, area, &placements, nbw);
        draw_page_notes(buf, area, &notes);
        self.draw_legend(buf, area, zone_h + 1);
    }

    fn content_zone_height(&self, zones: &[usize], maximum: u16) -> u16 {
        zones
            .iter()
            .map(|zone_index| {
                let indices = zone_node_indices(&self.model.nodes, &self.model.zones[*zone_index]);
                compact_zone_height(&self.zone_slice(&indices))
            })
            .max()
            .unwrap_or(5)
            .clamp(5, maximum.max(5))
    }
}

fn compact_zone_height(slice: &ZoneSlice) -> u16 {
    let gap = u16::from(slice.node_indices.len() > 1) * NODE_VGAP;
    2 + node_span(slice.node_indices.len(), gap) + u16::from(slice.note.is_some())
}

fn dfd_empty_copy<'a>(width: u16, hint: &'a str) -> (&'a str, &'static str) {
    if width < 60 {
        return (
            "no threat model yet — run `threat-model:build`",
            "map trust zones",
        );
    }
    (hint, "map trust zones and flows")
}

impl DfdDiagram {
    /// One titled trust-zone panel per zone, laid out across the width.
    fn draw_zone_panels(
        &self,
        buf: &mut Buffer,
        area: Rect,
        zone_w: u16,
        zone_h: u16,
        visible_zones: &[usize],
        zx: &impl Fn(u16) -> u16,
    ) {
        for (column, &zone_index) in visible_zones.iter().enumerate() {
            let zone = &self.model.zones[zone_index];
            let title = zone_panel_title(zone, zone_w);
            panel(
                buf,
                area,
                zx(column as u16),
                1,
                zone_w,
                zone_h,
                &title,
                diagram_subtle(),
            );
        }
    }

    /// Pure layout: which nodes are visible (per-zone paging anchored to the
    /// selection) and where each box goes. No drawing.
    fn layout_nodes(
        &self,
        zone_w: u16,
        zone_h: u16,
        nbw: u16,
        visible_zones: &[usize],
        zx: &impl Fn(u16) -> u16,
    ) -> (Vec<NodePlacement>, Vec<PageNote>) {
        let mut placements = Vec::new();
        let mut notes = Vec::new();
        for (column, &zi) in visible_zones.iter().enumerate() {
            let zone = &self.model.zones[zi];
            let cx = zx(column as u16) + zone_w / 2;
            let left = cx.saturating_sub(nbw / 2);
            self.layout_zone(zi, zone, cx, left, zone_h, &mut placements, &mut notes);
        }
        (placements, notes)
    }

    fn layout_zone(
        &self,
        zi: usize,
        zone: &str,
        cx: u16,
        left: u16,
        zone_h: u16,
        placements: &mut Vec<NodePlacement>,
        notes: &mut Vec<PageNote>,
    ) {
        let indices: Vec<usize> = zone_node_indices(&self.model.nodes, zone);
        let visible = self.zone_slice(&indices);
        let note_rows = u16::from(visible.note.is_some());
        let available = zone_h.saturating_sub(2 + note_rows);
        let preferred_span = node_span(visible.node_indices.len(), NODE_VGAP);
        let gap = if preferred_span <= available {
            NODE_VGAP
        } else {
            node_vertical_gap(available, visible.node_indices.len())
        };
        let mut y = 2;
        for &node_index in &visible.node_indices {
            placements.push(NodePlacement {
                node_index,
                zi,
                cx,
                left,
                y,
            });
            y += NODE_H + gap;
        }
        if let Some(note) = visible.note {
            notes.push(PageNote {
                x: left.saturating_add(1),
                y: zone_h.saturating_sub(1),
                text: note,
            });
        }
    }

    fn zone_slice(&self, indices: &[usize]) -> ZoneSlice {
        let endpoints = self.selected_endpoint_indices(indices);
        if endpoints.len() == 2 && endpoints_on_different_pages(indices, &endpoints) {
            return endpoint_zone_slice(indices, &endpoints);
        }
        let selected = endpoints
            .first()
            .copied()
            .or_else(|| self.selected_node(indices));
        let page = selected
            .and_then(|index| indices.iter().position(|candidate| *candidate == index))
            .map_or(0, |position| position / ZONE_PAGE_SIZE);
        ordinary_zone_slice(indices, page)
    }

    fn selected_node(&self, indices: &[usize]) -> Option<usize> {
        self.element_selection()
            .filter(|selected| indices.contains(selected))
    }

    fn selected_endpoint_indices(&self, indices: &[usize]) -> Vec<usize> {
        let Some(flow) = self.selected_flow() else {
            return Vec::new();
        };
        [&flow.from_id, &flow.to_id]
            .into_iter()
            .filter_map(|id| node_index_by_id(&self.model.nodes, id))
            .filter(|index| indices.contains(index))
            .fold(Vec::new(), |mut endpoints, index| {
                if !endpoints.contains(&index) {
                    endpoints.push(index);
                }
                endpoints
            })
    }

    fn selected_flow(&self) -> Option<&DfdFlowModel> {
        self.selection?;
        neighborhood::selected_flow(self).map(|selected| selected.flow)
    }

    /// Route a connector for every flow whose endpoints both have anchors;
    /// the selected flow is drawn last, highlighted, so its glyphs win.
    fn draw_flows(&self, buf: &mut Buffer, area: Rect, anchors: &HashMap<String, Anchor>) {
        let selected = self.selected_flow_index();
        for (index, flow) in self.model.flows.iter().enumerate() {
            if selected != Some(index) {
                draw_one_flow(buf, area, anchors, flow, flow_color(flow.crosses));
            }
        }
        if let Some(flow) = selected.and_then(|index| self.model.flows.get(index)) {
            draw_one_flow(buf, area, anchors, flow, selection_color());
        }
    }

    fn selected_flow_index(&self) -> Option<usize> {
        self.element_selection()
            .and_then(|selected| selected.checked_sub(self.model.nodes.len()))
    }

    fn element_selection(&self) -> Option<usize> {
        self.selection
    }

    /// Node boxes draw AFTER the flows and blank their interiors first, so
    /// connectors route under boxes instead of cutting through them.
    fn draw_node_boxes(
        &self,
        buf: &mut Buffer,
        area: Rect,
        placements: &[NodePlacement],
        nbw: u16,
    ) {
        for placement in placements {
            let node = &self.model.nodes[placement.node_index];
            let selected = self.element_selection() == Some(placement.node_index);
            let context_count = security_context_count(&self.model, &node.key);
            draw_node_box(buf, area, node, placement, nbw, context_count, selected);
        }
    }

    /// Node/flow/crossing and selection counts below the zone panels.
    fn draw_legend(&self, buf: &mut Buffer, area: Rect, legend_y: u16) {
        let total = dfd_selectable_count(&self.model);
        let legend = legend_text(&self.model, self.selection, total, area.width);
        text(
            buf,
            area,
            legend_indent(area.width),
            legend_y,
            &legend,
            diagram_primary(),
        );
    }

    fn draw_detail_panel(&self, buf: &mut Buffer, area: Rect, show_resize_hint: bool) {
        if area.height < 3 {
            return self.draw_borderless_detail(buf, area);
        }
        let detail = self.panel_detail_content(area, show_resize_hint);
        let render_area = compact_detail_area(area, detail.lines.len());
        let viewport = render_area.height.saturating_sub(2) as usize;
        let max_scroll = detail_scroll_bounds(detail.lines.len(), viewport).max_offset;
        let scroll = self.detail_scroll.min(max_scroll);
        let total = dfd_selectable_count(&self.model);
        let selected = selected_position(self.selection, total);
        let title = detail_panel_title(detail.kind, selected, total, scroll, max_scroll);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(diagram_style(diagram_subtle()))
            .title(Span::styled(title, diagram_style(selection_color())));
        Paragraph::new(detail.lines)
            .block(block)
            .scroll((scroll.min(u16::MAX as usize) as u16, 0))
            .render(render_area, buf);
    }

    fn draw_borderless_detail(&self, buf: &mut Buffer, area: Rect) {
        let detail = selected_detail_content(&self.model, self.selection, area.width as usize);
        let viewport = area.height as usize;
        let scroll = self
            .detail_scroll
            .min(detail.lines.len().saturating_sub(viewport));
        Paragraph::new(detail.lines)
            .scroll((scroll.min(u16::MAX as usize) as u16, 0))
            .render(area, buf);
    }
}

fn prepend_resize_hint(lines: &mut Vec<Line<'static>>, width: usize, show: bool) {
    if !show {
        return;
    }
    let hint_lines =
        crate::renderer::shared::text::wrap_text("resize to see topology", width.max(1));
    for hint in hint_lines.into_iter().rev() {
        lines.insert(0, Line::styled(hint, diagram_muted()));
    }
}

fn compact_detail_area(area: Rect, line_count: usize) -> Rect {
    if area.height == 0 {
        return area;
    }
    let desired = line_count.saturating_add(2).min(u16::MAX as usize) as u16;
    Rect {
        height: desired.max(3).min(area.height),
        ..area
    }
}

fn legend_text(model: &DfdModel, selection: Option<usize>, total: usize, width: u16) -> String {
    if model.review_only {
        return "PARTIAL · artifact review only".into();
    }
    complete_legend_text(model, selection, total, width)
}

fn complete_legend_text(
    model: &DfdModel,
    selection: Option<usize>,
    total: usize,
    width: u16,
) -> String {
    if width < 24 {
        return minimal_legend_text(model, selection, total);
    }
    if width < 40 {
        return tiny_legend_text(model, selection, total);
    }
    if width < 70 {
        return compact_legend_text(model, selection, total);
    }
    full_legend_text(model, selection, total)
}

fn full_legend_text(model: &DfdModel, selection: Option<usize>, total: usize) -> String {
    let base = format!(
        "{} nodes · {} flows · {} boundaries",
        model.nodes.len(),
        model.flows.len(),
        model.boundaries.len(),
    );
    let selected = selection.map_or(base.clone(), |index| {
        format!(
            "{base} · selected {}/{total}",
            selected_position(Some(index), total)
        )
    });
    let context = if model.link_state == DfdLinkState::LegacyNeedsRebuild {
        "context links unverified".to_string()
    } else {
        format!("ctx {}", model.security_context.len())
    };
    format!("{selected} · {context}")
}

fn compact_legend_text(model: &DfdModel, selection: Option<usize>, total: usize) -> String {
    format!(
        "{}N · {}F · {}B · {}/{} · {}",
        model.nodes.len(),
        model.flows.len(),
        model.boundaries.len(),
        selected_position(selection, total),
        total,
        compact_context_label(model),
    )
}

fn tiny_legend_text(model: &DfdModel, selection: Option<usize>, total: usize) -> String {
    format!(
        "{}/{} {}N {}F {}B {}",
        selected_position(selection, total),
        total,
        model.nodes.len(),
        model.flows.len(),
        model.boundaries.len(),
        tiny_context_label(model),
    )
}

fn minimal_legend_text(model: &DfdModel, selection: Option<usize>, total: usize) -> String {
    format!(
        "{}/{} N{}F{}B{}",
        selected_position(selection, total),
        total,
        model.nodes.len(),
        model.flows.len(),
        model.boundaries.len(),
    )
}

fn compact_context_label(model: &DfdModel) -> String {
    if model.link_state == DfdLinkState::LegacyNeedsRebuild {
        "unlinked".to_string()
    } else {
        format!("ctx{}", model.security_context.len())
    }
}

fn tiny_context_label(model: &DfdModel) -> String {
    if model.link_state == DfdLinkState::LegacyNeedsRebuild {
        "U".to_string()
    } else {
        format!("C{}", model.security_context.len())
    }
}

fn legend_indent(width: u16) -> u16 {
    if width < 24 {
        1
    } else {
        2
    }
}

fn selected_position(selection: Option<usize>, total: usize) -> usize {
    if total == 0 {
        return 0;
    }
    selection.map_or(0, |index| index.min(total - 1) + 1)
}

fn visible_zone_indices(model: &DfdModel, selection: Option<usize>, width: u16) -> Vec<usize> {
    let total = model.zones.len();
    let priority = selected_context_zones(model, selection);
    let preferred = zone_capacity(width, total, PREFERRED_ZONE_W);
    let compact = zone_capacity(width, total, MIN_ZONE_W);
    let count = preferred.max(priority.len().min(compact)).min(total);
    let mut visible = priority.iter().copied().take(count).collect::<Vec<_>>();
    fill_visible_zones(&mut visible, total, count, priority.first().copied());
    visible.sort_unstable();
    visible
}

fn zone_capacity(width: u16, total: usize, zone_width: u16) -> usize {
    if total == 0 {
        return 0;
    }
    let capacity = width
        .saturating_add(GAP)
        .checked_div(zone_width + GAP)
        .unwrap_or(1)
        .max(1) as usize;
    capacity.min(total)
}

fn selected_context_zones(model: &DfdModel, selection: Option<usize>) -> Vec<usize> {
    match selection.and_then(|index| dfd_selected_item(model, index)) {
        Some(DfdSelected::Node(node)) => node_context_zones(model, &node.key),
        Some(DfdSelected::Flow(flow)) => [&flow.from_id, &flow.to_id]
            .into_iter()
            .filter_map(|id| zone_index_for_node(model, id))
            .fold(Vec::new(), push_unique),
        Some(DfdSelected::Boundary(boundary)) => boundary_context_zones(model, boundary),
        None => Vec::new(),
    }
}

fn boundary_context_zones(model: &DfdModel, boundary: &DfdBoundaryModel) -> Vec<usize> {
    let declared = [&boundary.outer_zone, &boundary.inner_zone]
        .into_iter()
        .filter_map(|zone| model.zones.iter().position(|candidate| candidate == zone))
        .fold(Vec::new(), push_unique);
    model
        .flows
        .iter()
        .filter(|flow| flow_crosses_boundary(flow, boundary))
        .flat_map(|flow| [&flow.from_id, &flow.to_id])
        .filter_map(|node_id| zone_index_for_node(model, node_id))
        .fold(declared, push_unique)
}

fn flow_crosses_boundary(flow: &DfdFlowModel, boundary: &DfdBoundaryModel) -> bool {
    boundary.crossing_flow_ids.contains(&flow.key) || flow.boundary_ids.contains(&boundary.key)
}

fn node_context_zones(model: &DfdModel, node_id: &str) -> Vec<usize> {
    let mut zones = zone_index_for_node(model, node_id)
        .into_iter()
        .collect::<Vec<_>>();
    for flow in &model.flows {
        let Some(neighbor_id) = connected_node_id(flow, node_id) else {
            continue;
        };
        if let Some(zone) = zone_index_for_node(model, neighbor_id) {
            zones = push_unique(zones, zone);
        }
    }
    zones
}

fn connected_node_id<'a>(flow: &'a DfdFlowModel, node_id: &str) -> Option<&'a str> {
    if flow.from_id == node_id {
        return Some(&flow.to_id);
    }
    (flow.to_id == node_id).then_some(flow.from_id.as_str())
}

fn push_unique(mut values: Vec<usize>, value: usize) -> Vec<usize> {
    if !values.contains(&value) {
        values.push(value);
    }
    values
}

fn zone_index_for_node(model: &DfdModel, node_id: &str) -> Option<usize> {
    let zone = model
        .nodes
        .iter()
        .find(|node| node.key == node_id)
        .map(|node| node.zone.as_str())?;
    model.zones.iter().position(|candidate| candidate == zone)
}

fn fill_visible_zones(visible: &mut Vec<usize>, total: usize, count: usize, anchor: Option<usize>) {
    let start = zone_window_start(total, count, anchor);
    for zone in (start..total).chain(0..start) {
        if visible.len() == count {
            return;
        }
        if !visible.contains(&zone) {
            visible.push(zone);
        }
    }
}

fn zone_window_start(total: usize, visible: usize, anchor: Option<usize>) -> usize {
    if total <= visible || visible == 0 {
        return 0;
    }
    anchor
        .map(|zone| zone.saturating_sub(visible / 2))
        .unwrap_or(0)
        .min(total - visible)
}

fn zone_node_indices(nodes: &[DfdNodeModel], zone: &str) -> Vec<usize> {
    nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.zone == zone)
        .map(|(index, _)| index)
        .collect()
}

fn page_slice(indices: &[usize], page: usize) -> &[usize] {
    let start = (page * ZONE_PAGE_SIZE).min(indices.len());
    let end = (start + ZONE_PAGE_SIZE).min(indices.len());
    &indices[start..end]
}

fn ordinary_zone_slice(indices: &[usize], page: usize) -> ZoneSlice {
    let pages = indices.len().div_ceil(ZONE_PAGE_SIZE).max(1);
    let node_indices = page_slice(indices, page).to_vec();
    let hidden = indices.len().saturating_sub(node_indices.len());
    let note = (pages > 1).then(|| format!("page {}/{pages} · +{hidden} more", page + 1));
    ZoneSlice { node_indices, note }
}

fn endpoints_on_different_pages(indices: &[usize], endpoints: &[usize]) -> bool {
    let page_of = |endpoint: usize| {
        indices
            .iter()
            .position(|index| *index == endpoint)
            .map(|position| position / ZONE_PAGE_SIZE)
    };
    page_of(endpoints[0]) != page_of(endpoints[1])
}

fn endpoint_zone_slice(indices: &[usize], endpoints: &[usize]) -> ZoneSlice {
    let source_page = indices
        .iter()
        .position(|index| *index == endpoints[0])
        .map_or(0, |position| position / ZONE_PAGE_SIZE);
    let mut node_indices = page_slice(indices, source_page).to_vec();
    for endpoint in endpoints {
        include_endpoint(&mut node_indices, endpoints, *endpoint);
    }
    node_indices.sort_by_key(|index| indices.iter().position(|item| item == index));
    let shown = node_indices.len();
    ZoneSlice {
        node_indices,
        note: Some(format!("flow endpoints · {shown}/{} shown", indices.len())),
    }
}

fn include_endpoint(visible: &mut Vec<usize>, endpoints: &[usize], endpoint: usize) {
    if visible.contains(&endpoint) {
        return;
    }
    if visible.len() < ZONE_PAGE_SIZE {
        visible.push(endpoint);
        return;
    }
    if let Some(position) = visible.iter().rposition(|item| !endpoints.contains(item)) {
        visible[position] = endpoint;
    }
}

fn node_vertical_gap(available: u16, count: usize) -> u16 {
    if count < 2 {
        return 0;
    }
    available
        .saturating_sub(count as u16 * NODE_H)
        .checked_div(count as u16 - 1)
        .unwrap_or(0)
        .min(NODE_VGAP)
}

fn node_span(count: usize, gap: u16) -> u16 {
    if count == 0 {
        return 0;
    }
    count as u16 * NODE_H + count.saturating_sub(1) as u16 * gap
}

fn node_index_by_id(nodes: &[DfdNodeModel], id: &str) -> Option<usize> {
    nodes.iter().position(|node| node.key == id)
}

fn draw_zone_page_label(buf: &mut Buffer, area: Rect, visible_zones: &[usize], total: usize) {
    if visible_zones.len() >= total {
        return;
    }
    let label = zone_page_label(visible_zones, total, area.width.saturating_sub(1) as usize);
    text(buf, area, 1, 0, &label, diagram_muted());
}

fn zone_page_label(visible_zones: &[usize], total: usize, width: usize) -> String {
    let stem = if visible_zones.len() == 1 {
        format!("zone {}/{}", visible_zones[0] + 1, total)
    } else if zones_are_contiguous(visible_zones) {
        format!(
            "zones {}-{}/{}",
            visible_zones[0] + 1,
            visible_zones.last().copied().unwrap_or_default() + 1,
            total
        )
    } else {
        let positions = visible_zones
            .iter()
            .map(|zone| (zone + 1).to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!("zones {positions}/{total}")
    };
    let full = format!("{stem} · j/k follows selection");
    if full.chars().count() <= width {
        return full;
    }
    crate::renderer::shared::text::fit(&format!("{stem} · j/k"), width)
}

fn zones_are_contiguous(visible_zones: &[usize]) -> bool {
    visible_zones.windows(2).all(|pair| pair[1] == pair[0] + 1)
}

fn zone_panel_title(zone: &str, zone_w: u16) -> String {
    crate::renderer::shared::text::fit(&zone.to_uppercase(), zone_w.saturating_sub(2) as usize)
}

fn draw_page_notes(buf: &mut Buffer, area: Rect, notes: &[PageNote]) {
    for note in notes {
        text(buf, area, note.x, note.y, &note.text, diagram_muted());
    }
}

/// Anchors keyed by stable node id for the
/// visible placements only — flows to a paged-out node are simply skipped.
fn anchor_map(model: &DfdModel, placements: &[NodePlacement], nbw: u16) -> HashMap<String, Anchor> {
    placements
        .iter()
        .map(|placement| {
            (
                model.nodes[placement.node_index].key.clone(),
                Anchor {
                    col: placement.zi,
                    cx: placement.cx,
                    top: placement.y,
                    bottom: placement.y + NODE_H - 1,
                    left: placement.left,
                    right: placement.left + nbw,
                },
            )
        })
        .collect()
}

/// Draw one node box: blank the interior (hiding edge runs beneath), then the
/// rounded border + label. Selection recolours the border.
fn draw_node_box(
    buf: &mut Buffer,
    area: Rect,
    node: &DfdNodeModel,
    placement: &NodePlacement,
    nbw: u16,
    context_count: usize,
    selected: bool,
) {
    let color = node_color(node.kind);
    let border = if selected { selection_color() } else { color };
    let label = node_box_context_label(node, nbw, context_count);
    clear_rect(buf, area, placement.left, placement.y, nbw, NODE_H);
    boxed(
        buf,
        area,
        placement.left,
        placement.y,
        nbw,
        NODE_H,
        &label,
        border,
        color,
    );
}

fn node_box_label(node: &DfdNodeModel, box_width: u16) -> String {
    crate::renderer::shared::text::fit_words(
        &node_label(node),
        box_width.saturating_sub(3) as usize,
    )
}

fn node_box_context_label(node: &DfdNodeModel, box_width: u16, context_count: usize) -> String {
    if context_count == 0 {
        return node_box_label(node, box_width);
    }
    let label = format!("{} +{context_count}", node_label(node));
    crate::renderer::shared::text::fit_words(&label, box_width.saturating_sub(3) as usize)
}

fn security_context_count(model: &DfdModel, element_id: &str) -> usize {
    model
        .security_context
        .iter()
        .filter(|item| item.target_element_ids.iter().any(|id| id == element_id))
        .count()
}

fn draw_one_flow(
    buf: &mut Buffer,
    area: Rect,
    anchors: &HashMap<String, Anchor>,
    flow: &DfdFlowModel,
    color: Color,
) {
    if let (Some(a), Some(b)) = (anchors.get(&flow.from_id), anchors.get(&flow.to_id)) {
        draw_flow(buf, area, a, b, color);
    }
}

fn draw_flow(buf: &mut Buffer, area: Rect, a: &Anchor, b: &Anchor, color: Color) {
    use std::cmp::Ordering::{Equal, Greater, Less};
    match a.col.cmp(&b.col) {
        Less => connector_h(buf, area, (a.right, a.mid()), (b.left, b.mid()), color),
        Greater => connector_left(buf, area, (a.left, a.mid()), (b.right, b.mid()), color),
        Equal if a.top <= b.top => {
            connector_v(buf, area, (a.cx, a.bottom + 1), (b.cx, b.top), color)
        }
        Equal => connector_up(buf, area, a.cx, a.top, b.bottom, color),
    }
}

#[cfg(test)]
mod component_map_tests;
#[cfg(test)]
mod flow_direction_tests;

fn selected_detail_content(
    model: &DfdModel,
    selection: Option<usize>,
    width: usize,
) -> DetailContent {
    match selection.and_then(|index| dfd_selected_item(model, index)) {
        Some(DfdSelected::Node(node)) => node_detail_content(model, node, width),
        Some(DfdSelected::Flow(flow)) => flow_detail_content(model, flow, width),
        Some(DfdSelected::Boundary(boundary)) => boundary_detail_content(model, boundary, width),
        None => DetailContent {
            kind: "item",
            lines: vec![Line::styled(
                "j/k or ↑/↓ selects every node and flow",
                crate::theme::muted(),
            )],
        },
    }
}

fn boundary_detail_content(
    model: &DfdModel,
    boundary: &DfdBoundaryModel,
    width: usize,
) -> DetailContent {
    let mut lines = Vec::new();
    append_detail_lines(&mut lines, "name", &boundary.name, width);
    append_source_files_detail(&mut lines, model, &boundary.key, width);
    append_linked_context_detail(&mut lines, model, &boundary.key, width);
    append_detail_lines(&mut lines, "outer zone", &boundary.outer_zone, width);
    append_detail_lines(&mut lines, "inner zone", &boundary.inner_zone, width);
    append_detail_lines(
        &mut lines,
        "flows",
        &nonempty_list(&boundary.crossing_flow_ids),
        width,
    );
    DetailContent {
        kind: "boundary",
        lines,
    }
}

fn append_legacy_context_detail(lines: &mut Vec<Line<'static>>, model: &DfdModel, width: usize) {
    if model.link_state != DfdLinkState::LegacyNeedsRebuild {
        return;
    }
    append_detail_lines(
        lines,
        "context",
        "legacy model has no valid DFD links; overlay suppressed",
        width,
    );
}

fn nonempty_list(values: &[String]) -> String {
    if values.is_empty() {
        "none recorded".to_string()
    } else {
        values.join(", ")
    }
}

fn node_detail_content(model: &DfdModel, node: &DfdNodeModel, width: usize) -> DetailContent {
    let mut lines = Vec::new();
    append_detail_lines(&mut lines, "name", &node.name, width);
    append_source_files_detail(&mut lines, model, &node.key, width);
    append_detail_lines(
        &mut lines,
        "does",
        node.description
            .as_deref()
            .unwrap_or("not recorded in the threat model"),
        width,
    );
    append_component_topology_notice(&mut lines, model, &node.key, width);
    append_detail_lines(
        &mut lines,
        "purpose",
        node.purpose.as_deref().unwrap_or("not recorded"),
        width,
    );
    append_linked_context_detail(&mut lines, model, &node.key, width);
    append_detail_lines(&mut lines, "type", kind_label(node.kind), width);
    append_detail_lines(&mut lines, "zone", &node.zone, width);
    DetailContent {
        kind: "node",
        lines,
    }
}

fn append_component_topology_notice(
    lines: &mut Vec<Line<'static>>,
    model: &DfdModel,
    key: &str,
    width: usize,
) {
    if let Some(notice) = model.component_topology_notice(key) {
        append_detail_lines(lines, "flows", notice, width);
    }
}

fn flow_detail_content(model: &DfdModel, flow: &DfdFlowModel, width: usize) -> DetailContent {
    let mut lines = Vec::new();
    append_detail_lines(&mut lines, "from", &flow.from, width);
    append_source_files_detail(&mut lines, model, &flow.key, width);
    append_linked_context_detail(&mut lines, model, &flow.key, width);
    append_detail_lines(&mut lines, "to", &flow.to, width);
    append_detail_lines(&mut lines, "description", nonempty(&flow.label), width);
    append_detail_lines(&mut lines, "boundaries", &boundary_detail(flow), width);
    append_detail_lines(&mut lines, "routing", crossing_detail(flow), width);
    DetailContent {
        kind: "flow",
        lines,
    }
}

fn append_source_files_detail(
    lines: &mut Vec<Line<'static>>,
    model: &DfdModel,
    element_id: &str,
    width: usize,
) {
    let Some(paths) = model.element_file_paths.get(element_id) else {
        return;
    };
    let quoted = paths
        .iter()
        .map(|path| format!("{path:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    append_detail_lines(lines, "files", &quoted, width);
}

fn append_linked_context_detail(
    lines: &mut Vec<Line<'static>>,
    model: &DfdModel,
    element_id: &str,
    width: usize,
) {
    if model.link_state != DfdLinkState::Complete {
        return;
    }
    let summary = linked_context_summary(model, element_id);
    append_detail_lines(lines, "context", &summary, width);
}

fn linked_context_summary(model: &DfdModel, element_id: &str) -> String {
    let linked = dfd_selection_for_key(model, element_id)
        .map(|selection| dfd_security_items_for_selection(model, selection))
        .unwrap_or_default();
    if linked.is_empty() {
        return "none linked".to_string();
    }
    let mut parts = vec!["linked".into(), linked.len().to_string()];
    for kind in security_context_kinds() {
        let count = linked.iter().filter(|item| item.kind == kind).count();
        if count > 0 {
            parts.push(format!("{count} {}", responsive::security_kind_name(kind)));
        }
    }
    parts.join(" · ")
}

fn security_context_kinds() -> [DfdSecurityKind; 6] {
    [
        DfdSecurityKind::EntryPoint,
        DfdSecurityKind::RoleGate,
        DfdSecurityKind::ExternalSink,
        DfdSecurityKind::TrustedCaller,
        DfdSecurityKind::Asset,
        DfdSecurityKind::Threat,
    ]
}

fn append_detail_lines(lines: &mut Vec<Line<'static>>, key: &str, value: &str, width: usize) {
    let key_width = width.min(13);
    let value_width = width.saturating_sub(key_width).max(1);
    let chunks = crate::renderer::shared::text::wrap_document_lines(
        value
            .split('\n')
            .map(|line| Line::raw(line.to_owned()))
            .collect(),
        value_width.min(u16::MAX as usize) as u16,
    );
    for (index, chunk) in chunks.into_iter().enumerate() {
        let label = if index == 0 {
            format!("{key:<key_width$}")
        } else {
            " ".repeat(key_width)
        };
        lines.push(Line::from(vec![
            Span::styled(label, crate::theme::muted()),
            Span::styled(chunk.to_string(), crate::theme::primary()),
        ]));
    }
}

fn boundary_detail(flow: &DfdFlowModel) -> String {
    if flow.boundary_ids.is_empty() {
        return "none recorded".to_string();
    }
    flow.boundary_ids.join(", ")
}

fn crossing_detail(flow: &DfdFlowModel) -> &'static str {
    if flow.crosses {
        "trust-boundary crossing"
    } else {
        "in-zone"
    }
}

fn nonempty(value: &str) -> &str {
    if value.is_empty() {
        "none recorded"
    } else {
        value
    }
}

fn detail_panel_title(
    kind: &str,
    selected: usize,
    total: usize,
    scroll: usize,
    max_scroll: usize,
) -> String {
    if max_scroll == 0 {
        return format!(" DETAIL · {kind} {selected}/{total} ");
    }
    format!(
        " DETAIL · {kind} {selected}/{total} · rows {}/{} ",
        scroll + 1,
        max_scroll + 1
    )
}

fn kind_label(kind: DfdKind) -> &'static str {
    match kind {
        DfdKind::Entity => "external entity",
        DfdKind::Process => "process",
        DfdKind::Store => "data store",
    }
}

fn node_label(node: &DfdNodeModel) -> String {
    let glyph = match node.kind {
        DfdKind::Entity => "◆",
        DfdKind::Process => "◇",
        DfdKind::Store => "▣",
    };
    format!("{glyph} {}", node.name)
}

fn node_color(kind: DfdKind) -> Color {
    if theme::active_theme().high_contrast {
        return match kind {
            DfdKind::Entity | DfdKind::Process => theme::T_HEADING,
            DfdKind::Store => theme::SEV_HIGH,
        };
    }
    match kind {
        DfdKind::Entity => theme::T_LABEL,
        DfdKind::Process => theme::T_ACCENT,
        DfdKind::Store => theme::SEV_HIGH,
    }
}

fn flow_color(crosses: bool) -> Color {
    if crosses {
        theme::SEV_HIGH
    } else if theme::active_theme().high_contrast {
        theme::T_PRIMARY
    } else {
        theme::T_MUTED
    }
}

/// Distinct from every node/flow colour so the cursor reads at a glance.
fn selection_color() -> Color {
    if theme::active_theme().high_contrast {
        theme::T_HEADING
    } else {
        theme::T_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{DfdSecurityItem, DfdSecurityKind};

    mod selected_neighborhood;

    #[test]
    fn direct_source_files_are_visible_before_security_context_for_every_element() {
        let mut model = portrait_model();
        let path = " app /source.rs:7";
        for key in [
            model.nodes[0].key.clone(),
            model.flows[0].key.clone(),
            model.boundaries[0].key.clone(),
        ] {
            model.element_file_paths.insert(key, vec![path.into()]);
        }
        let details = [
            node_detail_content(&model, &model.nodes[0], 100),
            flow_detail_content(&model, &model.flows[0], 100),
            boundary_detail_content(&model, &model.boundaries[0], 100),
        ];
        for detail in details {
            let text = detail
                .lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                text.contains("files        \" app /source.rs:7\""),
                "{text}"
            );
            assert!(
                text.find("files").unwrap() < text.find("context").unwrap(),
                "{text}"
            );
        }
    }

    #[test]
    fn selected_position_is_one_based_and_clamped_to_the_available_items() {
        assert_eq!(selected_position(Some(0), 3), 1);
        assert_eq!(selected_position(Some(usize::MAX), 3), 3);
        assert_eq!(selected_position(Some(0), 0), 0);
    }

    #[test]
    fn legend_keeps_every_count_visible_at_medium_and_narrow_widths() {
        let model = portrait_model();
        let total = dfd_selectable_count(&model);

        assert_eq!(
            legend_text(&model, Some(0), total, 60),
            "5N · 4F · 1B · 1/10 · ctx1"
        );
        assert_eq!(legend_text(&model, Some(0), total, 39), "1/10 5N 4F 1B C1");
        assert_eq!(legend_text(&model, Some(0), total, 16), "1/10 N5F4B1");
    }

    #[test]
    fn detail_only_fallback_does_not_paint_resize_hint_over_inspector_rows() {
        let rendered = render_selection(&portrait_model(), 0, 0, 80, 7);

        assert!(rendered.contains("resize to see topology"), "{rendered}");
        assert!(
            rendered.contains("name         Local developer user"),
            "{rendered}"
        );
        assert!(rendered.contains("context      linked"), "{rendered}");
        assert!(!rendered.contains("cresize"), "{rendered}");
    }

    #[test]
    fn compact_layout_boundary_preserves_the_graph_when_space_is_sufficient() {
        let compact = Rect::new(0, 0, 15, 12);
        let available = Rect::new(0, 0, 16, 12);
        let compact_layout = responsive::topology_layout(compact);
        let available_layout = responsive::topology_layout(available);

        assert_eq!(compact_layout, responsive::DfdTopologyLayout::DetailOnly);
        assert_eq!(
            dfd_regions(compact, compact_layout),
            DfdRegions {
                graph: None,
                detail: Some(compact)
            }
        );
        assert!(dfd_regions(available, available_layout).graph.is_some());
    }

    #[test]
    fn responsive_layout_resolves_width_and_height_boundaries() {
        use responsive::DfdTopologyLayout::{CausalPath, DetailOnly, StackedZones, WideLanes};

        assert_eq!(
            responsive::topology_layout(Rect::new(0, 0, 15, 30)),
            DetailOnly
        );
        assert_eq!(
            responsive::topology_layout(Rect::new(0, 0, 16, 30)),
            CausalPath
        );
        assert_eq!(
            responsive::topology_layout(Rect::new(0, 0, 59, 30)),
            CausalPath
        );
        assert_eq!(
            responsive::topology_layout(Rect::new(0, 0, 60, 30)),
            StackedZones
        );
        assert_eq!(
            responsive::topology_layout(Rect::new(0, 0, 109, 30)),
            StackedZones
        );
        assert_eq!(
            responsive::topology_layout(Rect::new(0, 0, 110, 30)),
            WideLanes
        );
        assert_eq!(
            responsive::topology_layout(Rect::new(0, 0, 110, 15)),
            CausalPath
        );
    }

    #[test]
    fn portrait_layout_stacks_connected_zones_without_unrelated_columns() {
        let rendered = render_selection(&portrait_model(), 0, 0, 80, 40);
        let user_row = line_index(&rendered, "USER_DEVICE");
        let local_row = line_index(&rendered, "LOCAL_PROCESS");

        assert!(user_row < local_row, "{rendered}");
        assert!(rendered.contains("Local developer user +1"), "{rendered}");
        assert!(rendered.contains("Provider/plugin subsystem"), "{rendered}");
        assert!(!rendered.contains("INTERNET"), "{rendered}");
        assert!(rendered.contains("context      linked"), "{rendered}");
        assert!(rendered.contains("1 · 1 callers"), "{rendered}");
    }

    #[test]
    fn narrow_layout_shows_selected_causal_neighborhood_and_hidden_count() {
        let rendered = render_selection(&portrait_model(), 0, 0, 40, 30);

        assert!(rendered.contains("causal diagram"), "{rendered}");
        assert!(rendered.contains("◆ Local developer user +1"), "{rendered}");
        assert!(rendered.contains("Local developer user +1"), "{rendered}");
        assert!(rendered.contains("opencode CLI/TUI"), "{rendered}");
        assert!(rendered.contains("+2 adjacent flows"), "{rendered}");
        assert!(rendered.contains('▼'), "{rendered}");
        assert!(rendered.contains('╭'), "{rendered}");
    }

    #[test]
    fn wide_layout_shrink_wraps_topology_instead_of_centering_it_in_empty_space() {
        let rendered = render_selection(&portrait_model(), 0, 0, 160, 48);
        let selected_row = line_index(&rendered, "Local developer user +1");
        let legend_row = line_index(&rendered, "5 nodes · 4 flows");

        assert!(selected_row < 8, "{rendered}");
        assert!(legend_row < 20, "{rendered}");
    }

    #[test]
    fn narrow_flow_and_boundary_selections_keep_their_causal_identity() {
        let model = portrait_model();
        let flow_selection = model.nodes.len();
        let flow = render_selection(&model, flow_selection, 0, 40, 30);
        let boundary_selection = model.nodes.len() + model.flows.len();
        let boundary = render_selection(&model, boundary_selection, 0, 40, 30);

        assert!(flow.contains("selected flow"), "{flow}");
        assert!(flow.contains("Local developer"), "{flow}");
        assert!(flow.contains("opencode CLI/TUI"), "{flow}");
        assert!(flow.contains('▼'), "{flow}");
        assert!(boundary.contains("boundary flow"), "{boundary}");
        assert!(boundary.contains("invokes"), "{boundary}");
        assert!(boundary.contains('▼'), "{boundary}");
    }

    fn line_index(rendered: &str, needle: &str) -> usize {
        rendered
            .lines()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("missing {needle:?}: {rendered}"))
    }

    #[test]
    fn empty_dfd_prompts_generation() {
        let rendered = render_to_text(
            DfdDiagram {
                model: DfdModel {
                    empty_hint: Some("no persisted threat model".into()),
                    ..Default::default()
                },
                selection: Some(0),
                detail_scroll: 0,
                focused: false,
                context_selection: 0,
            },
            75,
            24,
        );

        assert!(rendered.contains("no data-flow diagram"), "{rendered}");
        assert!(rendered.contains("threat-model:build"), "{rendered}");
    }

    #[test]
    fn focused_security_graph_is_readable_across_width_classes() {
        let model = focused_model();

        for width in [24, 60, 96, 160] {
            let rendered = render_to_text(
                DfdDiagram {
                    model: model.clone(),
                    selection: Some(0),
                    detail_scroll: 0,
                    focused: true,
                    context_selection: 0,
                },
                width,
                28,
            );
            assert!(rendered.contains("OAuth"), "width {width}: {rendered}");
            assert!(
                rendered.contains("oauth_callback") || rendered.contains("oauth_cal"),
                "width {width}: {rendered}"
            );
            assert!(
                rendered.contains("Enter topology"),
                "width {width}: {rendered}"
            );
        }
    }

    #[test]
    fn topology_node_chip_discloses_linked_context_count() {
        let rendered = render_selection(&focused_model(), 0, 0, 75, 28);

        assert!(rendered.contains("◇ OAuth callback +2"), "{rendered}");
    }

    #[test]
    fn focused_annotation_selection_updates_the_link_detail() {
        let rendered = render_to_text(
            DfdDiagram {
                model: focused_model(),
                selection: Some(0),
                detail_scroll: 0,
                focused: true,
                context_selection: 1,
            },
            60,
            20,
        );

        assert!(rendered.contains("THREAT · T-state"), "{rendered}");
        assert!(
            rendered.contains("callback state can cross sessions"),
            "{rendered}"
        );
    }

    fn focused_model() -> DfdModel {
        DfdModel {
            zones: vec!["app".into()],
            nodes: vec![DfdNodeModel {
                key: "oauth".into(),
                name: "OAuth callback".into(),
                description: None,
                purpose: None,
                zone: "app".into(),
                kind: DfdKind::Process,
            }],
            security_context: vec![
                DfdSecurityItem {
                    key: "AS-oauth".into(),
                    kind: DfdSecurityKind::EntryPoint,
                    label: "oauth_callback".into(),
                    detail: "GET /oauth/callback".into(),
                    evidence: "src/oauth.rs:42".into(),
                    evidence_paths: vec!["src/oauth.rs:42".into()],
                    file_paths: vec!["src/oauth.rs".into()],
                    target_element_ids: vec!["oauth".into()],
                },
                DfdSecurityItem {
                    key: "T-state".into(),
                    kind: DfdSecurityKind::Threat,
                    label: "OAuth state confusion".into(),
                    detail: "callback state can cross sessions".into(),
                    evidence: "src/oauth.rs:51".into(),
                    evidence_paths: vec!["src/oauth.rs:51".into()],
                    file_paths: vec!["src/oauth.rs".into()],
                    target_element_ids: vec!["oauth".into()],
                },
            ],
            link_state: DfdLinkState::Complete,
            ..Default::default()
        }
    }

    fn portrait_model() -> DfdModel {
        let zones = vec![
            "user_device".into(),
            "internet".into(),
            "local_process".into(),
        ];
        let nodes = vec![
            node("Local developer user", "user_device"),
            node("Remote web/API client", "internet"),
            node("opencode CLI/TUI", "local_process"),
            node("opencode local HTTP API server", "local_process"),
            node("Provider/plugin subsystem", "local_process"),
        ];
        let flows = vec![
            flow("Local developer user", "opencode CLI/TUI", "invokes"),
            flow(
                "Local developer user",
                "Provider/plugin subsystem",
                "configures",
            ),
            flow(
                "Local developer user",
                "opencode local HTTP API server",
                "starts server",
            ),
            flow(
                "Remote web/API client",
                "opencode local HTTP API server",
                "sends request",
            ),
        ];
        DfdModel {
            target_name: "opencode".into(),
            system_context: None,
            review_only: false,
            zones,
            nodes,
            flows,
            boundaries: vec![DfdBoundaryModel {
                key: "tb-local".into(),
                name: "User to local process".into(),
                inner_zone: "local_process".into(),
                outer_zone: "user_device".into(),
                crossing_flow_ids: vec!["Local developer user->opencode CLI/TUI".into()],
            }],
            security_context: vec![DfdSecurityItem {
                key: "TC-local".into(),
                kind: DfdSecurityKind::TrustedCaller,
                label: "local developer".into(),
                detail: "authorized operator".into(),
                evidence: "src/main.rs:1".into(),
                evidence_paths: vec!["src/main.rs:1".into()],
                file_paths: vec!["src/main.rs".into()],
                target_element_ids: vec!["Local developer user".into()],
            }],
            element_file_paths: Default::default(),
            link_state: DfdLinkState::Complete,
            empty_hint: None,
        }
    }

    #[test]
    fn aggregate_boundary_uses_concrete_crossing_flow_zones() {
        let model = aggregate_boundary_model();
        let zones = boundary_context_zones(&model, &model.boundaries[0]);

        assert_eq!(zones, vec![0, 1, 2]);
    }

    #[test]
    fn medium_boundary_selection_renders_a_directional_fan_out() {
        let model = aggregate_boundary_model();
        let selection = model.nodes.len() + model.flows.len();
        let rendered = render_selection(&model, selection, 0, 80, 30);

        assert_contains_all(
            &rendered,
            &[
                "selected boundary · 3 crossing flows",
                "◇ Remote web/API client · INTERNET",
                "F12 · ◇ Serverless function API · CLOUD_FUNCTION",
                "F14 · ◇ Stats app · WEB_APP",
                "F16 · ◇ Console web app · WEB_APP",
                "├────▶",
            ],
        );
    }

    fn aggregate_boundary_model() -> DfdModel {
        let mut flows = vec![
            flow(
                "Remote web/API client",
                "Serverless function API",
                "calls functions",
            ),
            flow("Remote web/API client", "Stats app", "submits request"),
            flow("Remote web/API client", "Console web app", "opens console"),
        ];
        for (flow, key) in flows.iter_mut().zip(["F12", "F14", "F16"]) {
            flow.key = key.into();
            flow.boundary_ids = vec!["TB9".into()];
        }
        DfdModel {
            zones: vec!["internet".into(), "cloud_function".into(), "web_app".into()],
            nodes: vec![
                node("Remote web/API client", "internet"),
                node("Serverless function API", "cloud_function"),
                node("Stats app", "web_app"),
                node("Console web app", "web_app"),
            ],
            flows,
            boundaries: vec![DfdBoundaryModel {
                key: "TB9".into(),
                name: "Internet request to web/serverless app".into(),
                inner_zone: "web_or_function_runtime".into(),
                outer_zone: "internet".into(),
                crossing_flow_ids: vec!["F12".into(), "F14".into(), "F16".into()],
            }],
            link_state: DfdLinkState::Complete,
            empty_hint: None,
            ..Default::default()
        }
    }

    #[test]
    fn mutation_survivor_stacked_layout_reserves_detail_height_below_graph() {
        let area = Rect::new(3, 4, 80, 20);
        let regions = stacked_dfd_regions(area);

        assert_eq!(regions.graph, Some(Rect::new(3, 4, 80, 14)));
        assert_eq!(regions.detail, Some(Rect::new(3, 19, 80, 5)));
    }

    fn render_to_text(diagram: DfdDiagram, w: u16, h: u16) -> String {
        let area = Rect::new(0, 0, w, h);
        let mut buf = Buffer::empty(area);
        diagram.render(area, &mut buf);
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn node(name: &str, zone: &str) -> DfdNodeModel {
        DfdNodeModel {
            key: name.into(),
            name: name.into(),
            description: None,
            purpose: None,
            zone: zone.into(),
            kind: DfdKind::Process,
        }
    }

    #[test]
    fn tiny_inspector_spends_its_rows_on_selected_evidence_and_keeps_paging() {
        for height in [1, 2] {
            let model = DfdModel {
                nodes: vec![node("Alpha receiver", "application")],
                ..Default::default()
            };
            let diagram = |scroll| DfdDiagram {
                model: model.clone(),
                selection: Some(0),
                detail_scroll: scroll,
                focused: false,
                context_selection: 0,
            };
            let first = render_to_text(diagram(0), 40, height);
            assert!(first.contains("Alpha receiver"), "{first}");
            assert!(!first.contains("┌ DETAIL"), "{first}");
            let next = render_to_text(diagram(1), 40, height);
            assert!(next.contains("does"), "{next}");
        }
    }

    #[test]
    fn evidence_detail_preserves_literal_filename_spaces_at_every_wrap() {
        let value = "app/a  b.tf#L7";
        for width in [16, 24, 40, 120] {
            let mut lines = Vec::new();
            append_detail_lines(&mut lines, "evidence", value, width);
            let recovered = lines
                .iter()
                .flat_map(|line| line.spans.iter().skip(1))
                .map(|span| span.content.as_ref())
                .collect::<String>();
            assert_eq!(recovered, value, "{width}");
        }
    }

    fn flow(from: &str, to: &str, label: &str) -> DfdFlowModel {
        DfdFlowModel {
            key: format!("{from}->{to}"),
            from_id: from.into(),
            to_id: to.into(),
            from: from.into(),
            to: to.into(),
            crosses: true,
            label: label.into(),
            boundary_ids: vec!["tb-1".into()],
        }
    }

    /// A flow spanning zone 0 → zone 2 routes across the middle zone's box
    /// column; the box draws over it, so its interior row shows no edge run.
    #[test]
    fn edges_route_under_boxes_never_through_their_interiors() {
        let model = DfdModel {
            zones: vec!["a".into(), "b".into(), "c".into()],
            nodes: vec![node("src", "a"), node("mid", "b"), node("dst", "c")],
            flows: vec![flow("src", "dst", "long haul")],
            empty_hint: None,
            ..Default::default()
        };
        let rendered = render_to_text(
            DfdDiagram {
                model,
                selection: None,
                detail_scroll: 0,
                focused: false,
                context_selection: 0,
            },
            160,
            24,
        );

        let row = rendered
            .lines()
            .find(|line| line.contains("◇ mid"))
            .expect("mid node label row");
        let glyph_col = row.chars().position(|ch| ch == '◇').expect("glyph col");
        // Interior spans from just inside the left border past the label; the
        // connector may only resume after the right border.
        let interior: String = row
            .chars()
            .skip(glyph_col.saturating_sub(1))
            .take(18)
            .collect();
        assert!(
            !interior.contains('─') && !interior.contains('▶'),
            "edge run leaked into the box interior: {row:?}"
        );
        // The connector still exists outside the box.
        assert!(row.contains('─'), "flow should still be drawn: {row:?}");
    }

    #[test]
    fn dense_zone_pages_with_an_honest_indicator() {
        let names = ["n1", "n2", "n3", "n4", "n5", "n6"];
        let model = DfdModel {
            zones: vec!["app".into()],
            nodes: names.iter().map(|name| node(name, "app")).collect(),
            flows: Vec::new(),
            empty_hint: None,
            ..Default::default()
        };
        let first_page = render_to_text(
            DfdDiagram {
                model: model.clone(),
                selection: None,
                detail_scroll: 0,
                focused: false,
                context_selection: 0,
            },
            80,
            30,
        );
        assert!(first_page.contains("page 1/2 · +2 more"), "{first_page}");
        assert!(first_page.contains("◇ n1"));
        assert!(!first_page.contains("◇ n5"));

        // Selecting a node on the second page turns that page's nodes visible.
        let second_page = render_to_text(
            DfdDiagram {
                model,
                selection: Some(4),
                detail_scroll: 0,
                focused: false,
                context_selection: 0,
            },
            80,
            30,
        );
        assert!(second_page.contains("page 2/2 · +4 more"), "{second_page}");
        assert!(second_page.contains("◇ n5"));
        assert!(!second_page.contains("◇ n1"));
    }

    #[test]
    fn many_zone_diagram_pages_instead_of_abandoning_the_graph() {
        let model = many_zone_model();

        for width in [16, 20, 24, 32, 40, 60, 75, 80, 120, 160] {
            let rendered = render_selection(&model, 12, 0, width, 36);
            assert!(
                !rendered.contains("diagram compacted"),
                "width {width} abandoned the graph: {rendered}"
            );
            assert_selected_node_label_is_readable(width, &rendered);
            assert_layout_context_is_visible(width, &rendered);
        }
    }

    fn assert_selected_node_label_is_readable(width: u16, rendered: &str) {
        if width >= 32 {
            assert!(
                rendered.contains("service-thirteen"),
                "width {width} hid the selected node: {rendered}"
            );
            return;
        }
        assert!(rendered.contains('◆'), "{width}: {rendered}");
        assert!(rendered.contains("..."), "{width}: {rendered}");
    }

    fn assert_layout_context_is_visible(width: u16, rendered: &str) {
        if width < responsive::STACKED_LAYOUT_MIN {
            assert!(rendered.contains("causal diagr"), "{width}: {rendered}");
        } else {
            assert!(rendered.contains("zone"), "{width}: {rendered}");
        }
    }

    #[test]
    fn narrow_node_boxes_mark_truncation_instead_of_silently_clipping() {
        let long = node("Cloud share/stats/tenant data stores", "cloud");
        let label = node_box_label(&long, MIN_ZONE_W);

        assert!(label.starts_with("◇ Cloud"), "{label}");
        assert!(label.ends_with("..."), "{label}");
        assert!(label.chars().count() <= (MIN_ZONE_W - 3) as usize);
    }

    #[test]
    fn narrow_zone_page_label_keeps_position_and_navigation_visible() {
        assert_eq!(zone_page_label(&[12], 13, 23), "zone 13/13 · j/k");
    }

    #[test]
    fn selected_flow_keeps_both_endpoint_zones_visible_when_they_fit() {
        let model = many_zone_model();
        let selection = model.nodes.len();
        let rendered = render_selection(&model, selection, 0, 75, 36);

        assert!(rendered.contains("showing zones 11,13 of 13"), "{rendered}");
        assert!(rendered.contains("service-eleven"), "{rendered}");
        assert!(rendered.contains("service-thirteen"), "{rendered}");
        assert!(rendered.contains('▼'), "{rendered}");
    }

    #[test]
    fn selected_node_shows_its_connected_zone_instead_of_an_unrelated_neighbor() {
        let model = DfdModel {
            zones: vec![
                "user_device".into(),
                "internet".into(),
                "local_process".into(),
            ],
            nodes: vec![
                node("Local developer user", "user_device"),
                node("Remote web/API client", "internet"),
                node("opencode CLI/TUI", "local_process"),
            ],
            flows: vec![flow("Local developer user", "opencode CLI/TUI", "invokes")],
            empty_hint: None,
            ..Default::default()
        };
        let rendered = render_selection(&model, 0, 0, 75, 36);

        assert!(rendered.contains("showing zones 1,3 of 3"), "{rendered}");
        assert!(rendered.contains("◇ Local developer user"), "{rendered}");
        assert!(rendered.contains("◇ opencode CLI/TUI"), "{rendered}");
        assert!(!rendered.contains("◇ Remote web/API client"), "{rendered}");
        assert!(rendered.contains('▼'), "{rendered}");
    }

    fn many_zone_model() -> DfdModel {
        let zones = (1..=13)
            .map(|index| format!("trust-zone-{index:02}"))
            .collect::<Vec<_>>();
        let mut nodes = (1..=13)
            .map(|index| node(&format!("service-{index:02}"), &zones[index - 1]))
            .collect::<Vec<_>>();
        nodes[10].name = "service-eleven".into();
        nodes[12].name = "service-thirteen".into();
        DfdModel {
            zones,
            flows: vec![flow("service-11", "service-13", "selected route")],
            nodes,
            empty_hint: None,
            ..Default::default()
        }
    }

    #[test]
    fn inspector_panel_names_the_selected_node_and_flow() {
        let model = DfdModel {
            zones: vec!["a".into(), "b".into()],
            nodes: vec![node("web", "a"), node("db", "b")],
            flows: vec![flow("web", "db", "sql")],
            empty_hint: None,
            ..Default::default()
        };
        let node_selected = render_selection(&model, 0, 0, 60, 24);
        assert_contains_all(
            &node_selected,
            &["name         web", "type         process"],
        );

        let flow_selected = render_selection(&model, 2, 0, 60, 24);
        assert_contains_all(
            &flow_selected,
            &[
                "from         web",
                "to           db",
                "description  sql",
                "boundaries   tb-1",
            ],
        );
    }

    #[test]
    fn audit_regression_reaches_all_13_nodes_and_11_flows_at_120x36() {
        let model = audit_regression_model();
        let element_total = model.nodes.len() + model.flows.len();
        let navigation_total = element_total;

        for selection in 0..element_total {
            let rendered = render_selection(&model, selection, 0, 120, 36);
            assert!(
                rendered.contains(&format!("selected {}/{navigation_total}", selection + 1)),
                "selection {selection} has dishonest counts: {rendered}"
            );
            assert_selected_item_visible(&model, selection, &rendered);
        }

        assert_same_zone_endpoint_page(&model);
    }

    fn assert_same_zone_endpoint_page(model: &DfdModel) {
        let same_zone = render_selection(model, model.nodes.len() + 7, 0, 120, 36);
        let graph = graph_columns(&same_zone, 79);
        assert!(
            graph.contains("◇ map"),
            "source page is hidden: {same_zone}"
        );
        assert!(
            graph.contains("◇ worker-8"),
            "target page is hidden: {same_zone}"
        );
        assert!(
            same_zone.contains("flow endpoints · 4/9 shown"),
            "same-zone endpoint page must be explicit: {same_zone}"
        );
        assert!(same_zone.contains("11 flows · 0 boundaries"), "{same_zone}");
    }

    #[test]
    fn narrow_inspector_scroll_exposes_full_flow_details_and_all_boundaries() {
        let mut model = audit_regression_model();
        model.flows[7].label =
            "account mapping request with authorization context and response metadata".into();
        model.flows[7].boundary_ids = vec![
            "boundary-edge-authentication".into(),
            "boundary-gateway-authorization".into(),
            "boundary-service-account".into(),
        ];
        let selection = model.nodes.len() + 7;
        let mut reachable = String::new();

        for detail_scroll in 0..12 {
            reachable.push_str(&render_selection(&model, selection, detail_scroll, 48, 24));
        }

        assert!(
            reachable.contains("DETAIL · flow 21/24 · rows"),
            "{reachable}"
        );
        assert_contains_all(
            &reachable,
            &[
                "account mapping request with",
                "authorization context and",
                "response metadata",
                "boundary-edge-authentication",
                "boundary-gateway-authorization",
                "boundary-service-account",
            ],
        );
        assert!(reachable.contains("◇ map"), "{reachable}");
        assert!(reachable.contains("◇ worker-"), "{reachable}");
        assert!(reachable.contains("worker-8"), "{reachable}");
    }

    fn assert_contains_all(rendered: &str, expected_values: &[&str]) {
        for expected in expected_values {
            assert!(
                rendered.contains(expected),
                "missing {expected}: {rendered}"
            );
        }
    }

    fn render_selection(
        model: &DfdModel,
        selection: usize,
        detail_scroll: usize,
        width: u16,
        height: u16,
    ) -> String {
        render_to_text(
            DfdDiagram {
                model: model.clone(),
                selection: Some(selection),
                detail_scroll,
                focused: false,
                context_selection: 0,
            },
            width,
            height,
        )
    }

    fn assert_selected_item_visible(model: &DfdModel, selection: usize, rendered: &str) {
        match dfd_selected_item(model, selection).unwrap() {
            DfdSelected::Node(node) => assert!(rendered.contains(&node.name), "{rendered}"),
            DfdSelected::Flow(flow) => {
                let graph = graph_columns(rendered, 79);
                let from = format!("◇ {}", flow.from);
                let to = format!("◇ {}", flow.to);
                assert!(graph.contains(&from), "missing source {from}: {rendered}");
                assert!(graph.contains(&to), "missing target {to}: {rendered}");
                assert!(rendered.contains(&flow.label), "{rendered}");
                for boundary in &flow.boundary_ids {
                    assert!(
                        rendered.contains(boundary),
                        "missing {boundary}: {rendered}"
                    );
                }
            }
            DfdSelected::Boundary(boundary) => {
                assert!(rendered.contains(&boundary.name), "{rendered}");
            }
        }
    }

    fn graph_columns(rendered: &str, width: usize) -> String {
        rendered
            .lines()
            .map(|line| line.chars().take(width).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn audit_regression_model() -> DfdModel {
        DfdModel {
            zones: vec!["edge".into(), "gateway".into(), "data".into()],
            nodes: audit_nodes(),
            flows: audit_flows(),
            empty_hint: None,
            ..Default::default()
        }
    }

    fn audit_nodes() -> Vec<DfdNodeModel> {
        let mut nodes = vec![node("browser", "edge")];
        nodes.extend(
            [
                "gateway",
                "map",
                "Account mapping service",
                "svc",
                "worker-4",
                "worker-5",
                "worker-6",
                "worker-7",
                "worker-8",
            ]
            .into_iter()
            .map(|name| node(name, "gateway")),
        );
        nodes.extend(
            ["postgres", "cache", "audit"]
                .into_iter()
                .map(|name| node(name, "data")),
        );
        nodes
    }

    fn audit_flows() -> Vec<DfdFlowModel> {
        let endpoints = [
            ("browser", "gateway"),
            ("gateway", "map"),
            ("gateway", "svc"),
            ("svc", "postgres"),
            ("map", "cache"),
            ("worker-4", "audit"),
            ("worker-5", "worker-6"),
            ("map", "worker-8"),
            ("worker-6", "worker-7"),
            ("worker-7", "postgres"),
            ("cache", "audit"),
        ];
        endpoints
            .into_iter()
            .enumerate()
            .map(|(index, (from, to))| audit_flow(index, from, to))
            .collect()
    }

    fn audit_flow(index: usize, from: &str, to: &str) -> DfdFlowModel {
        DfdFlowModel {
            key: format!("flow-{}", index + 1),
            from_id: from.into(),
            to_id: to.into(),
            from: from.into(),
            to: to.into(),
            crosses: index < 8,
            label: format!("flow description {}", index + 1),
            boundary_ids: (index < 8)
                .then(|| format!("tb-{}", index + 1))
                .into_iter()
                .collect(),
        }
    }
}
