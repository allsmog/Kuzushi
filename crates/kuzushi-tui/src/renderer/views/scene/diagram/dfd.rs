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
    dfd_selected_item, DfdFlowModel, DfdKind, DfdModel, DfdNodeModel, DfdSelected,
};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};
use std::collections::HashMap;

const GAP: u16 = 2;
const NODE_H: u16 = 3;
const NODE_VGAP: u16 = 1;
const DETAIL_GAP: u16 = 1;
const WIDE_DETAIL_MIN: u16 = 96;
/// Nodes shown per zone page; denser zones page (anchored to the selection)
/// instead of silently dropping topology.
const ZONE_PAGE_SIZE: usize = 4;

pub(crate) struct DfdDiagram {
    pub model: DfdModel,
    /// Inspector cursor over the flattened nodes-then-flows order;
    /// `None` renders the plain diagram without highlight or inspector.
    pub selection: Option<usize>,
    /// Requested first row in the wrapped inspector panel.
    pub detail_scroll: usize,
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

impl Widget for DfdDiagram {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if let Some(hint) = &self.model.empty_hint {
            let (hint, guidance) = dfd_empty_copy(area.width, hint);
            render_empty_state_panel(
                buf,
                area,
                "no data-flow diagram",
                hint,
                &[("threat-model:build", guidance)],
            );
            return;
        }
        if self.selection.is_none() {
            self.draw_graph(buf, area);
            return;
        }
        let (graph_area, detail_area) = dfd_regions(area);
        if let Some(graph_area) = graph_area {
            self.draw_graph(buf, graph_area);
        }
        self.draw_detail_panel(buf, detail_area);
    }
}

fn dfd_regions(area: Rect) -> (Option<Rect>, Rect) {
    if area.width < 24 || area.height < 12 {
        return (None, area);
    }
    if area.width >= WIDE_DETAIL_MIN {
        return wide_dfd_regions(area);
    }
    stacked_dfd_regions(area)
}

fn wide_dfd_regions(area: Rect) -> (Option<Rect>, Rect) {
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
    (Some(graph), detail)
}

fn stacked_dfd_regions(area: Rect) -> (Option<Rect>, Rect) {
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
    (Some(graph), detail)
}

impl DfdDiagram {
    fn draw_graph(&self, buf: &mut Buffer, area: Rect) {
        let zone_count = self.model.zones.len().max(1) as u16;
        let zone_w = (area.width.saturating_sub((zone_count - 1) * GAP)) / zone_count;
        if zone_w < 8 || area.height < 10 {
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
        let zone_h = area.height.saturating_sub(2);
        let zx = |i: u16| i * (zone_w + GAP);

        self.draw_zone_panels(buf, area, zone_w, zone_h, &zx);
        let nbw = zone_w.saturating_sub(2).clamp(8, 24);
        let (placements, notes) = self.layout_nodes(zone_w, zone_h, nbw, &zx);
        let anchors = anchor_map(&self.model, &placements, nbw);
        self.draw_flows(buf, area, &anchors);
        self.draw_node_boxes(buf, area, &placements, nbw);
        draw_page_notes(buf, area, &notes);
        self.draw_legend(buf, area, zone_h + 1);
    }
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
        zx: &impl Fn(u16) -> u16,
    ) {
        for (i, zone) in self.model.zones.iter().enumerate() {
            panel(
                buf,
                area,
                zx(i as u16),
                1,
                zone_w,
                zone_h,
                &zone.to_uppercase(),
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
        zx: &impl Fn(u16) -> u16,
    ) -> (Vec<NodePlacement>, Vec<PageNote>) {
        let mut placements = Vec::new();
        let mut notes = Vec::new();
        for (zi, zone) in self.model.zones.iter().enumerate() {
            let cx = zx(zi as u16) + zone_w / 2;
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
        let gap = node_vertical_gap(available, visible.node_indices.len());
        let span = node_span(visible.node_indices.len(), gap);
        let mut y = 2 + available.saturating_sub(span) / 2;
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
        self.selection.filter(|selected| indices.contains(selected))
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
        self.selected_flow_index()
            .and_then(|index| self.model.flows.get(index))
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
        self.selection
            .and_then(|selected| selected.checked_sub(self.model.nodes.len()))
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
            let selected = self.selection == Some(placement.node_index);
            draw_node_box(buf, area, node, placement, nbw, selected);
        }
    }

    /// Node/flow/crossing and selection counts below the zone panels.
    fn draw_legend(&self, buf: &mut Buffer, area: Rect, legend_y: u16) {
        let crossings = self.model.flows.iter().filter(|f| f.crosses).count();
        let total = self.model.nodes.len() + self.model.flows.len();
        let legend = legend_text(&self.model, self.selection, crossings, total);
        text(buf, area, 2, legend_y, &legend, diagram_primary());
    }

    fn draw_detail_panel(&self, buf: &mut Buffer, area: Rect) {
        let width = area.width.saturating_sub(2) as usize;
        let detail = selected_detail_content(&self.model, self.selection, width);
        let viewport = area.height.saturating_sub(2) as usize;
        let max_scroll = detail.lines.len().saturating_sub(viewport);
        let scroll = self.detail_scroll.min(max_scroll);
        let total = self.model.nodes.len() + self.model.flows.len();
        let selected = selected_position(self.selection, total);
        let title = detail_panel_title(detail.kind, selected, total, scroll, max_scroll);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(diagram_style(diagram_subtle()))
            .title(Span::styled(title, diagram_style(selection_color())));
        Paragraph::new(detail.lines)
            .block(block)
            .scroll((scroll.min(u16::MAX as usize) as u16, 0))
            .render(area, buf);
    }
}

fn legend_text(
    model: &DfdModel,
    selection: Option<usize>,
    crossings: usize,
    total: usize,
) -> String {
    let counts = format!(
        "{} nodes · {} flows · {crossings} boundary crossings",
        model.nodes.len(),
        model.flows.len()
    );
    selection.map_or(counts.clone(), |index| {
        format!(
            "{counts} · selected {}/{total} · j/k select",
            selected_position(Some(index), total)
        )
    })
}

fn selected_position(selection: Option<usize>, total: usize) -> usize {
    if total == 0 {
        return 0;
    }
    selection.map_or(0, |index| index.min(total - 1) + 1)
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
    selected: bool,
) {
    let color = node_color(node.kind);
    let border = if selected { selection_color() } else { color };
    clear_rect(buf, area, placement.left, placement.y, nbw, NODE_H);
    boxed(
        buf,
        area,
        placement.left,
        placement.y,
        nbw,
        NODE_H,
        &node_label(node),
        border,
        color,
    );
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
        // Back-flow: draw left→right between the boxes (arrow lands on the
        // right-hand node) — direction is approximate for the rarer reverse flows.
        Greater => connector_h(buf, area, (b.right, b.mid()), (a.left, a.mid()), color),
        Equal if a.top <= b.top => {
            connector_v(buf, area, (a.cx, a.bottom + 1), (b.cx, b.top), color)
        }
        Equal => connector_v(buf, area, (b.cx, b.bottom + 1), (a.cx, a.top), color),
    }
}

fn selected_detail_content(
    model: &DfdModel,
    selection: Option<usize>,
    width: usize,
) -> DetailContent {
    match selection.and_then(|index| dfd_selected_item(model, index)) {
        Some(DfdSelected::Node(node)) => node_detail_content(node, width),
        Some(DfdSelected::Flow(flow)) => flow_detail_content(flow, width),
        None => DetailContent {
            kind: "item",
            lines: vec![Line::styled(
                "j/k or ↑/↓ selects every node and flow",
                crate::theme::muted(),
            )],
        },
    }
}

fn node_detail_content(node: &DfdNodeModel, width: usize) -> DetailContent {
    let mut lines = Vec::new();
    append_detail_lines(&mut lines, "name", &node.name, width);
    append_detail_lines(&mut lines, "type", kind_label(node.kind), width);
    append_detail_lines(&mut lines, "zone", &node.zone, width);
    DetailContent {
        kind: "node",
        lines,
    }
}

fn flow_detail_content(flow: &DfdFlowModel, width: usize) -> DetailContent {
    let mut lines = Vec::new();
    append_detail_lines(&mut lines, "from", &flow.from, width);
    append_detail_lines(&mut lines, "to", &flow.to, width);
    append_detail_lines(&mut lines, "description", nonempty(&flow.label), width);
    append_detail_lines(&mut lines, "boundaries", &boundary_detail(flow), width);
    append_detail_lines(&mut lines, "routing", crossing_detail(flow), width);
    DetailContent {
        kind: "flow",
        lines,
    }
}

fn append_detail_lines(lines: &mut Vec<Line<'static>>, key: &str, value: &str, width: usize) {
    let key_width = width.min(13);
    let value_width = width.saturating_sub(key_width).max(1);
    let chunks = crate::renderer::shared::text::wrap_text(value, value_width);
    for (index, chunk) in chunks.into_iter().enumerate() {
        let label = if index == 0 {
            format!("{key:<key_width$}")
        } else {
            " ".repeat(key_width)
        };
        lines.push(Line::from(vec![
            Span::styled(label, crate::theme::muted()),
            Span::styled(chunk, crate::theme::primary()),
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

    #[test]
    fn selected_position_is_one_based_and_clamped_to_the_available_items() {
        assert_eq!(selected_position(Some(0), 3), 1);
        assert_eq!(selected_position(Some(usize::MAX), 3), 3);
        assert_eq!(selected_position(Some(0), 0), 0);
    }

    #[test]
    fn compact_layout_boundary_preserves_the_graph_when_space_is_sufficient() {
        let compact = Rect::new(0, 0, 23, 12);
        let available = Rect::new(0, 0, 24, 12);

        assert_eq!(dfd_regions(compact), (None, compact));
        assert!(dfd_regions(available).0.is_some());
    }

    #[test]
    fn mutation_survivor_stacked_layout_reserves_detail_height_below_graph() {
        let area = Rect::new(3, 4, 80, 20);
        let (graph, detail) = stacked_dfd_regions(area);

        assert_eq!(graph, Some(Rect::new(3, 4, 80, 14)));
        assert_eq!(detail, Rect::new(3, 19, 80, 5));
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
            zone: zone.into(),
            kind: DfdKind::Process,
        }
    }

    fn flow(from: &str, to: &str, label: &str) -> DfdFlowModel {
        DfdFlowModel {
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
        };
        let rendered = render_to_text(
            DfdDiagram {
                model,
                selection: None,
                detail_scroll: 0,
            },
            72,
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
        };
        let first_page = render_to_text(
            DfdDiagram {
                model: model.clone(),
                selection: None,
                detail_scroll: 0,
            },
            40,
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
            },
            40,
            30,
        );
        assert!(second_page.contains("page 2/2 · +4 more"), "{second_page}");
        assert!(second_page.contains("◇ n5"));
        assert!(!second_page.contains("◇ n1"));
    }

    #[test]
    fn inspector_panel_names_the_selected_node_and_flow() {
        let model = DfdModel {
            zones: vec!["a".into(), "b".into()],
            nodes: vec![node("web", "a"), node("db", "b")],
            flows: vec![flow("web", "db", "sql")],
            empty_hint: None,
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
        let total = model.nodes.len() + model.flows.len();

        for selection in 0..total {
            let rendered = render_selection(&model, selection, 0, 120, 36);
            assert!(
                rendered.contains(&format!("selected {}/{total}", selection + 1)),
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
        assert!(same_zone.contains("8 boundary crossings"), "{same_zone}");
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
        }
    }

    fn audit_nodes() -> Vec<DfdNodeModel> {
        let mut nodes = vec![node("browser", "edge")];
        nodes.extend(
            [
                "gateway",
                "map",
                "Account mapping service",
                "services",
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
            ("gateway", "services"),
            ("services", "postgres"),
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
