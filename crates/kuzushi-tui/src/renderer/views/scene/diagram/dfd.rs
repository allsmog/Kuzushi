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
use ratatui::widgets::Widget;
use std::collections::HashMap;

const GAP: u16 = 2;
const NODE_H: u16 = 3;
const NODE_VGAP: u16 = 1;
/// Nodes shown per zone page; denser zones page (anchored to the selection)
/// instead of silently dropping topology.
const ZONE_PAGE_SIZE: usize = 4;

pub(crate) struct DfdDiagram {
    pub model: DfdModel,
    /// Inspector cursor over the flattened nodes-then-flows order;
    /// `None` renders the plain diagram without highlight or inspector.
    pub selection: Option<usize>,
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

impl Widget for DfdDiagram {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 24 {
            text(
                buf,
                area,
                1,
                0,
                "widen terminal (≥24 cols) for the diagram",
                diagram_muted(),
            );
            return;
        }
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
        let zone_count = self.model.zones.len().max(1) as u16;
        let zone_w = (area.width.saturating_sub((zone_count - 1) * GAP)) / zone_count;
        // Reserve 6 rows below the panels: 1 gap + 2 legend + 2 inspector + 1
        // so the last inspector row stays inside the area.
        let zone_h = area.height.saturating_sub(6).max(9);
        let zx = |i: u16| i * (zone_w + GAP);

        self.draw_zone_panels(buf, area, zone_w, zone_h, &zx);
        let nbw = zone_w.saturating_sub(2).clamp(8, 24);
        let (placements, notes) = self.layout_nodes(zone_w, zone_h, nbw, &zx);
        let anchors = anchor_map(&self.model, &placements, nbw);
        self.draw_flows(buf, area, &anchors);
        self.draw_node_boxes(buf, area, &placements, nbw);
        draw_page_notes(buf, area, &notes);
        self.draw_legend(buf, area, zone_h + 2);
        self.draw_inspector(buf, area, zone_h + 4);
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
        let page = self.zone_page(&indices);
        let visible = page_slice(&indices, page);
        let span = visible.len() as u16 * (NODE_H + NODE_VGAP);
        let mut y = 2 + zone_h.saturating_sub(2).saturating_sub(span) / 2;
        for &node_index in visible {
            placements.push(NodePlacement {
                node_index,
                zi,
                cx,
                left,
                y,
            });
            y += NODE_H + NODE_VGAP;
        }
        push_page_note(notes, &indices, visible.len(), page, left, y);
    }

    /// A zone shows the page containing the selected node; zones without the
    /// selection show their first page.
    fn zone_page(&self, indices: &[usize]) -> usize {
        self.selection
            .and_then(|selected| indices.iter().position(|&index| index == selected))
            .map_or(0, |position| position / ZONE_PAGE_SIZE)
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

    /// Node/flow/crossing counts plus the colour key, below the zone panels.
    fn draw_legend(&self, buf: &mut Buffer, area: Rect, legend_y: u16) {
        let crossings = self.model.flows.iter().filter(|f| f.crosses).count();
        text(
            buf,
            area,
            2,
            legend_y,
            &format!(
                "{} nodes · {} flows · {crossings} boundary crossings",
                self.model.nodes.len(),
                self.model.flows.len()
            ),
            diagram_primary(),
        );
        text(
            buf,
            area,
            2,
            legend_y + 1,
            "amber ▶ = trust-boundary crossing · grey = in-zone · j/k select",
            diagram_muted(),
        );
    }

    /// Two-row strip naming the selected node (name · kind · zone) or flow
    /// (from → to · description · boundary ids).
    fn draw_inspector(&self, buf: &mut Buffer, area: Rect, y: u16) {
        let Some(selected) = self.selection else {
            return;
        };
        match dfd_selected_item(&self.model, selected) {
            Some(DfdSelected::Node(node)) => {
                text(
                    buf,
                    area,
                    2,
                    y,
                    &format!("▸ {}", node.name),
                    selection_color(),
                );
                text(buf, area, 2, y + 1, &node_detail(node), diagram_muted());
            }
            Some(DfdSelected::Flow(flow)) => {
                let title = format!("▸ {} → {}", flow.from, flow.to);
                text(buf, area, 2, y, &title, selection_color());
                text(buf, area, 2, y + 1, &flow_detail(flow), diagram_muted());
            }
            None => {}
        }
    }
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

fn push_page_note(
    notes: &mut Vec<PageNote>,
    indices: &[usize],
    visible: usize,
    page: usize,
    x: u16,
    y: u16,
) {
    let pages = indices.len().div_ceil(ZONE_PAGE_SIZE).max(1);
    if pages <= 1 {
        return;
    }
    let hidden = indices.len() - visible;
    notes.push(PageNote {
        x: x.saturating_add(1),
        y,
        text: format!("page {}/{pages} · +{hidden} more", page + 1),
    });
}

fn draw_page_notes(buf: &mut Buffer, area: Rect, notes: &[PageNote]) {
    for note in notes {
        text(buf, area, note.x, note.y, &note.text, diagram_muted());
    }
}

/// Anchors keyed by node name (flows reference display names) for the
/// visible placements only — flows to a paged-out node are simply skipped.
fn anchor_map(model: &DfdModel, placements: &[NodePlacement], nbw: u16) -> HashMap<String, Anchor> {
    placements
        .iter()
        .map(|placement| {
            (
                model.nodes[placement.node_index].name.clone(),
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
    if let (Some(a), Some(b)) = (anchors.get(&flow.from), anchors.get(&flow.to)) {
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

fn node_detail(node: &DfdNodeModel) -> String {
    format!("  {} · zone {}", kind_label(node.kind), node.zone)
}

fn flow_detail(flow: &DfdFlowModel) -> String {
    let boundaries = if flow.boundary_ids.is_empty() {
        if flow.crosses {
            "crosses boundary"
        } else {
            "in-zone"
        }
        .to_string()
    } else {
        format!("boundaries: {}", flow.boundary_ids.join(", "))
    };
    if flow.label.is_empty() {
        format!("  {boundaries}")
    } else {
        format!("  {} · {boundaries}", flow.label)
    }
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
            name: name.into(),
            zone: zone.into(),
            kind: DfdKind::Process,
        }
    }

    fn flow(from: &str, to: &str, label: &str) -> DfdFlowModel {
        DfdFlowModel {
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
            },
            40,
            30,
        );
        assert!(second_page.contains("page 2/2 · +4 more"), "{second_page}");
        assert!(second_page.contains("◇ n5"));
        assert!(!second_page.contains("◇ n1"));
    }

    #[test]
    fn inspector_strip_names_the_selected_node_and_flow() {
        let model = DfdModel {
            zones: vec!["a".into(), "b".into()],
            nodes: vec![node("web", "a"), node("db", "b")],
            flows: vec![flow("web", "db", "sql")],
            empty_hint: None,
        };
        let node_selected = render_to_text(
            DfdDiagram {
                model: model.clone(),
                selection: Some(0),
            },
            60,
            24,
        );
        assert!(node_selected.contains("▸ web"), "{node_selected}");
        assert!(
            node_selected.contains("process · zone a"),
            "{node_selected}"
        );

        let flow_selected = render_to_text(
            DfdDiagram {
                model,
                selection: Some(2),
            },
            60,
            24,
        );
        assert!(flow_selected.contains("▸ web → db"), "{flow_selected}");
        assert!(
            flow_selected.contains("sql · boundaries: tb-1"),
            "{flow_selected}"
        );
    }
}
