//! Data-flow diagram: one trust-zone panel per zone (sized to the width),
//! rounded node boxes stacked inside, joined by crisp orthogonal connectors
//! routed between node anchors. Boundary-crossing flows are amber + arrowed;
//! in-zone flows are muted. Driven by the real threat-model `DfdModel`.

use super::*;
use crate::theme;
use crate::ui_view_models::{DfdKind, DfdModel, DfdNodeModel};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::widgets::Widget;
use std::collections::HashMap;

const GAP: u16 = 2;
const NODE_H: u16 = 3;
const NODE_VGAP: u16 = 1;
const MAX_NODES_PER_ZONE: usize = 4;

pub(crate) struct DfdDiagram {
    pub model: DfdModel,
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

impl Widget for DfdDiagram {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 24 {
            return;
        }
        if let Some(hint) = &self.model.empty_hint {
            text(buf, area, 2, 1, hint, theme::T_MUTED);
            return;
        }
        let zone_count = self.model.zones.len().max(1) as u16;
        let zone_w = (area.width.saturating_sub((zone_count - 1) * GAP)) / zone_count;
        // Reserve 4 rows below the panels (1 gap + 2 legend lines + 1 so the
        // last legend row stays inside the area); otherwise the second legend
        // line is silently clipped at the common pane heights (≤ 24 rows).
        let zone_h = area.height.saturating_sub(4).clamp(9, 21);
        let zx = |i: u16| i * (zone_w + GAP);

        self.draw_zone_panels(buf, area, zone_w, zone_h, &zx);
        let nbw = zone_w.saturating_sub(2).clamp(8, 24);
        let anchors = self.place_nodes(buf, area, zone_w, zone_h, nbw, &zx);
        self.draw_flows(buf, area, &anchors);
        self.draw_legend(buf, area, zone_h + 2);
    }
}

impl DfdDiagram {
    /// One titled trust-zone panel per zone, laid out across the width.
    fn draw_zone_panels(&self, buf: &mut Buffer, area: Rect, zone_w: u16, zone_h: u16, zx: &impl Fn(u16) -> u16) {
        for (i, zone) in self.model.zones.iter().enumerate() {
            panel(buf, area, zx(i as u16), 1, zone_w, zone_h, &zone.to_uppercase(), theme::T_SUBTLE);
        }
    }

    /// Route a connector for every flow whose endpoints both have anchors.
    fn draw_flows(&self, buf: &mut Buffer, area: Rect, anchors: &HashMap<String, Anchor>) {
        for flow in &self.model.flows {
            if let (Some(a), Some(b)) = (anchors.get(&flow.from), anchors.get(&flow.to)) {
                draw_flow(buf, area, a, b, flow_color(flow.crosses));
            }
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
            theme::T_PRIMARY,
        );
        text(buf, area, 2, legend_y + 1, "amber ▶ = trust-boundary crossing · grey = in-zone", theme::T_MUTED);
    }

    /// Draw each zone's node boxes (stacked, vertically centred) and return their
    /// anchors keyed by node name for connector routing.
    fn place_nodes(
        &self,
        buf: &mut Buffer,
        area: Rect,
        zone_w: u16,
        zone_h: u16,
        nbw: u16,
        zx: &impl Fn(u16) -> u16,
    ) -> HashMap<String, Anchor> {
        let mut anchors = HashMap::new();
        for (zi, zone) in self.model.zones.iter().enumerate() {
            let cx = zx(zi as u16) + zone_w / 2;
            let left = cx.saturating_sub(nbw / 2);
            let nodes: Vec<&DfdNodeModel> = self
                .model
                .nodes
                .iter()
                .filter(|n| &n.zone == zone)
                .take(MAX_NODES_PER_ZONE)
                .collect();
            let span = nodes.len() as u16 * (NODE_H + NODE_VGAP);
            let mut y = 2 + zone_h.saturating_sub(2).saturating_sub(span) / 2;
            for node in nodes {
                let color = node_color(node.kind);
                boxed(buf, area, left, y, nbw, NODE_H, &node_label(node), color, color);
                anchors.insert(
                    node.name.clone(),
                    Anchor { col: zi, cx, top: y, bottom: y + NODE_H - 1, left, right: left + nbw },
                );
                y += NODE_H + NODE_VGAP;
            }
        }
        anchors
    }
}

fn draw_flow(buf: &mut Buffer, area: Rect, a: &Anchor, b: &Anchor, color: Color) {
    use std::cmp::Ordering::{Equal, Greater, Less};
    match a.col.cmp(&b.col) {
        Less => connector_h(buf, area, (a.right, a.mid()), (b.left, b.mid()), color),
        // Back-flow: draw left→right between the boxes (arrow lands on the
        // right-hand node) — direction is approximate for the rarer reverse flows.
        Greater => connector_h(buf, area, (b.right, b.mid()), (a.left, a.mid()), color),
        Equal if a.top <= b.top => connector_v(buf, area, (a.cx, a.bottom + 1), (b.cx, b.top), color),
        Equal => connector_v(buf, area, (b.cx, b.bottom + 1), (a.cx, a.top), color),
    }
}

fn node_label(node: &DfdNodeModel) -> String {
    let glyph = match node.kind {
        DfdKind::Entity => "◆",
        DfdKind::Process => "▸",
        DfdKind::Store => "▣",
    };
    format!("{glyph} {}", node.name)
}

fn node_color(kind: DfdKind) -> Color {
    match kind {
        DfdKind::Entity => theme::T_LABEL,
        DfdKind::Process => theme::T_ACCENT,
        DfdKind::Store => theme::SEV_HIGH,
    }
}

fn flow_color(crosses: bool) -> Color {
    if crosses {
        theme::SEV_HIGH
    } else {
        theme::T_MUTED
    }
}
