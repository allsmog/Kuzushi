use super::*;
use crate::ui_view_models::DfdSecurityKind;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

mod causal;
mod stacked;

pub(super) const WIDE_LAYOUT_MIN: u16 = 110;
pub(super) const STACKED_LAYOUT_MIN: u16 = 60;
const FULL_LAYOUT_MIN_HEIGHT: u16 = 16;
const MIN_TOPOLOGY_WIDTH: u16 = 16;
const MIN_TOPOLOGY_HEIGHT: u16 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DfdTopologyLayout {
    WideLanes,
    StackedZones,
    CausalPath,
    DetailOnly,
}

pub(super) fn topology_layout(area: Rect) -> DfdTopologyLayout {
    if area.width < MIN_TOPOLOGY_WIDTH || area.height < MIN_TOPOLOGY_HEIGHT {
        return DfdTopologyLayout::DetailOnly;
    }
    if area.width >= WIDE_LAYOUT_MIN && area.height >= FULL_LAYOUT_MIN_HEIGHT {
        return DfdTopologyLayout::WideLanes;
    }
    if area.width >= STACKED_LAYOUT_MIN && area.height >= FULL_LAYOUT_MIN_HEIGHT {
        return DfdTopologyLayout::StackedZones;
    }
    DfdTopologyLayout::CausalPath
}

pub(super) fn render_causal(diagram: &DfdDiagram, buf: &mut Buffer, area: Rect) {
    causal::render(diagram, buf, area);
}

pub(super) fn render_stacked(diagram: &DfdDiagram, buf: &mut Buffer, area: Rect) {
    stacked::render(diagram, buf, area);
}

pub(super) fn compact_content_height(
    diagram: &DfdDiagram,
    layout: DfdTopologyLayout,
    area: Rect,
) -> Option<u16> {
    match layout {
        DfdTopologyLayout::StackedZones => Some(stacked::content_height(diagram, area)),
        DfdTopologyLayout::CausalPath => Some(causal::content_height(diagram, area)),
        DfdTopologyLayout::WideLanes | DfdTopologyLayout::DetailOnly => None,
    }
}

pub(super) fn context_node_label(node: &DfdNodeModel, count: usize) -> String {
    context_name(&node_label(node), count)
}

pub(super) fn context_name(name: &str, count: usize) -> String {
    if count == 0 {
        name.to_string()
    } else {
        format!("{name} +{count}")
    }
}

pub(super) fn security_kind_name(kind: DfdSecurityKind) -> &'static str {
    match kind {
        DfdSecurityKind::EntryPoint => "entry",
        DfdSecurityKind::RoleGate => "gates",
        DfdSecurityKind::ExternalSink => "sinks",
        DfdSecurityKind::TrustedCaller => "callers",
        DfdSecurityKind::Asset => "assets",
        DfdSecurityKind::Threat => "threats",
    }
}
