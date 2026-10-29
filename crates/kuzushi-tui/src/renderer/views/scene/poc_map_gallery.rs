//! TEMPORARY — threat-revisions PoC hook (feature `threat-revisions-poc`).
//!
//! Exposes the real Map Summary and DFD widgets for an arbitrary threat-model
//! document so `examples/threat_revisions_poc.rs` renders the genuine Map
//! gallery for whichever revision is active. Delete with the PoC.

use super::diagram::{DfdDiagram, DfdSummary};
use crate::ui_view_models::{
    dfd_model_from_doc, dfd_overview, dfd_overview_component_count, dfd_selectable_count,
};
use ratatui::buffer::Buffer;
use ratatui::text::Line;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapGalleryPage {
    Summary,
    Dfd,
}

/// Cursor bounds for a page: Summary components, or flattened DFD elements.
pub fn selectable_count(page: MapGalleryPage, doc: Option<&Value>) -> usize {
    let model = dfd_model_from_doc(doc, None);
    match page {
        MapGalleryPage::Summary => dfd_overview_component_count(&dfd_overview(&model)),
        MapGalleryPage::Dfd => dfd_selectable_count(&model),
    }
}

pub fn render_map_gallery(
    page: MapGalleryPage,
    doc: Option<&Value>,
    target: Option<&Path>,
    selection: usize,
    area: Rect,
    buf: &mut Buffer,
) {
    let model = dfd_model_from_doc(doc, target);
    match page {
        MapGalleryPage::Summary => DfdSummary {
            model,
            component_selection: selection,
            scroll: 0,
        }
        .render(area, buf),
        MapGalleryPage::Dfd => DfdDiagram {
            model,
            selection: Some(selection),
            detail_scroll: 0,
            focused: false,
            context_selection: 0,
        }
        .render(area, buf),
    }
}

/// The shell's own markdown projection (headings, tables, lists).
pub fn markdown_lines(text: &str, width: usize) -> Vec<Line<'static>> {
    crate::renderer::shared::markdown::answer_markdown(text, width)
}
