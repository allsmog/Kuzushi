//! Keyboard reading measures the same selected detail pane as rendering.
use super::*;

pub(crate) struct DfdDetailScroll {
    pub(crate) page_rows: usize,
    pub(crate) max_offset: usize,
}

pub(super) fn detail_scroll_bounds(lines: usize, rows: usize) -> DfdDetailScroll {
    DfdDetailScroll {
        page_rows: rows.max(1),
        max_offset: lines.saturating_sub(rows),
    }
}

impl DfdDiagram {
    pub(crate) fn detail_scroll_bounds(&self, area: Rect) -> Option<DfdDetailScroll> {
        if !self.allows_detail_reading() {
            return None;
        }
        let layout = responsive::topology_layout(area);
        let detail = positioned_detail_area(self, area, layout, dfd_regions(area, layout))?;
        if detail.height < 3 {
            let content =
                selected_detail_content(&self.model, self.selection, detail.width as usize);
            return Some(detail_scroll_bounds(
                content.lines.len(),
                detail.height as usize,
            ));
        }
        let content =
            self.panel_detail_content(detail, layout == responsive::DfdTopologyLayout::DetailOnly);
        let viewport = compact_detail_area(detail, content.lines.len())
            .height
            .saturating_sub(2);
        Some(detail_scroll_bounds(content.lines.len(), viewport as usize))
    }

    fn allows_detail_reading(&self) -> bool {
        !self.focused && self.selection.is_some() && self.model.empty_hint.is_none()
    }

    pub(super) fn panel_detail_content(&self, area: Rect, resize_hint: bool) -> DetailContent {
        let width = area.width.saturating_sub(2) as usize;
        let mut content = selected_detail_content(&self.model, self.selection, width);
        prepend_resize_hint(&mut content.lines, width, resize_hint);
        append_legacy_context_detail(&mut content.lines, &self.model, width);
        content
    }
}
