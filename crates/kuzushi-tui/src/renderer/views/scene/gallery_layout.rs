//! Shared geometry for gallery rendering and keyboard paging.
use crate::{ShellApp, ShellView};
use ratatui::layout::{Constraint, Direction, Layout, Rect};

pub(in crate::renderer::views) fn map_canvas_sections(area: Rect) -> [Rect; 2] {
    split_rows(area, [Constraint::Min(0), Constraint::Length(1)])
}

pub(super) fn gallery_sections(area: Rect, embedded: bool) -> [Rect; 2] {
    let header = gallery_header_height(area.height, embedded);
    split_rows(area, [Constraint::Length(header), Constraint::Min(0)])
}

fn gallery_header_height(height: u16, embedded: bool) -> u16 {
    if !embedded && height < 12 {
        return 1;
    }
    if embedded {
        2
    } else {
        3
    }
}

fn split_rows(area: Rect, constraints: [Constraint; 2]) -> [Rect; 2] {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);
    [areas[0], areas[1]]
}

pub(super) fn entry_point_browser_area(app: &ShellApp) -> Option<Rect> {
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    match app.shell_view() {
        ShellView::Workbench => embedded_entry_area(app, full),
        ShellView::Scene => {
            Some(gallery_sections(crate::renderer::workbench_primary_area(app, full), false)[1])
        }
        _ => None,
    }
}

fn embedded_entry_area(app: &ShellApp, full: Rect) -> Option<Rect> {
    let plan = crate::renderer::workbench_phase_plan_for_app(app, full)?;
    let canvas = plan.surface(crate::ui_view_models::PhaseSurfaceId::MapDfd)?;
    let gallery = map_canvas_sections(canvas.rect)[0];
    Some(gallery_sections(gallery, true)[1])
}

/// The scrolled window an embedded line page shows, when the page is taller
/// than its canvas. `None` means the page fits and states nothing.
pub(super) struct LinePageWindow {
    pub(super) start: u16,
    pub(super) position_label: String,
}

/// Ratatui clips a `Paragraph` without a word, so an embedded line page that
/// overflows its canvas would hide the rest of the projection silently — the
/// full-frame view discloses the same overflow through
/// `pinned_document_viewport_lines`. Reserve the canvas's last row for that
/// disclosure and clamp the window so scrolling past the end shows the last
/// page rather than an empty canvas.
pub(super) fn line_page_window(
    visible_rows: u16,
    total_rows: usize,
    scroll: u16,
) -> Option<LinePageWindow> {
    let visible = visible_rows as usize;
    if visible == 0 || total_rows <= visible {
        return None;
    }
    let capacity = visible - 1;
    // The body scrolls by a `u16`, so the label must name the window the body
    // can actually reach rather than the one the offset asked for.
    let start = (scroll as usize)
        .min(total_rows - capacity.max(1))
        .min(u16::MAX as usize);
    let position_label = if capacity == 0 {
        format!(" row {}/{total_rows}", start + 1)
    } else {
        format!(" rows {}-{}/{total_rows}", start + 1, start + capacity)
    };
    Some(LinePageWindow {
        start: start as u16,
        position_label,
    })
}

/// Splits an embedded line page's canvas into its body and the one row that
/// states the body's position.
pub(super) fn line_page_position_sections(area: Rect) -> [Rect; 2] {
    split_rows(area, [Constraint::Min(0), Constraint::Length(1)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_that_fits_its_canvas_states_no_position() {
        assert!(line_page_window(24, 24, 0).is_none());
        assert!(line_page_window(0, 9, 0).is_none());
    }

    #[test]
    fn an_overflowing_page_reserves_its_last_row_for_the_row_count() {
        let window = line_page_window(20, 2657, 0).expect("overflowing page");

        assert_eq!(window.start, 0);
        assert_eq!(window.position_label, " rows 1-19/2657");
    }

    #[test]
    fn scrolling_past_the_end_lands_on_the_last_page_not_an_empty_canvas() {
        let window = line_page_window(20, 2657, u16::MAX).expect("overflowing page");

        assert_eq!(window.start, 2638);
        assert_eq!(window.position_label, " rows 2639-2657/2657");
    }

    #[test]
    fn a_single_row_canvas_spends_it_on_the_position() {
        let window = line_page_window(1, 40, 7).expect("overflowing page");

        assert_eq!(window.start, 7);
        assert_eq!(window.position_label, " row 8/40");
    }
}
