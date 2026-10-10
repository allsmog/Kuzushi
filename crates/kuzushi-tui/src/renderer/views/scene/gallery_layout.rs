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

/// Splits an embedded line page's canvas into its body and the one row that
/// states the body's position.
pub(super) fn line_page_position_sections(area: Rect) -> [Rect; 2] {
    split_rows(area, [Constraint::Min(0), Constraint::Length(1)])
}
