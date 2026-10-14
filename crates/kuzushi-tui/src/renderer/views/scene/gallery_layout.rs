//! Shared geometry for gallery rendering and keyboard paging.
use super::line_page::PageDirection;
use crate::{ShellApp, ShellView};
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};

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

pub(super) fn gallery_body_area(app: &ShellApp) -> Option<Rect> {
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    match app.shell_view() {
        ShellView::Workbench => embedded_gallery_body_area(app, full),
        ShellView::Scene => {
            Some(gallery_sections(crate::renderer::workbench_primary_area(app, full), false)[1])
        }
        _ => None,
    }
}

fn embedded_gallery_body_area(app: &ShellApp, full: Rect) -> Option<Rect> {
    let plan = crate::renderer::workbench_phase_plan_for_app(app, full)?;
    let canvas = plan.surface(crate::ui_view_models::PhaseSurfaceId::MapDfd)?;
    let gallery = map_canvas_sections(canvas.rect)[0];
    Some(gallery_sections(gallery, true)[1])
}

pub(super) fn summary_document_area(area: Rect) -> Rect {
    if area.height <= 4 {
        return area;
    }
    area.inner(Margin::new(1, 1))
}

pub(crate) fn summary_page_rows(app: &ShellApp) -> Option<usize> {
    let area = gallery_body_area(app)?;
    Some(super::diagram::summary_reading_rows(
        area,
        &crate::ui_view_models::dfd_model(app),
    ))
}

/// The rows PgUp/PgDn move a full-frame line page by: the step to the
/// adjacent window of whole rows on the canvas the viewport draws, so paging
/// neither skips nor repeats a row however the rows wrap.
pub(crate) fn scene_page_rows(app: &ShellApp, direction: PageDirection) -> Option<usize> {
    if app.shell_view() != ShellView::Scene {
        return None;
    }
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    let area = crate::renderer::workbench_primary_area(app, full);
    let scroll = usize::from(app.router.default_scroll().offset());
    super::gallery::scene_line_page_step(app, area, scroll, direction)
}

/// The rows PgUp/PgDn move Map's embedded line page by, measured on the same
/// gallery body the embedded canvas draws.
pub(crate) fn map_gallery_page_rows(app: &ShellApp, direction: PageDirection) -> Option<usize> {
    if app.shell_view() != ShellView::Workbench {
        return None;
    }
    let area = gallery_body_area(app)?;
    let scroll = app
        .router
        .workbench()
        .scroll()
        .get(crate::ui_view_models::PhaseSurfaceId::MapDfd);
    super::gallery::embedded_line_page_step(app, area, usize::from(scroll), direction)
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
    fn line_gallery_paging_is_only_measured_for_a_line_page_in_its_own_view() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::Scene);
        app.router
            .scene_mut()
            .set_page(crate::scene3d::VizPage::Dfd);
        assert_eq!(scene_page_rows(&app, PageDirection::Down), None);
        app.router
            .scene_mut()
            .set_page(crate::scene3d::VizPage::Components);
        assert!(scene_page_rows(&app, PageDirection::Down).is_some());
        assert_eq!(map_gallery_page_rows(&app, PageDirection::Down), None);
        app.set_shell_view(ShellView::Context);
        assert_eq!(scene_page_rows(&app, PageDirection::Down), None);
    }
}
