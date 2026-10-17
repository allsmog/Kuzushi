//! Retain logical text positions through gallery resize without reading files.
use super::gallery::{page_body_rows, scene_line_page_body_height};
use crate::app::GalleryReadingPosition;
use crate::scene3d::VizPage;
use crate::ui_view_models::PhaseSurfaceId;
use crate::{ShellApp, ShellView};
use ratatui::layout::Rect;

struct LineCanvas {
    embedded: bool,
    page: VizPage,
    area: Rect,
    visible: u16,
    offset: u16,
}

pub(crate) fn capture_gallery_reading(app: &ShellApp) -> Option<GalleryReadingPosition> {
    let canvas = line_canvas(app)?;
    let rows = page_body_rows(app, canvas.area, canvas.page);
    let remembered = app.ui().gallery_reading().filter(|position| {
        position.embedded == canvas.embedded
            && position.page == canvas.page
            && position.offset == canvas.offset
    });
    let retained = remembered.filter(|position| {
        rows.restore_reading(canvas.visible, position.anchor)
            .is_some()
    });
    let anchor = retained
        .map(|position| position.anchor)
        .or_else(|| rows.reading_anchor(canvas.visible, canvas.offset as usize))?;
    Some(GalleryReadingPosition {
        embedded: canvas.embedded,
        page: canvas.page,
        offset: canvas.offset,
        anchor,
    })
}

pub(crate) fn restore_gallery_reading(
    app: &mut ShellApp,
    position: Option<GalleryReadingPosition>,
) {
    let restored = position.and_then(|position| reflow_position(app, position));
    if let Some(position) = restored {
        set_gallery_offset(app, position.embedded, position.offset);
    }
    app.ui_mut().set_gallery_reading(restored);
}

fn reflow_position(
    app: &ShellApp,
    mut position: GalleryReadingPosition,
) -> Option<GalleryReadingPosition> {
    let canvas = line_canvas(app)?;
    if position.embedded != canvas.embedded || position.page != canvas.page {
        return None;
    }
    let rows = page_body_rows(app, canvas.area, canvas.page);
    let offset = rows.restore_reading(canvas.visible, position.anchor)?;
    position.offset = offset.min(u16::MAX as usize) as u16;
    Some(position)
}

pub(crate) fn gallery_line_offset(app: &ShellApp, amount: i32) -> Option<u16> {
    let canvas = line_canvas(app)?;
    let rows = page_body_rows(app, canvas.area, canvas.page);
    let current = rows.normalized_scroll(canvas.visible, canvas.offset as usize);
    let next = current.saturating_add_signed(amount as isize);
    Some(
        rows.normalized_scroll(canvas.visible, next)
            .min(u16::MAX as usize) as u16,
    )
}

fn line_canvas(app: &ShellApp) -> Option<LineCanvas> {
    let (embedded, page) = match app.shell_view() {
        ShellView::Scene => (false, app.router.scene().page()),
        ShellView::Workbench => (true, app.current_map_viz_page()),
        _ => return None,
    };
    if page.is_frame_rendered() {
        return None;
    }
    canvas_geometry(app, embedded, page)
}

fn canvas_geometry(app: &ShellApp, embedded: bool, page: VizPage) -> Option<LineCanvas> {
    if embedded {
        let area = super::gallery_layout::gallery_body_area(app)?;
        return Some(LineCanvas {
            embedded,
            page,
            area,
            visible: area.height,
            offset: app.router.workbench().scroll().get(PhaseSurfaceId::MapDfd),
        });
    }
    let viewport = app.viewport();
    let area = crate::renderer::workbench_primary_area(
        app,
        Rect::new(0, 0, viewport.columns, viewport.rows),
    );
    Some(LineCanvas {
        embedded,
        page,
        area,
        visible: scene_line_page_body_height(app, area),
        offset: app.router.default_scroll().offset(),
    })
}

fn set_gallery_offset(app: &mut ShellApp, embedded: bool, offset: u16) {
    if embedded {
        app.router
            .workbench_mut()
            .scroll_mut()
            .set(PhaseSurfaceId::MapDfd, offset);
    } else {
        app.router.default_scroll_mut().set(offset);
    }
}

#[cfg(test)]
mod tests;
