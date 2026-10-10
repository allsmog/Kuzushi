use super::*;

pub(crate) fn recommendation_page_rows(app: &ShellApp) -> Option<usize> {
    recommendation_area(app).map(|area| usize::from(area.height).max(1))
}

pub(crate) fn recommendation_max_scroll(app: &ShellApp) -> Option<u16> {
    let area = recommendation_area(app)?;
    let max = recommend_lines(app, area)
        .len()
        .saturating_sub(usize::from(area.height));
    Some(max.min(u16::MAX as usize) as u16)
}

fn recommendation_area(app: &ShellApp) -> Option<Rect> {
    if app.shell_view() != ShellView::Recommend {
        return None;
    }
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    let primary = crate::renderer::primary_body_area(app, full);
    Some(crate::ui_view_models::answers_layout(app, primary).workspace)
}
