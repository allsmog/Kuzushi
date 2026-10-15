use super::*;
use crate::app::ToolOptionEdit;

pub(super) fn render_option_edit(frame: &mut Frame<'_>, area: Rect, edit: &ToolOptionEdit) {
    let scope = if edit.global { "global" } else { "session" };
    let title = format!(
        " EDIT {} · {scope} ",
        crate::ui_view_models::option_display_name(&edit.option)
    );
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let error = error_lines(edit, inner.width as usize);
    let (field, error_area, controls) = edit_regions(inner, error.len());
    let lines = crate::renderer::shared::field_editor_lines(
        &edit.field,
        field.width as usize,
        field.height as usize,
    );
    frame.render_widget(Paragraph::new(lines), field);
    render_edit_error(frame, error_area, edit, error);
    render_edit_controls(frame, controls, edit);
}

fn edit_regions(area: Rect, errors: usize) -> (Rect, Rect, Rect) {
    let controls = area.height.saturating_sub(1).min(2);
    let error_height = errors.min(usize::from(area.height.saturating_sub(controls + 1))) as u16;
    let field = Rect {
        height: area.height.saturating_sub(controls + error_height),
        ..area
    };
    let error = Rect {
        y: field.bottom(),
        height: error_height,
        ..area
    };
    let controls = Rect {
        y: error.bottom(),
        height: controls,
        ..area
    };
    (field, error, controls)
}

fn error_lines(edit: &ToolOptionEdit, width: usize) -> Vec<Line<'static>> {
    edit.error
        .iter()
        .flat_map(|error| wrap_text(error, width.max(1)))
        .map(Line::raw)
        .collect()
}

pub(crate) fn option_error_page_bounds(app: &ShellApp) -> (usize, usize) {
    let Some(edit) = app.router.options_browser().edit.as_ref() else {
        return (1, 0);
    };
    let area = Block::default()
        .borders(Borders::ALL)
        .inner(option_browser_area(app));
    let total = error_lines(edit, area.width as usize).len();
    let (_, error, _) = edit_regions(area, total);
    let page = usize::from(error.height).max(1);
    (page, total.saturating_sub(page))
}

fn render_edit_error(
    frame: &mut Frame<'_>,
    area: Rect,
    edit: &ToolOptionEdit,
    lines: Vec<Line<'static>>,
) {
    let offset = edit
        .error_scroll
        .min(lines.len().saturating_sub(area.height as usize));
    let visible = lines
        .into_iter()
        .skip(offset)
        .take(area.height as usize)
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible).style(theme::danger()), area);
}

fn render_edit_controls(frame: &mut Frame<'_>, area: Rect, edit: &ToolOptionEdit) {
    let save = if edit.global {
        "Enter/Ctrl+S save globally"
    } else {
        "Enter/Ctrl+S save session"
    };
    let lines = vec![
        Line::raw(save),
        Line::raw("Ctrl+G global · Esc keeps draft"),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}
