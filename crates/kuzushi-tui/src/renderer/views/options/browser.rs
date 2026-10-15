use super::*;
use crate::renderer::shared::text::wrap_text;
use ratatui::widgets::{Block, Borders};

mod editor;
pub(crate) use editor::option_error_page_bounds;
use editor::render_option_edit;

pub(crate) fn option_detail_page_bounds(app: &ShellApp) -> (usize, usize) {
    let rows = app.option_browser_rows();
    let selected = app.selected_browser_option();
    let Some(row) = rows
        .iter()
        .find(|row| Some(&row.cells[0]) == selected.as_ref())
    else {
        return (1, 0);
    };
    let area = option_browser_area(app);
    let body = option_detail_area(area);
    let page = usize::from(body.height.saturating_sub(1)).max(1);
    let total = detail_lines(app, row, body.width as usize).len();
    (page, total.saturating_sub(page))
}

fn option_browser_area(app: &ShellApp) -> Rect {
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    crate::renderer::workbench_primary_area(app, full)
}

fn option_detail_area(area: Rect) -> Rect {
    let body = Rect {
        y: area.y + 1,
        height: area.height.saturating_sub(1),
        ..area
    };
    if body.width < 90 || body.height < 14 {
        return body;
    }
    let list_width = body.width / 3;
    Rect {
        x: body.x + list_width + 1,
        width: body.width.saturating_sub(list_width + 1),
        ..body
    }
}

pub(crate) fn render_options_browser(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if let Some(edit) = app.router.options_browser().edit.as_ref() {
        render_option_edit(frame, area, edit);
        return;
    }
    let model = options_model(app, app.router.options());
    let rows = app.option_browser_rows();
    let selected = app.selected_browser_option();
    let index = rows
        .iter()
        .position(|row| Some(&row.cells[0]) == selected.as_ref())
        .unwrap_or(0);
    let header = browser_header(app, &model);
    frame.render_widget(
        Paragraph::new(fit(&header, area.width as usize)).style(theme::accent()),
        Rect { height: 1, ..area },
    );
    let body = Rect {
        y: area.y + 1,
        height: area.height.saturating_sub(1),
        ..area
    };
    render_option_selection(frame, body, app, &model, &rows, index);
}

fn browser_header(app: &ShellApp, model: &crate::ui_view_models::OptionsModel) -> String {
    let support = model
        .summary_rows
        .iter()
        .find(|row| row.cells[0] == "support")
        .map(|row| format!(" · {}", row.cells[1]))
        .unwrap_or_default();
    let filter = model
        .summary_rows
        .iter()
        .find(|row| row.cells[0] == "view")
        .map(|row| row.cells[1].as_str())
        .unwrap_or("options");
    format!(
        "OPTIONS{support} · {} · {filter}",
        app.router.options().tool_name
    )
}

fn render_option_selection(
    frame: &mut Frame<'_>,
    body: Rect,
    app: &ShellApp,
    model: &crate::ui_view_models::OptionsModel,
    rows: &[OptionsTableRow],
    index: usize,
) {
    if rows.is_empty() {
        render_empty_options(frame, body, &model.body);
        return;
    }
    if body.width >= 90 && body.height >= 14 {
        let list_width = body.width / 3;
        render_option_list(
            frame,
            Rect {
                width: list_width,
                ..body
            },
            rows,
            index,
        );
        let detail = Rect {
            x: body.x + list_width + 1,
            width: body.width.saturating_sub(list_width + 1),
            ..body
        };
        render_option_detail(frame, detail, app, &rows[index], index, rows.len());
        return;
    }
    render_option_detail(frame, body, app, &rows[index], index, rows.len());
}

fn render_option_list(frame: &mut Frame<'_>, area: Rect, rows: &[OptionsTableRow], index: usize) {
    let start =
        crate::renderer::views::viewport_start_for_cursor(rows.len(), area.height as usize, index);
    let lines = rows
        .iter()
        .enumerate()
        .skip(start)
        .take(area.height as usize)
        .map(|(position, row)| {
            let mark = if position == index { "▸" } else { " " };
            let text = fit(
                &format!(
                    "{mark} {}",
                    crate::ui_view_models::option_display_name(&row.cells[0])
                ),
                area.width as usize,
            );
            let style = if position == index {
                theme::accent()
            } else {
                theme::muted()
            };
            Line::styled(text, style)
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_option_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    row: &OptionsTableRow,
    index: usize,
    count: usize,
) {
    if area.height == 0 {
        return;
    }
    let title = format!(
        "{} · {}/{}",
        crate::ui_view_models::option_display_name(&row.cells[0]),
        index + 1,
        count
    );
    frame.render_widget(
        Paragraph::new(fit(&title, area.width as usize)).style(theme::accent()),
        Rect { height: 1, ..area },
    );
    let body = Rect {
        y: area.y + 1,
        height: area.height.saturating_sub(1),
        ..area
    };
    render_detail_body(frame, body, app, row);
}

fn render_detail_body(frame: &mut Frame<'_>, body: Rect, app: &ShellApp, row: &OptionsTableRow) {
    let lines = detail_lines(app, row, body.width as usize);
    let scroll = app
        .router
        .options_browser()
        .detail_scroll
        .min(lines.len().saturating_sub(body.height as usize));
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(scroll)
                .take(body.height as usize)
                .collect::<Vec<_>>(),
        ),
        body,
    );
}

fn detail_lines(app: &ShellApp, row: &OptionsTableRow, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![effective_value_line(row)];
    lines.extend(app.router.options_browser().notice.iter().cloned());
    lines.extend([
        format!("{} · required: {}", row.cells[4], row.cells[3]),
        row.cells[6].clone(),
        format!("Key: {}", row.cells[0]),
        format!("Default: {}", row.cells[2]),
        format!("Aliases: {}", row.cells[5]),
        "Tool defaults only. Approved run inputs are frozen separately.".into(),
    ]);
    lines
        .into_iter()
        .flat_map(|text| {
            text.lines()
                .flat_map(|part| wrap_text(part, width.max(1)))
                .collect::<Vec<_>>()
        })
        .map(Line::raw)
        .collect()
}

fn effective_value_line(row: &OptionsTableRow) -> String {
    if row.cells[1] != "-" {
        return format!("Value: {}", row.cells[1]);
    }
    if row.cells[2] != "-" {
        return format!("Value: {} · default", row.cells[2]);
    }
    if row.cells[4] == "workflow" {
        return "Value: workflow supplied at dispatch".into();
    }
    "Value: not set".into()
}

fn render_empty_options(frame: &mut Frame<'_>, area: Rect, body: &OptionsBody) {
    let text = match body {
        OptionsBody::Message { message, .. } => *message,
        _ => "No options in this view.",
    };
    let lines = wrap_text(text, area.width as usize)
        .into_iter()
        .map(Line::raw)
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}
