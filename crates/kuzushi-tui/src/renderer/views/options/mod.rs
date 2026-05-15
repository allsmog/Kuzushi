use super::*;
pub(in crate::renderer) use super::*;
use crate::ui_view_models::{
    options_model, sast_tasks_model, OptionsBody, OptionsSummaryRow, OptionsTable, OptionsTableRow,
    SastTasksModel,
};

const OPTION_ALIASES_COLUMN: usize = 5;
const OPTION_DESCRIPTION_COLUMN: usize = 6;

pub(crate) fn options_lines(
    app: &ShellApp,
    area: Rect,
    view: &crate::app::OptionsView,
) -> Vec<Line<'static>> {
    let model = options_model(app, view);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(model.title, area.width));
    for row in &model.summary_rows {
        lines.push(options_summary_row(row));
    }
    push_options_body(&mut lines, area.width, &model.body);
    lines
}

fn options_summary_row(row: &OptionsSummaryRow) -> Line<'static> {
    detail(row.label, &row.value)
}

fn push_options_body(lines: &mut Vec<Line<'static>>, width: u16, body: &OptionsBody) {
    lines.push(blank());
    match body {
        OptionsBody::Table(table) => push_options_table(lines, width, table),
        OptionsBody::Message { message, .. } => lines.push(muted(message)),
    }
}

fn push_options_table(lines: &mut Vec<Line<'static>>, width: u16, table: &OptionsTable) {
    lines.push(muted(&fit(table.hint, width as usize)));
    lines.push(blank());
    let widths = option_table_widths(width);
    lines.push(table_header(&table.headers, &widths));
    for row in &table.rows {
        lines.push(option_row_line(row, &widths));
    }
}

fn option_row_line(row: &OptionsTableRow, widths: &[usize]) -> Line<'static> {
    let aliases = fit(
        &row.cells[OPTION_ALIASES_COLUMN],
        widths.get(OPTION_ALIASES_COLUMN).copied().unwrap_or(10),
    );
    let description = fit(
        &row.cells[OPTION_DESCRIPTION_COLUMN],
        widths.get(OPTION_DESCRIPTION_COLUMN).copied().unwrap_or(16),
    );
    table_row(
        &[
            &row.cells[0],
            &row.cells[1],
            &row.cells[2],
            &row.cells[3],
            &row.cells[4],
            &aliases,
            &description,
        ],
        widths,
    )
}

pub(crate) fn sast_tasks_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = sast_tasks_model(app);

    lines.push(blank());
    lines.push(divider(model.title, area.width));
    for row in &model.summary_rows {
        lines.push(detail(row.label, &row.value));
    }
    lines.push(blank());
    lines.push(muted(&fit(model.legend, area.width as usize)));
    lines.push(blank());
    push_sast_task_table(&mut lines, area.width, &model);
    lines.push(blank());
    lines.push(command_list_line(&model.command_hints, area.width as usize));
    lines
}

fn push_sast_task_table(lines: &mut Vec<Line<'static>>, width: u16, model: &SastTasksModel) {
    lines.push(table_header(&model.headers, &sast_task_table_widths(width)));
    let widths = sast_task_table_widths(width);
    for row in &model.rows {
        lines.push(table_row(
            &[
                row.state,
                row.id,
                row.cost,
                row.scan_task,
                &fit(row.notes, widths.get(4).copied().unwrap_or(20)),
            ],
            &widths,
        ));
    }
}
