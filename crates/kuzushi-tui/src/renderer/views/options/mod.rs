use super::*;
pub(in crate::renderer) use super::*;
use crate::ui_view_models::{
    options_model, sast_tasks_model, OptionRow, OptionsModelStatus, OptionsSummaryRow,
    SastTasksModel,
};

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
    push_options_body(&mut lines, area.width, &model.status, &model.rows);
    lines
}

fn options_summary_row(row: &OptionsSummaryRow) -> Line<'static> {
    detail(row.label, &row.value)
}

fn push_options_body(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    status: &OptionsModelStatus,
    rows: &[OptionRow],
) {
    lines.push(blank());
    match status {
        OptionsModelStatus::Ready => push_options_table(lines, width, rows),
        OptionsModelStatus::UnknownTool => lines.push(muted(
            "Unknown tool. Run tools to inspect the native registry.",
        )),
        OptionsModelStatus::Empty { message, .. } => lines.push(muted(message)),
    }
}

fn push_options_table(lines: &mut Vec<Line<'static>>, width: u16, rows: &[OptionRow]) {
    lines.push(muted(&fit(
        "set <key> <value> writes session state; setg writes global state. Option names are canonical; aliases work.",
        width as usize,
    )));
    lines.push(blank());
    let widths = option_table_widths(width);
    lines.push(table_header(
        &[
            "option",
            "value",
            "default",
            "req",
            "type",
            "aliases",
            "description",
        ],
        &widths,
    ));
    for row in rows {
        lines.push(option_row_line(row, &widths));
    }
}

fn option_row_line(row: &OptionRow, widths: &[usize]) -> Line<'static> {
    let aliases = fit(&row.aliases, widths.get(5).copied().unwrap_or(10));
    let description = fit(&row.description, widths.get(6).copied().unwrap_or(16));
    table_row(
        &[
            &row.name,
            &row.value,
            &row.default_value,
            row.required,
            row.option_type,
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
    lines.push(divider("SAST TASKS", area.width));
    lines.push(detail("mode", model.mode_label));
    lines.push(detail("selected", &model.selected_summary));
    lines.push(blank());
    lines.push(muted(&fit(
        "legend: [x] enabled · [ ] disabled · [A] advanced (off by default; allow with /task allow <id>) · [B] blocked",
        area.width as usize,
    )));
    lines.push(blank());
    push_sast_task_table(&mut lines, area.width, &model);
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "/task block <id>",
            "/task allow <id>",
            "/task toggle [id]",
            "/task mode auto|manual|toggle",
            "/task reset",
        ],
        area.width as usize,
    ));
    lines
}

fn push_sast_task_table(lines: &mut Vec<Line<'static>>, width: u16, model: &SastTasksModel) {
    lines.push(table_header(
        &["state", "id", "cost", "scan", "notes"],
        &sast_task_table_widths(width),
    ));
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
