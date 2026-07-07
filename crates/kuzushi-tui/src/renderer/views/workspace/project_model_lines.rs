use super::*;
use crate::ui_view_models::{project_model, ProjectModel, ProjectModelRow};

pub(crate) fn project_model_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = project_model(app);

    lines.push(blank());
    lines.push(divider("PROJECT MODEL", area.width));
    lines.push(detail("scope", &model.scope_label));
    lines.push(detail("revision", &model.revision_label));
    append_project_model_rows(&mut lines, &model, area);
    lines.push(blank());
    lines.push(next_action_line(model.next_hint, area.width as usize));
    lines
}

fn append_project_model_rows(lines: &mut Vec<Line<'static>>, model: &ProjectModel, area: Rect) {
    let widths = project_model_widths(area.width);
    lines.push(blank());
    lines.push(table_header(
        &["src", "section", "state", "summary", "action"],
        &widths,
    ));
    for row in &model.rows {
        lines.push(project_model_row(row, &widths));
    }
}

fn project_model_row(row: &ProjectModelRow, widths: &[usize]) -> Line<'static> {
    let source = format!("{} {}", row.origin.glyph(), row.origin.label());
    let values = [
        fit(&source, widths[0]),
        fit(row.section, widths[1]),
        fit(row.state, widths[2]),
        fit(&row.summary, widths[3]),
        fit(row.action, widths[4]),
    ];
    table_row(
        &[&values[0], &values[1], &values[2], &values[3], &values[4]],
        widths,
    )
}

fn project_model_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let source = 10;
    let section = if total < 90 { 14 } else { 18 };
    let state = 10;
    let action = if total < 90 { 14 } else { 18 };
    let gaps = 8;
    let summary = total
        .saturating_sub(source + section + state + action + gaps)
        .max(18);
    vec![source, section, state, summary, action]
}
