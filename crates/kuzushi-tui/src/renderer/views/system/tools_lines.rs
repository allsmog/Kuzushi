use super::*;
use crate::ui_view_models::{tools_model, ToolRow};

pub(crate) fn tools_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = tools_model(app);
    let widths = [28usize, value_width(area, 30)];
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("TOOLS", area.width));
    lines.push(aligned_header(&["tool", "description"], &widths));
    push_tool_rows(&mut lines, &widths, &model.rows);
    lines
}

fn push_tool_rows(lines: &mut Vec<Line<'static>>, widths: &[usize], rows: &[ToolRow]) {
    for row in rows {
        lines.push(aligned_row(&row.cells, widths));
    }
}
