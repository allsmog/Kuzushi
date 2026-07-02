use super::*;
use crate::ui_view_models::{tools_model, ToolRow};

pub(crate) fn tools_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = tools_model(app);
    let widths = [28usize, value_width(area, 30)];
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(
        &tools_title(model.filter.as_deref(), model.total_count),
        area.width,
    ));
    push_tools_filter_line(
        &mut lines,
        model.filter.as_deref(),
        model.rows.len(),
        model.total_count,
        area.width as usize,
    );
    if model.rows.is_empty() {
        push_empty_tools_lines(&mut lines, area.width as usize);
        return lines;
    }
    lines.push(aligned_header(&["tool", "description"], &widths));
    push_tool_rows(&mut lines, &widths, &model.rows);
    push_tools_footer(&mut lines, area.width as usize);
    lines
}

fn push_tools_filter_line(
    lines: &mut Vec<Line<'static>>,
    query: Option<&str>,
    visible_count: usize,
    total_count: usize,
    width: usize,
) {
    let Some(query) = query else {
        return;
    };
    lines.push(muted(&fit(
        &format!("filter: {query} · showing {visible_count} of {total_count} tools"),
        width,
    )));
}

fn push_empty_tools_lines(lines: &mut Vec<Line<'static>>, width: usize) {
    lines.extend(empty_state_panel(
        "tools",
        &[
            "No routed tools match this filter.",
            "Search by module id, tool id, or words in the description.",
        ],
        &[
            ("tools", "clear the filter"),
            ("modules", "browse module groups"),
            ("recommend", "rank useful next tools"),
        ],
    ));
    lines.push(command_list_line(
        &["tools <query>", "tools", "modules", "recommend"],
        width,
    ));
}

fn push_tools_footer(lines: &mut Vec<Line<'static>>, width: usize) {
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "tools <query>",
            "j/k/g/G scroll",
            "PgUp/PgDn scroll",
            "use <id>",
            "options <tool>",
        ],
        width,
    ));
}

fn push_tool_rows(lines: &mut Vec<Line<'static>>, widths: &[usize], rows: &[ToolRow]) {
    for row in rows {
        lines.push(aligned_row(&row.cells, widths));
    }
}

fn tools_title(filter: Option<&str>, total_count: usize) -> String {
    match filter {
        Some(query) => format!("TOOLS · {query}"),
        None => format!("TOOLS · {total_count}"),
    }
}
