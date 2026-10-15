use super::*;
use crate::ui_view_models::{tools_model, ToolGroup, ToolRow};

pub(crate) fn tools_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = tools_model(app);
    let widths = tool_widths(area);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(
        &tools_title(model.filter.as_deref(), model.total_count),
        area.width,
    ));
    if model.visible_count == 0 {
        push_empty_tools_or_support(
            &mut lines,
            &model,
            model.selected_support.as_deref(),
            area.width as usize,
        );
        return lines;
    }
    push_tools_filter_line(
        &mut lines,
        model.filter.as_deref(),
        model.visible_count,
        model.total_count,
        area.width as usize,
    );
    push_tool_groups(&mut lines, &widths, &model.groups, area.width as usize);
    push_tools_footer(&mut lines, area.width as usize);
    lines
}

fn push_empty_tools_or_support(
    lines: &mut Vec<Line<'static>>,
    model: &crate::ui_view_models::ToolsModel,
    selected: Option<&str>,
    width: usize,
) {
    if model.omitted_support.is_empty() {
        push_empty_tools_lines(lines, width);
        return;
    }
    let index = model.selected_support_index(selected);
    let tool = &model.omitted_support[index];
    lines.push(styled(
        &format!("{} · {}", tool.support, tool.tool),
        theme::warn(),
    ));
    lines.push(muted(&format!(
        "Enter settings · {}/{} · ↑/↓ choose",
        index + 1,
        model.omitted_support.len()
    )));
    lines.push(muted(&format!("options {}", tool.tool)));
    lines.push(muted(
        "Outside supported defaults. Inspect settings before choosing work.",
    ));
    lines.push(command_list_line(&["tools", "modules"], width));
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

fn push_tool_groups(
    lines: &mut Vec<Line<'static>>,
    widths: &[usize],
    groups: &[ToolGroup],
    width: usize,
) {
    for group in groups {
        lines.push(blank());
        lines.push(tool_group_header(group, width));
        lines.push(aligned_header(&["tool", "purpose", "next"], widths));
        push_tool_rows(lines, widths, &group.rows);
    }
}

fn tool_group_header(group: &ToolGroup, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{} ", group.label), theme::accent()),
        Span::styled(
            fit(group.hint, width.saturating_sub(group.label.len() + 1)),
            theme::muted(),
        ),
    ])
}

fn push_tool_rows(lines: &mut Vec<Line<'static>>, widths: &[usize], rows: &[ToolRow]) {
    for row in rows {
        lines.push(aligned_row(&row.cells, widths));
    }
}

fn tool_widths(area: Rect) -> [usize; 3] {
    fit_table_widths(area.width as usize, [28, 50, 28], [12, 10, 6])
}

fn tools_title(filter: Option<&str>, total_count: usize) -> String {
    match filter {
        Some(query) => format!("TOOLS · {query}"),
        None => format!("TOOLS · {total_count}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excluded_tool_support_names_the_reason_and_read_only_next_action() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.router
            .tools_mut()
            .open(Some("module:govulncheck".into()));
        for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
            let lines = tools_lines(&app, Rect::new(0, 0, width, height));
            let text = lines
                .iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("Experimental · govulncheck:scan"), "{text}");
            assert!(text.contains("options govulncheck:scan"), "{text}");
            assert!(!text.contains("No routed tools match"), "{text}");
        }
    }

    #[test]
    fn tool_columns_fit_narrow_area_budgets() {
        let row = ToolRow {
            cells: [
                "sast:日本語-scan".to_string(),
                "finds a long class of security defects".to_string(),
                "run with explicit options".to_string(),
            ],
        };
        for width in [40, 60, 80] {
            let widths = tool_widths(Rect::new(0, 0, width, 20));
            let line = aligned_row(&row.cells, &widths);
            let rendered_width = line
                .spans
                .iter()
                .map(|span| display_width(span.content.as_ref()))
                .sum::<usize>();

            assert_eq!(table_width(&widths), width as usize);
            assert!(rendered_width <= width as usize);
        }
    }
}
