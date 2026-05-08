use super::*;
pub(in crate::renderer) use super::*;

pub(crate) fn options_lines(
    app: &ShellApp,
    area: Rect,
    view: &crate::app::OptionsView,
) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("OPTIONS", area.width));
    lines.push(detail("tool", &view.tool_name));
    lines.push(detail("view", options_filter_label(view.filter)));

    let Some(tool) = app.registry.resolve_tool(&view.tool_name) else {
        lines.push(blank());
        lines.push(muted(
            "Unknown tool. Run tools to inspect the native registry.",
        ));
        return lines;
    };

    let stored = app.option_store.effective_stored_values(&tool.name);
    let specs = tool
        .options
        .iter()
        .filter(|spec| option_visible(spec, view.filter, stored.get(&spec.name).is_some()))
        .collect::<Vec<_>>();

    if specs.is_empty() {
        lines.push(blank());
        let message = match view.filter {
            crate::app::OptionsFilter::Standard => {
                "No standard options. Run show advanced for hidden controls."
            }
            crate::app::OptionsFilter::Advanced => "No advanced options for this tool.",
            crate::app::OptionsFilter::Missing => "No missing required options for this tool.",
        };
        lines.push(muted(message));
        return lines;
    }

    lines.push(blank());
    lines.push(table_header(
        &["option", "value", "default", "req", "type", "description"],
        &option_table_widths(area.width),
    ));
    for spec in specs {
        let current = stored.get(&spec.name);
        let required = if spec.required && current.is_none() && spec.default.is_none() {
            "missing"
        } else if spec.required {
            "yes"
        } else {
            "no"
        };
        let description = option_description(spec);
        let widths = option_table_widths(area.width);
        lines.push(table_row(
            &[
                &spec.name,
                &current
                    .map(format_json_value)
                    .unwrap_or_else(|| "-".to_string()),
                &spec
                    .default
                    .as_ref()
                    .map(format_json_value)
                    .unwrap_or_else(|| "-".to_string()),
                required,
                option_type_label(spec.option_type),
                &fit(&description, widths.get(5).copied().unwrap_or(16)),
            ],
            &widths,
        ));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "set <key> <value> writes a session option; setg writes a global option for this shell session.",
        area.width as usize,
    )));
    lines
}

pub(crate) fn sast_tasks_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let rows = app.sast_task_rows();
    let enabled = rows.iter().filter(|row| row.selected).count();
    let blocked = rows.iter().filter(|row| row.source == "blocked").count();
    let mode = app
        .option_store
        .effective_stored_values("sast:scan")
        .get("taskMode")
        .and_then(serde_json::Value::as_str)
        .filter(|mode| *mode == "manual")
        .map(|_| "manual allowlist")
        .unwrap_or("auto + denylist");

    lines.push(blank());
    lines.push(divider("SAST TASKS", area.width));
    lines.push(detail("mode", mode));
    lines.push(detail(
        "selected",
        &format!("{enabled}/{} enabled, {blocked} blocked", rows.len()),
    ));
    lines.push(blank());
    lines.push(muted(&fit(
        "legend: [x] enabled · [ ] disabled · [A] advanced (off by default; allow with /task allow <id>) · [B] blocked",
        area.width as usize,
    )));
    lines.push(blank());
    lines.push(table_header(
        &["state", "id", "cost", "scan", "notes"],
        &sast_task_table_widths(area.width),
    ));
    let widths = sast_task_table_widths(area.width);
    for row in rows {
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
