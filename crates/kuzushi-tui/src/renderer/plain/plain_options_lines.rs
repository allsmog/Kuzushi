use super::*;

pub(crate) fn plain_options_lines(
    app: &ShellApp,
    width: usize,
    view: &crate::app::OptionsView,
) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    lines.push(String::new());
    lines.push(plain_section_divider("OPTIONS", width));
    lines.push(format!("tool: {}", view.tool_name));
    lines.push(format!("view: {}", options_filter_label(view.filter)));

    let Some(tool) = app.registry.resolve_tool(&view.tool_name) else {
        lines.push(String::new());
        lines.push("Unknown tool. Next: tools".to_string());
        return lines;
    };

    let stored = app.option_store.effective_stored_values(&tool.name);
    let specs = tool
        .options
        .iter()
        .filter(|spec| option_visible(spec, view.filter, stored.get(&spec.name).is_some()))
        .collect::<Vec<_>>();

    if specs.is_empty() {
        lines.push(String::new());
        lines.push(
            match view.filter {
                crate::app::OptionsFilter::Standard => "No standard options. Next: show advanced",
                crate::app::OptionsFilter::Advanced => "No advanced options for this tool.",
                crate::app::OptionsFilter::Missing => "No missing required options for this tool.",
            }
            .to_string(),
        );
        return lines;
    }

    lines.push(String::new());
    let widths = option_table_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(
        &["option", "value", "default", "req", "type", "description"],
        &widths,
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
        let current = current
            .map(format_json_value)
            .unwrap_or_else(|| "-".to_string());
        let default = spec
            .default
            .as_ref()
            .map(format_json_value)
            .unwrap_or_else(|| "-".to_string());
        lines.push(table_text(
            &[
                &spec.name,
                &current,
                &default,
                required,
                option_type_label(spec.option_type),
                &fit(&description, widths.get(5).copied().unwrap_or(16)),
            ],
            &widths,
        ));
    }
    lines.push(String::new());
    lines.push(
        "Next: set <key> <value>, setg <key> <value>, show advanced, show missing".to_string(),
    );
    lines
}
