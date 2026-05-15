use super::*;
use crate::ui_view_models::module_prompts_model;

pub(crate) fn module_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let Some(module_id) = &app.focused_module else {
        return catalog_lines(app, area);
    };
    let Some(module) = app
        .registry
        .modules()
        .find(|module| module.metadata().id == *module_id)
    else {
        return catalog_lines(app, area);
    };

    let mut lines = context_strip(app, area);
    let primary_tool = primary_tool_name(module);

    append_module_header(&mut lines, module, primary_tool, area);
    append_tools_section(&mut lines, module, area);
    append_stored_options(&mut lines, app, module, area);
    append_prompt_overrides(&mut lines, app, module, area);
    append_session_stats(&mut lines, app, module, area);
    append_recent_activity(&mut lines, app, module, area);
    lines.extend(module_playbook_lines(
        module.metadata().id.as_str(),
        primary_tool,
        area.width,
    ));

    lines
}

fn primary_tool_name(module: &kuzushi_core::BuiltinModule) -> &str {
    visible_module_tools(module)
        .first()
        .map(|tool| tool.name.as_str())
        .unwrap_or("no-tool")
}

fn append_module_header(
    lines: &mut Vec<Line<'static>>,
    module: &kuzushi_core::BuiltinModule,
    primary_tool: &str,
    area: Rect,
) {
    lines.push(blank());
    lines.push(transcript_line(
        ">",
        &format!("/use {}", module.metadata().id),
        false,
    ));
    lines.push(transcript_line(
        "use",
        &format!(
            "focused module {} · primary tool {}",
            module.metadata().id,
            primary_tool
        ),
        false,
    ));
    lines.push(Line::from(vec![
        Span::styled("MODULE DETAIL", theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(module.metadata().id.clone(), theme::accent()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(module.metadata().name.clone(), theme::muted()),
    ]));
    lines.push(indent(
        muted(&short_sentence(
            &module.metadata().description,
            area.width.saturating_sub(2) as usize,
        )),
        2,
    ));
    lines.push(blank());
}

fn append_tools_section(
    lines: &mut Vec<Line<'static>>,
    module: &kuzushi_core::BuiltinModule,
    area: Rect,
) {
    let tools = visible_module_tools(module);
    if tools.is_empty() {
        lines.push(muted("No shell tools are exposed by this module."));
        lines.push(blank());
        return;
    }
    lines.push(divider("TOOLS", area.width));
    for tool in tools {
        lines.push(tool_console_row(
            &tool.name,
            &tool.description,
            tool.headless,
            area.width,
        ));
    }
    lines.push(blank());
}

fn append_stored_options(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    module: &kuzushi_core::BuiltinModule,
    area: Rect,
) {
    let stored_options = module_stored_options(app, module);
    if stored_options.is_empty() {
        return;
    }
    lines.push(divider(
        &format!("OPTIONS · {}", stored_options.len()),
        area.width,
    ));
    for (name, value) in &stored_options {
        lines.push(detail(name, value));
    }
    lines.push(blank());
}

fn append_prompt_overrides(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    module: &kuzushi_core::BuiltinModule,
    area: Rect,
) {
    let prompts = module_prompts_model(app, &module.metadata().id);
    if prompts.is_empty() {
        return;
    }
    lines.push(divider(&format!("PROMPTS · {}", prompts.len()), area.width));
    for prompt in &prompts {
        lines.push(detail(&prompt.verb, &prompt.path));
    }
    lines.push(blank());
}

fn append_session_stats(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    module: &kuzushi_core::BuiltinModule,
    area: Rect,
) {
    let module_log_count = module_log_count(app, module.metadata().id.as_str());
    if module_log_count > 0 {
        lines.push(divider("STATS · this session", area.width));
        lines.push(detail(
            "log entries",
            &format!("{module_log_count} from `{}`", module.metadata().id),
        ));
        lines.push(detail(
            "tools bound",
            &visible_module_tools(module).len().to_string(),
        ));
        lines.push(blank());
    }
}

pub(crate) fn visible_module_tools(
    module: &kuzushi_core::BuiltinModule,
) -> Vec<&kuzushi_core::ToolDescriptor> {
    module.tools().iter().filter(|tool| !tool.hidden).collect()
}

fn module_log_count(app: &ShellApp, module_id: &str) -> usize {
    app.log
        .iter()
        .filter(|line| is_module_log_line(line, module_id))
        .count()
}

fn is_module_log_line(line: &LogLine, module_id: &str) -> bool {
    line.prefix == module_id || line.prefix.starts_with(&format!("{module_id}:"))
}

fn append_recent_activity(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    module: &kuzushi_core::BuiltinModule,
    area: Rect,
) {
    let Some(label) = recent_activity_label(module.metadata().id.as_str()) else {
        return;
    };
    let activity = recent_module_activity_lines(app, module.metadata().id.as_str(), 8);
    if activity.is_empty() {
        return;
    }
    lines.push(section_header_line(label, area.width));
    lines.extend(activity);
    lines.push(blank());
}

fn recent_activity_label(module_id: &str) -> Option<&'static str> {
    match module_id {
        "recon" => Some("RECENT RECON ACTIVITY"),
        "carlini-threat-hunt" | "offense-review" => Some("RECENT THREAT-HUNT ACTIVITY"),
        "agentic-sast" => Some("RECENT AGENTIC-SAST ACTIVITY"),
        _ => None,
    }
}
