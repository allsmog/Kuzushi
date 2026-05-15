use super::*;
use crate::ui_view_models::{focused_module_detail_model, ModuleDetailModel};

pub(crate) fn module_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let Some(module) = focused_module_detail_model(app) else {
        return catalog_lines(app, area);
    };

    let mut lines = context_strip(app, area);

    append_module_header(&mut lines, &module, area);
    append_tools_section(&mut lines, &module, area);
    append_stored_options(&mut lines, &module, area);
    append_prompt_overrides(&mut lines, &module, area);
    append_session_stats(&mut lines, &module, area);
    append_recent_activity(&mut lines, app, &module, area);
    lines.extend(module_playbook_lines(
        &module.id,
        &module.primary_tool,
        area.width,
    ));

    lines
}

fn append_module_header(lines: &mut Vec<Line<'static>>, module: &ModuleDetailModel, area: Rect) {
    lines.push(blank());
    lines.push(transcript_line(">", &format!("/use {}", module.id), false));
    lines.push(transcript_line(
        "use",
        &format!(
            "focused module {} · primary tool {}",
            module.id, module.primary_tool
        ),
        false,
    ));
    lines.push(Line::from(vec![
        Span::styled("MODULE DETAIL", theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(module.id.clone(), theme::accent()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(module.name.clone(), theme::muted()),
    ]));
    lines.push(indent(
        muted(&short_sentence(
            &module.description,
            area.width.saturating_sub(2) as usize,
        )),
        2,
    ));
    lines.push(blank());
}

fn append_tools_section(lines: &mut Vec<Line<'static>>, module: &ModuleDetailModel, area: Rect) {
    if module.visible_tools.is_empty() {
        lines.push(muted("No shell tools are exposed by this module."));
        lines.push(blank());
        return;
    }
    lines.push(divider("TOOLS", area.width));
    for tool in &module.visible_tools {
        lines.push(tool_console_row(
            &tool.name,
            &tool.description,
            tool.headless,
            area.width,
        ));
    }
    lines.push(blank());
}

fn append_stored_options(lines: &mut Vec<Line<'static>>, module: &ModuleDetailModel, area: Rect) {
    if module.stored_options.is_empty() {
        return;
    }
    lines.push(divider(
        &format!("OPTIONS · {}", module.stored_options.len()),
        area.width,
    ));
    for (name, value) in &module.stored_options {
        lines.push(detail(name, value));
    }
    lines.push(blank());
}

fn append_prompt_overrides(lines: &mut Vec<Line<'static>>, module: &ModuleDetailModel, area: Rect) {
    if module.prompts.is_empty() {
        return;
    }
    lines.push(divider(
        &format!("PROMPTS · {}", module.prompts.len()),
        area.width,
    ));
    for prompt in &module.prompts {
        lines.push(detail(&prompt.verb, &prompt.path));
    }
    lines.push(blank());
}

fn append_session_stats(lines: &mut Vec<Line<'static>>, module: &ModuleDetailModel, area: Rect) {
    if module.log_count > 0 {
        lines.push(divider("STATS · this session", area.width));
        lines.push(detail(
            "log entries",
            &format!("{} from `{}`", module.log_count, module.id),
        ));
        lines.push(detail(
            "tools bound",
            &module.visible_tools.len().to_string(),
        ));
        lines.push(blank());
    }
}

fn append_recent_activity(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    module: &ModuleDetailModel,
    area: Rect,
) {
    let Some(label) = recent_activity_label(&module.id) else {
        return;
    };
    let activity = recent_module_activity_lines(app, &module.id, 8);
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
