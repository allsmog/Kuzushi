use super::*;
use crate::ui_view_models::{
    focused_module_detail_model, ModuleDetailModel, ModuleKeyValueSection,
};

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
        "module",
        &format!(
            "now using {} · primary tool {}",
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
            &module.summary,
            area.width.saturating_sub(2) as usize,
        )),
        2,
    ));
    lines.push(blank());
}

fn append_tools_section(lines: &mut Vec<Line<'static>>, module: &ModuleDetailModel, area: Rect) {
    let section = &module.tools_section;
    if let Some(message) = section.empty_message {
        lines.push(muted(message));
        lines.push(blank());
        return;
    }
    lines.push(divider(section.header, area.width));
    for tool in &section.rows {
        lines.push(tool_console_row(
            &tool.cells[0],
            &tool.cells[1],
            &tool.cells[2],
            area.width,
        ));
    }
    lines.push(blank());
}

fn append_stored_options(lines: &mut Vec<Line<'static>>, module: &ModuleDetailModel, area: Rect) {
    append_key_value_section(lines, module.options_section.as_ref(), area);
}

fn append_prompt_overrides(lines: &mut Vec<Line<'static>>, module: &ModuleDetailModel, area: Rect) {
    append_key_value_section(lines, module.prompts_section.as_ref(), area);
}

fn append_session_stats(lines: &mut Vec<Line<'static>>, module: &ModuleDetailModel, area: Rect) {
    append_key_value_section(lines, module.stats_section.as_ref(), area);
}

fn append_key_value_section(
    lines: &mut Vec<Line<'static>>,
    section: Option<&ModuleKeyValueSection>,
    area: Rect,
) {
    let Some(section) = section else {
        return;
    };
    lines.push(divider(&section.header, area.width));
    for (name, value) in &section.rows {
        lines.push(detail(name, value));
    }
    lines.push(blank());
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
