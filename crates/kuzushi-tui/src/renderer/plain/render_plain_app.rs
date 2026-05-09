use super::*;

pub fn render_plain_app(app: &ShellApp, width: usize) -> String {
    let lines = render_plain_lines(app, width);
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

pub fn render_plain_command_result(
    app: &ShellApp,
    width: usize,
    command: &str,
    log_start: usize,
) -> String {
    let lines = render_plain_command_result_lines(app, width, command, log_start);
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

pub(crate) fn render_plain_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let width = width.max(40);
    let mut lines = match &app.shell_view {
        ShellView::Options(view) => plain_options_lines(app, width, view),
        ShellView::SastTasks => plain_sast_tasks_lines(app, width),
        ShellView::Context => plain_context_lines(app, width),
        ShellView::Workspace => plain_workspace_lines(app, width),
        ShellView::KnowledgeBase => plain_knowledge_base_lines(app, width),
        ShellView::Config => plain_config_lines(app, width),
        ShellView::Help => plain_help_lines(app, width),
        // Activity view's main render path is frame-level Ratatui (see
        // render_activity_view); the plain path uses the legacy line-based
        // helper so non-TTY callers (--scripted, render_plain_app tests)
        // still get text output. Fall through to shell_view_lines so the
        // primary_view_lines arm for ShellView::Activity drives the
        // line-based renderer.
        _ => {
            let area = Rect::new(0, 0, width.min(u16::MAX as usize) as u16, u16::MAX);
            shell_view_lines(app, area)
                .into_iter()
                .map(line_to_unstyled_text)
                .collect()
        }
    };

    lines = finalize_width_safe_plain_lines(lines, width);
    trim_plain_lines(lines)
}

pub(crate) fn render_plain_command_result_lines(
    app: &ShellApp,
    width: usize,
    command: &str,
    log_start: usize,
) -> Vec<String> {
    let width = width.max(40);
    let mut lines = vec![
        plain_section_divider("COMMAND RESULT", width),
        format!("command: {command}"),
        "logs:".to_string(),
    ];
    let log_start = log_start.min(app.log.len());
    for line in &app.log[log_start..] {
        lines.extend(plain_log_lines(line));
    }
    lines.push(String::new());
    lines.push(plain_section_divider("VIEW", width));
    lines.extend(render_plain_lines(app, width));

    let lines = finalize_width_safe_plain_lines(lines, width);
    trim_plain_lines(lines)
}

pub(crate) fn plain_log_lines(line: &LogLine) -> Vec<String> {
    let mut lines = Vec::new();
    let body_lines = if line.body.is_empty() {
        vec![""]
    } else {
        line.body.lines().collect::<Vec<_>>()
    };
    for (index, body) in body_lines.into_iter().enumerate() {
        if line.prefix == ">" {
            if index == 0 {
                lines.push(format!("> {body}"));
            } else {
                lines.push(format!("  {body}"));
            }
        } else if index == 0 {
            lines.push(format!("{}: {body}", line.prefix));
        } else {
            lines.push(format!("  {body}"));
        }
    }
    lines
}
