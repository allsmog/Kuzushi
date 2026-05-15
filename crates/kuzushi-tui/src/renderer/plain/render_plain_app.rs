use super::*;
use crate::ui_view_models::{
    plain_command_result_model, plain_live_activity_rows, plain_prereq_plan_model,
    plain_render_mode, PlainCommandResultModel, PlainPrereqPlanModel, PlainRenderMode,
};

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
    let mut lines = match plain_render_mode(app) {
        PlainRenderMode::Options(view) => plain_options_lines(app, width, view),
        PlainRenderMode::SastTasks => plain_sast_tasks_lines(app, width),
        PlainRenderMode::Context => plain_context_lines(app, width),
        PlainRenderMode::Workspace => plain_workspace_lines(app, width),
        PlainRenderMode::KnowledgeBase => plain_knowledge_base_lines(app, width),
        PlainRenderMode::Config => plain_config_lines(app, width),
        PlainRenderMode::Help => plain_help_lines(app, width),
        PlainRenderMode::LineBased => plain_line_based_view_lines(app, width),
    };

    lines = prepend_plain_activity_lines(app, width, lines);

    lines = finalize_width_safe_plain_lines(lines, width);
    trim_plain_lines(lines)
}

fn plain_line_based_view_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let area = Rect::new(0, 0, width.min(u16::MAX as usize) as u16, u16::MAX);
    shell_view_lines(app, area)
        .into_iter()
        .map(line_to_unstyled_text)
        .collect()
}

pub(crate) fn render_plain_command_result_lines(
    app: &ShellApp,
    width: usize,
    command: &str,
    log_start: usize,
) -> Vec<String> {
    let width = width.max(40);
    let model = plain_command_result_model(app, command, log_start);
    let mut lines = plain_command_result_lines(model, width);
    lines.push(String::new());
    lines.extend(render_plain_lines(app, width));

    let lines = finalize_width_safe_plain_lines(lines, width);
    trim_plain_lines(lines)
}

fn plain_command_result_lines(model: PlainCommandResultModel, width: usize) -> Vec<String> {
    let mut lines = vec![plain_section_divider(model.result_title, width)];
    lines.extend(model.rows);
    lines.push(String::new());
    lines.push(plain_section_divider(model.view_title, width));
    lines
}

fn plain_prereq_plan_lines(plan: PlainPrereqPlanModel, width: usize) -> Vec<String> {
    let mut lines = vec![plain_section_divider(plan.title, width)];
    lines.extend(plan.rows);
    lines
}

fn prepend_plain_activity_lines(app: &ShellApp, width: usize, lines: Vec<String>) -> Vec<String> {
    let mut prefix = Vec::new();
    if let Some(rows) = plain_live_activity_rows(app) {
        prefix.extend(plain_live_activity_lines(rows, width));
        prefix.push(String::new());
    }
    if let Some(plan) = plain_prereq_plan_model(app) {
        prefix.extend(plain_prereq_plan_lines(plan, width));
        prefix.push(String::new());
    }
    if prefix.is_empty() {
        return lines;
    }
    prefix.into_iter().chain(lines).collect()
}

fn plain_live_activity_lines(
    rows: Vec<crate::ui_view_models::PlainLiveActivityRow>,
    width: usize,
) -> Vec<String> {
    let mut lines = vec![plain_section_divider("LIVE ACTIVITY", width)];
    lines.extend(
        rows.into_iter()
            .map(|row| format!("{}: {}", row.label, row.value)),
    );
    lines
}
