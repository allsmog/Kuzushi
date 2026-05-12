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

    lines = prepend_plain_activity_lines(app, width, lines);

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

fn plain_prereq_plan_lines(plan: &PendingPrereqPrompt, width: usize) -> Vec<String> {
    let mut lines = vec![
        plain_section_divider("PREREQUISITE PLAN", width),
        format!("final tool: {}", plan.final_tool),
        "review required before prerequisites or final tool start".to_string(),
    ];
    for step in &plan.steps {
        lines.extend(plain_prereq_step_lines(step));
    }
    lines.push(format!(
        "actions: approve | reuse cached | regenerate | cancel (recommended: {})",
        plan.recommended_action.label()
    ));
    lines
}

fn prepend_plain_activity_lines(app: &ShellApp, width: usize, lines: Vec<String>) -> Vec<String> {
    let mut prefix = Vec::new();
    if let Some(activity) = app.live_activity.as_ref() {
        prefix.extend(plain_live_activity_lines(activity, width));
        prefix.push(String::new());
    }
    if let Some(plan) = app.pending_prereq_prompt.as_ref() {
        prefix.extend(plain_prereq_plan_lines(plan, width));
        prefix.push(String::new());
    }
    if prefix.is_empty() {
        return lines;
    }
    prefix.into_iter().chain(lines).collect()
}

fn plain_live_activity_lines(activity: &LiveActivity, width: usize) -> Vec<String> {
    vec![
        plain_section_divider("LIVE ACTIVITY", width),
        format!("phase: {}", activity.phase.label()),
        format!("subject: {}", activity.subject),
        format!("detail: {}", activity.detail),
    ]
}

fn plain_prereq_step_lines(step: &PrereqPlanStep) -> Vec<String> {
    let writes = step
        .writes
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        format!(
            "- {} {} via {}",
            step.artifact_state.label(),
            step.artifact_label,
            step.tool
        ),
        format!("  writes: {writes}"),
        format!("  risk: {}", step.risk),
        format!("  cost: {}", step.cost_hint),
    ]
}
