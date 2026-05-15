use super::*;
use crate::ui_view_models::{prereq_prompt_model, PrereqPromptModel, PrereqPromptStepModel};

pub(crate) fn prereq_prompt_card_height(app: &ShellApp, area: Rect) -> u16 {
    let Some(prompt) = prereq_prompt_model(app) else {
        return 0;
    };
    if area.height < 8 {
        return 0;
    }
    prereq_prompt_lines(&prompt, area.width)
        .len()
        .min(area.height.saturating_sub(8) as usize)
        .max(5) as u16
}

pub(crate) fn render_prereq_prompt_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(prompt) = prereq_prompt_model(app) else {
        return;
    };
    render_lines(frame, area, prereq_prompt_lines(&prompt, area.width));
}

pub(crate) fn prereq_prompt_lines(prompt: &PrereqPromptModel, width: u16) -> Vec<Line<'static>> {
    let mut lines = prereq_prompt_header_lines(prompt);
    lines.extend(prereq_prompt_step_lines(prompt, width));
    lines.push(prereq_prompt_actions_line(prompt));
    lines
}

fn prereq_prompt_header_lines(prompt: &PrereqPromptModel) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::raw(" "),
            Span::styled("PREREQUISITE PLAN", theme::accent()),
            Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
            Span::styled(prompt.final_tool.clone(), theme::primary()),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                "review required before prerequisites or final tool start",
                theme::muted(),
            ),
        ]),
    ]
}

fn prereq_prompt_step_lines(prompt: &PrereqPromptModel, width: u16) -> Vec<Line<'static>> {
    prompt
        .steps
        .iter()
        .flat_map(|step| {
            let mut lines = vec![prereq_step_line(step, width)];
            lines.extend(prereq_step_detail_lines(step, width));
            lines
        })
        .collect()
}

fn prereq_prompt_actions_line(prompt: &PrereqPromptModel) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled("recommended ", theme::muted()),
        Span::styled(prompt.recommended_action.clone(), theme::success()),
        Span::raw("   "),
        Span::styled("a", theme::success()),
        Span::raw(" approve   "),
        Span::styled("r", theme::primary()),
        Span::raw(" reuse cached   "),
        Span::styled("g", theme::warn()),
        Span::raw(" regenerate   "),
        Span::styled("c", theme::danger()),
        Span::raw(" cancel"),
    ])
}

fn prereq_step_line(step: &PrereqPromptStepModel, width: u16) -> Line<'static> {
    let state_style = if step.cached {
        theme::success()
    } else {
        theme::warn()
    };
    let label_width = width.saturating_sub(48) as usize;
    Line::from(vec![
        Span::raw("  "),
        Span::styled(step.state_label.clone(), state_style),
        Span::raw(" "),
        Span::styled(fit(&step.artifact_label, label_width), theme::primary()),
        Span::styled(" via ", theme::muted()),
        Span::styled(step.tool.clone(), theme::label()),
    ])
}

fn prereq_step_detail_lines(step: &PrereqPromptStepModel, width: u16) -> Vec<Line<'static>> {
    [
        format!("writes {}", step.writes),
        format!("risk {}", step.risk),
        format!("cost {}", step.cost_hint),
    ]
    .into_iter()
    .map(|detail| {
        Line::from(vec![
            Span::raw("    "),
            Span::styled(
                fit(&detail, width.saturating_sub(4) as usize),
                theme::muted(),
            ),
        ])
    })
    .collect()
}
