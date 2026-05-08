use super::*;

pub(crate) fn prereq_prompt_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 || app.pending_prereq_prompt.is_none() {
        return 0;
    }
    4.min(area.height.saturating_sub(8) as u16).max(3)
}

pub(crate) fn render_prereq_prompt_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(prompt) = app.pending_prereq_prompt.as_ref() else {
        return;
    };
    render_lines(frame, area, prereq_prompt_lines(prompt, area.width));
}

fn prereq_prompt_lines(prompt: &PendingPrereqPrompt, width: u16) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::raw(" "),
            Span::styled("PREREQUISITE EXISTS", theme::accent()),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("artifact ", theme::muted()),
            Span::styled(
                fit(
                    &prompt.current_artifact_label,
                    width.saturating_sub(14) as usize,
                ),
                theme::primary(),
            ),
            Span::raw("   "),
            Span::styled("path ", theme::muted()),
            Span::styled(
                fit(
                    &prompt.current_artifact_path.display().to_string(),
                    width.saturating_sub(40) as usize,
                ),
                theme::muted(),
            ),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("for      ", theme::muted()),
            Span::styled(prompt.final_tool.clone(), theme::primary()),
            Span::raw("   "),
            Span::styled("regen via ", theme::muted()),
            Span::styled(prompt.current_tool.clone(), theme::primary()),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("r", theme::success()),
            Span::raw(" reuse existing   "),
            Span::styled("g", theme::warn()),
            Span::raw(" regenerate   "),
            Span::styled("(y/n also accepted)", theme::muted()),
        ]),
    ]
}
