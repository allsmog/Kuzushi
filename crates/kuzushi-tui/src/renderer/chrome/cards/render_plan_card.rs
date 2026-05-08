use super::*;

pub(crate) fn render_plan_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(plan) = app.pending_plan.as_ref() else {
        return;
    };
    let active = plan
        .changes
        .iter()
        .enumerate()
        .filter(|(idx, _)| !app.plan_change_skipped(*idx))
        .count();
    let total = plan.changes.len();
    let cursor = app.plan_cursor_clamped();
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::styled(
        fit(
            &format!("◆ PLAN · goal: {} · {active}/{total} active", plan.goal),
            area.width as usize,
        ),
        theme::accent(),
    ));
    lines.push(Line::styled(
        fit(&format!("  summary: {}", plan.summary), area.width as usize),
        theme::primary(),
    ));
    for (idx, change) in plan.changes.iter().enumerate() {
        let skipped = app.plan_change_skipped(idx);
        let marker = if idx == cursor { ">" } else { " " };
        let toggle = if skipped { "[ ]" } else { "[x]" };
        let style = if skipped {
            theme::muted().add_modifier(Modifier::DIM)
        } else if idx == cursor {
            theme::success().add_modifier(Modifier::BOLD)
        } else {
            theme::success()
        };
        lines.push(Line::styled(
            fit(
                &format!("  {marker} {toggle} {}", change.label()),
                area.width as usize,
            ),
            style,
        ));
    }
    for note in &plan.unsupported {
        lines.push(Line::styled(
            fit(&format!("  ! unsupported: {note}"), area.width as usize),
            theme::warn(),
        ));
    }
    // Mirror the keybind footer's accent-key + muted-hint shape rather
    // than `[k]` chrome.  Per `design/mockups/plan.jsx` and the rest of
    // the shell.  Slash verbs (/yes, /no) are kept as muted hints since
    // they aren't single keys.
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("j/k", theme::accent()),
        Span::raw(" "),
        Span::styled("move", theme::muted()),
        Span::raw("   "),
        Span::styled("space", theme::accent()),
        Span::raw(" "),
        Span::styled("toggle", theme::muted()),
        Span::raw("   "),
        Span::styled("y", theme::accent()),
        Span::raw(" "),
        Span::styled("apply active", theme::muted()),
        Span::raw("   "),
        Span::styled("n", theme::accent()),
        Span::raw(" "),
        Span::styled("discard", theme::muted()),
        Span::raw("   "),
        Span::styled("/yes", theme::muted()),
        Span::raw("   "),
        Span::styled("/no", theme::muted()),
    ]));
    render_lines(frame, area, lines);
}

pub(crate) fn render_cost_cap_halt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(halt) = app.advisory.budget_halt.as_ref() else {
        return;
    };
    let header = fit(
        &format!(
            "■ COST CAP HALT · spent ${:.4} / cap ${:.4}",
            halt.spent_usd, halt.limit_usd
        ),
        area.width as usize,
    );
    let mut lines = vec![Line::styled(header, theme::danger())];
    if area.height > 1 {
        // Mirror the unbracketed key style from `keybindings_line` /
        // `design/mockups/_shared.jsx::footer` — accent key + muted hint
        // separated by 3 spaces.  Matches the rest of the shell's
        // muscle-memory rather than re-introducing `[k]` chrome.
        let action_line = Line::from(vec![
            Span::raw(" "),
            Span::styled("c", theme::accent()),
            Span::raw(" "),
            Span::styled("continue past cap", theme::warn()),
            Span::raw("   "),
            Span::styled("a", theme::accent()),
            Span::raw(" "),
            Span::styled("abort scan", theme::warn()),
        ]);
        lines.push(action_line);
    }
    render_lines(frame, area, lines);
}
