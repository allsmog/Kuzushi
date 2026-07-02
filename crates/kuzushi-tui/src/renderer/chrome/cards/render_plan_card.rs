use super::*;
use crate::ui_view_models::{
    cost_cap_halt_model, plan_card_model, CostCapHaltModel, PlanCardModel, PlanChangeRow,
};

pub(crate) fn render_plan_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(plan) = plan_card_model(app) else {
        return;
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(plan_header_line(&plan, area.width as usize));
    lines.push(Line::styled(
        fit(&format!("  summary: {}", plan.summary), area.width as usize),
        theme::primary(),
    ));
    for change in &plan.changes {
        lines.push(plan_change_line(change, area.width as usize));
    }
    for note in &plan.unsupported {
        lines.push(Line::styled(
            fit(&format!("  ! unsupported: {note}"), area.width as usize),
            theme::warn(),
        ));
    }
    lines.push(plan_action_line());
    render_lines(frame, area, lines);
}

fn plan_action_line() -> Line<'static> {
    // Mirror the keybind footer's accent-key + muted-hint shape rather
    // than `[k]` chrome.  Per `design/mockups/plan.jsx` and the rest of
    // the shell.  Slash verbs (/yes, /no) are kept as muted hints since
    // they aren't single keys.
    Line::from(vec![
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
    ])
}

fn plan_header_line(plan: &PlanCardModel, width: usize) -> Line<'static> {
    Line::styled(
        fit(
            &format!(
                "◆ PLAN · goal: {} · {}/{} active",
                plan.goal, plan.active_count, plan.total_count
            ),
            width,
        ),
        theme::accent(),
    )
}

fn plan_change_line(change: &PlanChangeRow, width: usize) -> Line<'static> {
    let marker = if change.selected { ">" } else { " " };
    let toggle = if change.skipped { "[ ]" } else { "[x]" };
    Line::styled(
        fit(&format!("  {marker} {toggle} {}", change.label), width),
        plan_change_style(change),
    )
}

fn plan_change_style(change: &PlanChangeRow) -> Style {
    if change.skipped {
        return theme::disabled();
    }
    if change.selected {
        return theme::success().add_modifier(Modifier::BOLD);
    }
    theme::success()
}

pub(crate) fn render_cost_cap_halt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(halt) = cost_cap_halt_model(app) else {
        return;
    };
    if area.height == 1 {
        render_lines(
            frame,
            area,
            vec![Line::styled(
                fit(halt.compact, area.width as usize),
                theme::danger(),
            )],
        );
        return;
    }
    let mut lines = vec![cost_cap_halt_header_line(&halt, area.width as usize)];
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

fn cost_cap_halt_header_line(halt: &CostCapHaltModel, width: usize) -> Line<'static> {
    Line::styled(fit(&halt.header, width), theme::danger())
}
