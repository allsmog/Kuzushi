use super::interruption_content::{interruption_content, InterruptionSection};
use super::overlay_lines::{model_status, overlay_header};
use super::*;
use crate::{InterruptionFooter, InterruptionSnapshot, InterruptionStatus, InterruptionView};

pub(crate) fn interruption_lines(
    app: &ShellApp,
    area: Rect,
    view: InterruptionView,
) -> Vec<Line<'static>> {
    if let Some(snapshot) = matching_interruption_snapshot(app, view) {
        return interruption_snapshot_lines(snapshot.clone(), area.width as usize);
    }
    let content = interruption_content(view);
    let mut lines = overlay_header(app, area, content.title);
    lines.push(styled(content.headline, interruption_style(view)));
    lines.push(muted(content.summary));
    lines.push(blank());
    lines.extend(interruption_detail_lines(app, view, area.width));
    append_interruption_sections(&mut lines, &content.sections, area.width);
    lines.push(blank());
    lines.extend(command_list_lines(&content.commands, area.width as usize));
    lines
}

fn matching_interruption_snapshot(
    app: &ShellApp,
    view: InterruptionView,
) -> Option<&InterruptionSnapshot> {
    app.interruption_snapshot()
        .filter(|snapshot| snapshot.view == view)
}

fn interruption_snapshot_lines(snapshot: InterruptionSnapshot, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        interruption_status_line(&snapshot.status),
        raw("─".repeat(width)),
        blank(),
    ];
    lines.extend(snapshot.body_rows.into_iter().map(raw));
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(interruption_footer_stage_line(width, &snapshot.footer)));
    lines.push(raw(interruption_footer_keybind_line(&snapshot.footer)));
    lines.push(raw(interruption_prompt_line(&snapshot.footer)));
    lines
}

fn interruption_status_line(status: &InterruptionStatus) -> Line<'static> {
    raw(format!(
        " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
        status.target, status.ctx, status.model, status.module, status.cost
    ))
}

fn interruption_footer_stage_line(width: usize, footer: &InterruptionFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn interruption_footer_keybind_line(footer: &InterruptionFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}

fn interruption_prompt_line(footer: &InterruptionFooter) -> String {
    match footer.prompt_module.as_deref() {
        Some(module) => format!(" kuzushi ({module})>"),
        None => " kuzushi>".to_string(),
    }
}

fn raw(value: impl Into<String>) -> Line<'static> {
    Line::raw(value.into())
}

fn interruption_style(view: InterruptionView) -> ratatui::style::Style {
    match view {
        InterruptionView::RateLimited => theme::warn(),
        _ => theme::danger(),
    }
}

fn interruption_detail_lines(
    app: &ShellApp,
    view: InterruptionView,
    width: u16,
) -> Vec<Line<'static>> {
    match view {
        InterruptionView::BudgetHardStop | InterruptionView::BudgetStop => {
            budget_snapshot_lines(app, width)
        }
        InterruptionView::NoModel => vec![
            detail("model", &model_status(app)),
            detail("credential", &app.config().runtime.api_key_env),
        ],
        InterruptionView::NoBinary => vec![detail("tool", focused_tool(app, "codeql"))],
        InterruptionView::NoPlugin => vec![detail("tool", focused_tool(app, "plugin-backed"))],
        InterruptionView::NetworkDown => vec![detail("network", "cloud provider unreachable")],
        InterruptionView::RateLimited => vec![detail("provider", "throttled")],
    }
}

fn budget_snapshot_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let Some(halt) = app.advisory().budget_halt.as_ref() else {
        return vec![detail(
            "budget",
            "no live halt object; see cost for current totals",
        )];
    };
    detail_wrapped(
        "budget",
        &format!("spent ${:.4} / cap ${:.4}", halt.spent_usd, halt.limit_usd),
        width,
    )
}

fn focused_tool<'a>(app: &'a ShellApp, fallback: &'a str) -> &'a str {
    app.focused_module().unwrap_or(fallback)
}

fn append_interruption_sections(
    lines: &mut Vec<Line<'static>>,
    sections: &[InterruptionSection],
    width: u16,
) {
    for section in sections {
        lines.push(blank());
        lines.push(category_divider(section.title, "", width));
        for row in &section.rows {
            lines.push(interruption_row(row, width as usize));
        }
    }
}

fn interruption_row(row: &str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::raw("   "),
        Span::styled("- ", theme::subtle()),
        Span::styled(fit(row, width.saturating_sub(5)), theme::muted()),
    ])
}
