use super::detail_pane::detail_pane_lines;
use super::panes::{center_pane_lines, findings_pane_lines, sep, source_pane_lines, source_title};
use super::*;
use crate::app::WorkbenchPane;
use crate::ui_view_models::{
    workbench_view_model, FindingsModel, WorkbenchCenterBody, WorkbenchHint, WorkbenchTopBar,
    WorkbenchViewModel,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

const TOP_BAR_ROWS: u16 = 2;

/// Frame-level renderer for the Workbench command center. Owns the whole body
/// region: a `Kuzushi · project · target · LIVE · phase` top bar over a
/// responsive review cockpit. Wide terminals show
/// `[SOURCE | CENTER | FINDINGS | DETAILS]`; compact terminals stack the reading
/// path so selected finding details keep usable width. The prompt + keybind
/// footer are drawn by the shell chrome below `area`.
pub(crate) fn render_workbench_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let model = workbench_view_model(app);
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(TOP_BAR_ROWS), Constraint::Min(0)])
        .split(area);
    frame.render_widget(
        Paragraph::new(top_bar_lines(&model.top_bar, &model.command_bar_hints)),
        outer[0],
    );
    render_body(frame, outer[1], app, &model);
}

fn render_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, model: &WorkbenchViewModel) {
    if area.width < 8 || area.height < 3 {
        return;
    }
    if area.width >= 140 {
        render_wide_body(frame, area, app, model);
    } else {
        render_compact_body(frame, area, app, model);
    }
}

fn render_wide_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, model: &WorkbenchViewModel) {
    let widths = wide_pane_widths(area.width);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(widths.source),
            Constraint::Length(widths.center),
            Constraint::Length(widths.findings),
            Constraint::Min(widths.details_min),
        ])
        .split(area);
    render_source(frame, cols[0], app, model);
    render_center(frame, cols[1], app, model);
    render_findings_pane(
        frame,
        cols[2],
        &model.right_list,
        model.focus == WorkbenchPane::Findings,
    );
    render_detail_pane(frame, cols[3], app, model);
}

fn render_compact_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(compact_constraints(model))
        .split(area);
    render_source(frame, rows[0], app, model);
    render_center(frame, rows[1], app, model);
    render_findings_pane(
        frame,
        rows[2],
        &model.right_list,
        model.focus == WorkbenchPane::Findings,
    );
    render_detail_pane(frame, rows[3], app, model);
}

fn compact_constraints(model: &WorkbenchViewModel) -> [Constraint; 4] {
    match &model.center.body {
        WorkbenchCenterBody::Code(_) => [
            Constraint::Percentage(16),
            Constraint::Percentage(44),
            Constraint::Percentage(18),
            Constraint::Percentage(22),
        ],
        WorkbenchCenterBody::Dfd { .. } => [
            Constraint::Percentage(22),
            Constraint::Percentage(28),
            Constraint::Percentage(24),
            Constraint::Percentage(26),
        ],
    }
}

fn render_source(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, model: &WorkbenchViewModel) {
    render_pane(
        frame,
        area,
        &source_title(&model.left),
        source_pane_lines(&model.left),
        model.focus == WorkbenchPane::Source,
        pane_scroll(app, model, WorkbenchPane::Source),
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WidePaneWidths {
    source: u16,
    center: u16,
    findings: u16,
    details_min: u16,
}

/// Prioritize the review path: SOURCE stays compact, CENTER remains useful, and
/// DETAILS gets enough width to wrap title/evidence instead of clipping it.
fn wide_pane_widths(total: u16) -> WidePaneWidths {
    let source = (total * 14 / 100).clamp(18, 32);
    let findings = (total * 23 / 100).clamp(34, 56);
    let mut center = (total * 30 / 100).clamp(32, 76);
    let details_min = 44;
    let fixed = source + findings + center;
    if fixed + details_min > total {
        let reducible = center.saturating_sub(24);
        let needed = fixed + details_min - total;
        center = center.saturating_sub(needed.min(reducible));
    }
    WidePaneWidths {
        source,
        center,
        findings,
        details_min,
    }
}

fn pane_scroll(app: &ShellApp, model: &WorkbenchViewModel, pane: WorkbenchPane) -> u16 {
    if model.focus == pane {
        app.scroll_offset
    } else {
        0
    }
}

fn render_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    focused: bool,
    scroll: u16,
) {
    let block = bordered_block(title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let para = Paragraph::new(lines)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner);
}

fn bordered_block(title: &str, focused: bool) -> Block<'static> {
    let title_style = if focused {
        theme::accent()
    } else {
        theme::label()
    };
    Block::default()
        .borders(Borders::ALL)
        .border_style(if focused {
            theme::accent()
        } else {
            theme::subtle()
        })
        .title(Span::styled(title.to_string(), title_style))
}

fn render_center(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, model: &WorkbenchViewModel) {
    let focused = model.focus == WorkbenchPane::Center;
    let block = bordered_block(&model.center.title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = center_pane_lines(app, &model.center, inner.width as usize);
    let scroll = if focused { app.scroll_offset } else { 0 };
    let para = Paragraph::new(lines)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner);
}

fn render_detail_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let title = detail_pane_title(&model.right_detail);
    render_pane(
        frame,
        area,
        &title,
        detail_pane_lines(&model.right_detail, area.width as usize),
        model.focus == WorkbenchPane::Details,
        pane_scroll(app, model, WorkbenchPane::Details),
    );
}

fn detail_pane_title(detail: &Option<crate::ui_view_models::FindingDetailModel>) -> String {
    detail
        .as_ref()
        .and_then(|detail| detail.alias.as_deref())
        .map(|alias| format!("DETAILS · {alias}"))
        .unwrap_or_else(|| "DETAILS".to_string())
}

fn render_findings_pane(frame: &mut Frame<'_>, area: Rect, model: &FindingsModel, focused: bool) {
    let block = bordered_block(&format!("FINDINGS · {}", model.total), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(findings_pane_lines(model, inner)), inner);
}

// ── top bar ────────────────────────────────────────────────────────────────

fn top_bar_lines(top: &WorkbenchTopBar, hints: &[WorkbenchHint]) -> Vec<Line<'static>> {
    vec![identity_line(top), command_hint_line(hints)]
}

fn identity_line(top: &WorkbenchTopBar) -> Line<'static> {
    let mut spans = vec![
        Span::styled(top.brand.to_string(), theme::heading()),
        sep(),
        Span::styled(top.project.clone(), theme::label()),
        sep(),
        Span::styled(format!("target:{}", top.target), theme::muted()),
        sep(),
        live_span(top.live),
    ];
    if let Some(phase) = &top.phase {
        spans.push(sep());
        spans.push(Span::styled(phase.clone(), theme::accent()));
    }
    Line::from(spans)
}

fn live_span(live: bool) -> Span<'static> {
    if live {
        Span::styled("● LIVE", theme::success())
    } else {
        Span::styled("○ idle", theme::subtle())
    }
}

fn command_hint_line(hints: &[WorkbenchHint]) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (index, hint) in hints.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(hint.verb.to_string(), theme::accent()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(hint.label.to_string(), theme::muted()));
    }
    Line::from(spans)
}

// ── plain / non-TTY path ─────────────────────────────────────────────────────

/// Line-based projection of the Workbench for plain/non-TTY output. Text only:
/// section dividers stand in for the bordered panes (no box-drawing dependency
/// for the layout structure); center content reuses the same lines.
pub(crate) fn workbench_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = workbench_view_model(app);
    let mut lines = top_bar_lines(&model.top_bar, &model.command_bar_hints);
    lines.push(blank());
    lines.push(divider(&source_title(&model.left), area.width));
    lines.extend(source_pane_lines(&model.left));
    lines.push(blank());
    lines.push(divider(&model.center.title, area.width));
    lines.extend(center_pane_lines(app, &model.center, area.width as usize));
    lines.push(blank());
    lines.push(divider(&model.right_list.header, area.width));
    lines.extend(findings_pane_lines(&model.right_list, area));
    lines.push(blank());
    lines.push(divider("DETAILS", area.width));
    lines.extend(detail_pane_lines(&model.right_detail, area.width as usize));
    lines
}
