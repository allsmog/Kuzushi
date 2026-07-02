use super::detail_pane::detail_pane_lines;
use super::panes::{center_pane_lines, findings_pane_lines, sep, source_pane_lines, source_title};
use super::*;
use crate::app::WorkbenchPane;
use crate::ui_view_models::{
    workbench_view_model, FindingsModel, JourneyPhaseStatus, WorkbenchCenterBody, WorkbenchHint,
    WorkbenchTopBar, WorkbenchViewModel,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

const TOP_BAR_ROWS: u16 = 2;
const AFFORDANCE_ROWS: u16 = 1;
const FOUR_COLUMN_MIN_WIDTH: u16 = 120;
const THREE_COLUMN_MIN_WIDTH: u16 = 100;
const STACKED_MIN_BODY_HEIGHT: u16 = 21;

/// Frame-level renderer for the Workbench command center. Owns the whole body
/// region: a `Kuzushi · project · target · LIVE · phase` top bar over a
/// responsive review cockpit. Wide terminals show four columns; middle widths
/// keep CENTER/FINDINGS/DETAILS; narrow tall terminals stack all panes; narrow
/// short terminals collapse to the review path. The prompt + keybind footer are
/// drawn by the shell chrome below `area`.
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
    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(AFFORDANCE_ROWS), Constraint::Min(0)])
        .split(area);
    frame.render_widget(Paragraph::new(workbench_affordance_line()), body[0]);
    if body[1].height < 3 {
        return;
    }
    match workbench_layout(body[1]) {
        WorkbenchLayout::FourColumn => render_four_column_body(frame, body[1], app, model),
        WorkbenchLayout::ThreeColumn => render_three_column_body(frame, body[1], app, model),
        WorkbenchLayout::Stacked => render_stacked_body(frame, body[1], app, model),
        WorkbenchLayout::ShortReview => render_short_review_body(frame, body[1], app, model),
    }
}

fn workbench_affordance_line() -> Line<'static> {
    muted(" Tab cycle panes · Shift+Tab reverse · j/k move · Enter open finding · Esc back")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkbenchLayout {
    FourColumn,
    ThreeColumn,
    Stacked,
    ShortReview,
}

fn workbench_layout(area: Rect) -> WorkbenchLayout {
    if area.width >= FOUR_COLUMN_MIN_WIDTH {
        return WorkbenchLayout::FourColumn;
    }
    if area.width >= THREE_COLUMN_MIN_WIDTH {
        return WorkbenchLayout::ThreeColumn;
    }
    if area.height >= STACKED_MIN_BODY_HEIGHT {
        return WorkbenchLayout::Stacked;
    }
    WorkbenchLayout::ShortReview
}

fn render_four_column_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let widths = four_column_widths(area.width);
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

fn render_three_column_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let widths = three_column_widths(area.width);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(widths.center),
            Constraint::Length(widths.findings),
            Constraint::Min(widths.details_min),
        ])
        .split(area);
    render_center(frame, cols[0], app, model);
    render_findings_pane(
        frame,
        cols[1],
        &model.right_list,
        model.focus == WorkbenchPane::Findings,
    );
    render_detail_pane(frame, cols[2], app, model);
}

fn render_stacked_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(stacked_constraints(model))
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

fn render_short_review_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Percentage(48),
            Constraint::Percentage(52),
        ])
        .split(area);
    frame.render_widget(Paragraph::new(hidden_panes_stub()), rows[0]);
    render_findings_pane(
        frame,
        rows[1],
        &model.right_list,
        model.focus == WorkbenchPane::Findings,
    );
    render_detail_pane(frame, rows[2], app, model);
}

fn hidden_panes_stub() -> Line<'static> {
    muted(concat!(
        " SOURCE+CODE/DFD hidden · need >=30 rows or >=120 cols ",
        "for all 4; 2/4 shown",
    ))
}

fn stacked_constraints(model: &WorkbenchViewModel) -> [Constraint; 4] {
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
        &pane_title(
            &source_title(&model.left),
            model.focus == WorkbenchPane::Source,
        ),
        source_pane_lines(&model.left),
        model.focus == WorkbenchPane::Source,
        pane_scroll(app, model, WorkbenchPane::Source),
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FourColumnWidths {
    source: u16,
    center: u16,
    findings: u16,
    details_min: u16,
}

/// Prioritize the review path: SOURCE stays compact, FINDINGS keeps proof
/// context visible, CENTER remains useful, and DETAILS gets enough width to
/// wrap title/evidence instead of clipping it.
fn four_column_widths(total: u16) -> FourColumnWidths {
    let source = (total * 14 / 100).clamp(18, 32);
    let findings = (total * 26 / 100).clamp(34, 68);
    let mut center = (total * 30 / 100).clamp(32, 76);
    let details_min = 44;
    let fixed = source + findings + center;
    if fixed + details_min > total {
        let reducible = center.saturating_sub(24);
        let needed = fixed + details_min - total;
        center = center.saturating_sub(needed.min(reducible));
    }
    FourColumnWidths {
        source,
        center,
        findings,
        details_min,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ThreeColumnWidths {
    center: u16,
    findings: u16,
    details_min: u16,
}

fn three_column_widths(total: u16) -> ThreeColumnWidths {
    let center = (total * 34 / 100).clamp(32, 52);
    let findings = (total * 30 / 100).clamp(30, 44);
    let used = center.saturating_add(findings);
    let details_min = total.saturating_sub(used).max(32);
    ThreeColumnWidths {
        center,
        findings,
        details_min,
    }
}

fn pane_scroll(app: &ShellApp, _model: &WorkbenchViewModel, pane: WorkbenchPane) -> u16 {
    app.workbench_scroll.get(pane)
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
    let scroll = clamped_paragraph_scroll(scroll, lines.len(), inner.height);
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
    let block = bordered_block(&pane_title(&model.center.title, focused), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = center_pane_lines(app, &model.center, inner.width as usize);
    let scroll = clamped_paragraph_scroll(
        pane_scroll(app, model, WorkbenchPane::Center),
        lines.len(),
        inner.height,
    );
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
    let title = pane_title(
        &detail_pane_title(&model.right_detail),
        model.focus == WorkbenchPane::Details,
    );
    render_pane(
        frame,
        area,
        &title,
        detail_pane_lines(
            &model.right_detail,
            area.width as usize,
            report_command(model),
        ),
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

fn report_command(model: &WorkbenchViewModel) -> Option<&'static str> {
    model.report_cta.map(|cta| cta.verb)
}

fn render_findings_pane(frame: &mut Frame<'_>, area: Rect, model: &FindingsModel, focused: bool) {
    let block = bordered_block(
        &pane_title(&format!("FINDINGS · {}", model.total), focused),
        focused,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(findings_pane_lines(model, inner)), inner);
}

fn pane_title(title: &str, focused: bool) -> String {
    if focused {
        format!("{title} ◂ focus")
    } else {
        title.to_string()
    }
}

fn clamped_paragraph_scroll(scroll: u16, line_count: usize, viewport_height: u16) -> u16 {
    let visible = viewport_height as usize;
    let max_scroll = line_count.saturating_sub(visible);
    scroll.min(max_scroll.min(u16::MAX as usize) as u16)
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
        Span::styled(format!("modules:{}", top.target), theme::muted()),
        sep(),
        live_span(top.live),
    ];
    if !top.phase_rail.is_empty() {
        spans.push(sep());
        push_phase_rail_spans(&mut spans, &top.phase_rail);
    } else if let Some(phase) = &top.phase {
        spans.push(sep());
        spans.push(Span::styled(phase.clone(), theme::accent()));
    }
    Line::from(spans)
}

fn push_phase_rail_spans(spans: &mut Vec<Span<'static>>, phases: &[JourneyPhaseStatus]) {
    for (index, phase) in phases.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        let style = journey_phase_tone_style(phase.tone);
        spans.push(Span::styled(phase.phase_label.to_string(), style));
        spans.push(Span::styled(phase.state_symbol.to_string(), style));
    }
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
    lines.push(workbench_affordance_line());
    lines.push(blank());
    lines.push(divider(
        &pane_title(
            &source_title(&model.left),
            model.focus == WorkbenchPane::Source,
        ),
        area.width,
    ));
    lines.extend(source_pane_lines(&model.left));
    lines.push(blank());
    lines.push(divider(
        &pane_title(&model.center.title, model.focus == WorkbenchPane::Center),
        area.width,
    ));
    lines.extend(center_pane_lines(app, &model.center, area.width as usize));
    lines.push(blank());
    lines.push(divider(
        &pane_title(
            &model.right_list.header,
            model.focus == WorkbenchPane::Findings,
        ),
        area.width,
    ));
    lines.extend(findings_pane_lines(&model.right_list, area));
    lines.push(blank());
    append_detail_plain_lines(&mut lines, &model, area);
    lines
}

fn append_detail_plain_lines(
    lines: &mut Vec<Line<'static>>,
    model: &WorkbenchViewModel,
    area: Rect,
) {
    lines.push(divider(
        &pane_title("DETAILS", model.focus == WorkbenchPane::Details),
        area.width,
    ));
    lines.extend(detail_pane_lines(
        &model.right_detail,
        area.width as usize,
        report_command(model),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_column_layout_can_fit_full_finding_meta_on_wide_terminals() {
        let widths = four_column_widths(260);

        assert!(
            widths.findings.saturating_sub(2) >= 60,
            "findings pane inner width should fit verdict/proof/location cells: {widths:?}"
        );
    }
}
