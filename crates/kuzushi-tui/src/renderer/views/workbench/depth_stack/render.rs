//! Per-depth frame renderers and their `Line` builders. The list/finding/record
//! entry points are dispatched from `mod::render_depth`; the ladder/drawer/record
//! line builders are also reused by the plain projection.

use super::layout::{finding_slots, list_slots};
use super::parts::{
    circled, kind_glyph, kind_style, line_muted, line_subtle, row_window, selected_alias,
    spine_row, worklist_row,
};
use super::widgets::{
    cols, elide, fan_out, log_window, pane_block, render_scroll_pane, stanza_lines, Elide, PaneRole,
};
use crate::app::{DrawerTab, FindingPane, WorkbenchNav};
use crate::renderer::shared::text::wrap_text;
use crate::theme;
use crate::ui_view_models::{Stanza, TraceLeg, Waypoint, WorkbenchModel};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

// ── Depth 0: list + peek ────────────────────────────────────────────────────

pub(super) fn render_list(
    frame: &mut Frame<'_>,
    body: Rect,
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
) {
    let (worklist, peek) = list_slots(body, nav.peek);
    render_worklist(frame, worklist, model);
    if let Some(peek_area) = peek {
        render_peek(frame, peek_area, model);
    }
}

fn render_worklist(frame: &mut Frame<'_>, area: Rect, model: &WorkbenchModel) {
    let block = pane_block(
        &format!("FINDINGS · {}", model.findings.len()),
        true,
        PaneRole::Rail,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = row_window(
        model,
        inner.height as usize,
        inner.width as usize,
        worklist_row,
    );
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_peek(frame: &mut Frame<'_>, area: Rect, model: &WorkbenchModel) {
    let Some(row) = model.findings.get(model.selected) else {
        return;
    };
    let block = pane_block(&format!("PEEK · {}", row.alias), false, PaneRole::Rail);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let width = inner.width as usize;
    let lines = vec![
        line_muted(elide(&format!("at {}", row.location), Elide::Path, width)),
        line_muted(elide(&row.title, Elide::Prose, width)),
        line_muted(format!(
            "verdict {} · confidence {}",
            row.verdict, row.confidence
        )),
        line_muted(format!("proof {} {}", row.proof_marker, row.proof_label)),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

// ── Depth 1: spine | ladder / drawer ────────────────────────────────────────

pub(super) fn render_finding(
    frame: &mut Frame<'_>,
    body: Rect,
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
) {
    let slots = finding_slots(body);
    if let Some(spine) = slots.spine {
        render_spine(frame, spine, nav, model);
    }
    render_ladder(frame, slots.ladder, nav, model);
    if let Some(drawer) = slots.drawer {
        render_drawer(frame, drawer, nav, model);
    }
}

fn render_spine(frame: &mut Frame<'_>, area: Rect, nav: &WorkbenchNav, model: &WorkbenchModel) {
    let block = pane_block("LIST", nav.pane == FindingPane::Spine, PaneRole::Rail);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = row_window(
        model,
        inner.height as usize,
        inner.width as usize,
        spine_row,
    );
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_ladder(frame: &mut Frame<'_>, area: Rect, nav: &WorkbenchNav, model: &WorkbenchModel) {
    let block = pane_block(
        &ladder_title(model),
        nav.pane == FindingPane::Ladder,
        PaneRole::Dominant,
    );
    let lines = ladder_lines(model, nav, area.width.saturating_sub(2) as usize);
    render_scroll_pane(frame, area, block, lines, &nav.ladder_scroll);
}

pub(super) fn ladder_title(model: &WorkbenchModel) -> String {
    match &model.flow_title {
        Some(flow) => format!("DATA-FLOW · {flow}"),
        None => "DATA-FLOW PATH".to_string(),
    }
}

pub(super) fn ladder_lines(
    model: &WorkbenchModel,
    nav: &WorkbenchNav,
    width: usize,
) -> Vec<Line<'static>> {
    if model.legs.is_empty() {
        return vec![line_subtle(
            "no data-flow path for this finding — run taint-iris:hunt".to_string(),
        )];
    }
    let mut lines = Vec::new();
    for (index, leg) in model.legs.iter().enumerate() {
        lines.push(leg_line(leg, index == nav.leg, width));
        if nav.expanded_leg == Some(index) {
            append_waypoints(&mut lines, leg, width);
        }
    }
    lines
}

fn leg_line(leg: &TraceLeg, cursored: bool, width: usize) -> Line<'static> {
    let marker = if cursored { "▶" } else { " " };
    let arrow = if leg.kind == crate::ui_view_models::LegKind::Source {
        "═══▶"
    } else {
        "──▶"
    };
    let head = format!(
        "{marker}{} {} {arrow} {}",
        circled(leg.index),
        leg.from,
        leg.to
    );
    let tail = format!("{} {}", kind_glyph(leg.kind), leg.meta);
    let style = kind_style(leg.kind);
    let budget = width.saturating_sub(cols(&tail) + 2);
    Line::from(vec![
        Span::styled(elide(&head, Elide::Prose, budget), style),
        Span::raw(" "),
        Span::styled(tail, style),
    ])
}

fn append_waypoints(lines: &mut Vec<Line<'static>>, leg: &TraceLeg, width: usize) {
    let (shown, hidden) = fan_out(&leg.waypoints, 5);
    for waypoint in shown {
        lines.push(waypoint_line(waypoint, width));
    }
    if hidden > 0 {
        lines.push(line_subtle(format!("      +{hidden} more nodes")));
    }
}

fn waypoint_line(waypoint: &Waypoint, width: usize) -> Line<'static> {
    let glyph = if waypoint.reached { "✓" } else { "○" };
    let text = format!("      ├ {}", waypoint.label);
    Line::from(vec![
        Span::styled(
            elide(&text, Elide::Prose, width.saturating_sub(2)),
            theme::muted(),
        ),
        Span::raw(" "),
        Span::styled(glyph.to_string(), theme::subtle()),
    ])
}

fn render_drawer(frame: &mut Frame<'_>, area: Rect, nav: &WorkbenchNav, model: &WorkbenchModel) {
    let block = pane_block("DRAWER", nav.pane == FindingPane::Drawer, PaneRole::Rail);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height < 2 {
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);
    frame.render_widget(Paragraph::new(drawer_tabs(nav)), rows[0]);
    let lines = drawer_body(nav, model, rows[1].width as usize, rows[1].height as usize);
    let offset = nav.drawer_scroll.resolved(lines.len(), rows[1].height);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((offset, 0))
            .wrap(Wrap { trim: false }),
        rows[1],
    );
}

fn drawer_tabs(nav: &WorkbenchNav) -> Line<'static> {
    let mut spans = vec![Span::styled("views  ", theme::subtle())];
    for tab in DrawerTab::ALL {
        let style = if tab == nav.tab {
            theme::accent()
        } else {
            theme::muted()
        };
        let label = if tab == nav.tab {
            format!("[{}]", tab.label())
        } else {
            tab.label().to_string()
        };
        spans.push(Span::styled(label, style));
        spans.push(Span::raw(" "));
    }
    Line::from(spans)
}

pub(super) fn drawer_body(
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
    width: usize,
    rows: usize,
) -> Vec<Line<'static>> {
    match nav.tab {
        DrawerTab::Triage => stanza_body(&model.drawer.triage, nav.drawer_row, width),
        DrawerTab::Proof => stanza_body(&model.drawer.proof, nav.drawer_row, width),
        DrawerTab::Log => log_window(&model.drawer.log, rows)
            .into_iter()
            .map(line_muted)
            .collect(),
        DrawerTab::Code => model.drawer.code.iter().cloned().map(line_muted).collect(),
    }
}

fn stanza_body(stanzas: &[Stanza], cursor: usize, width: usize) -> Vec<Line<'static>> {
    if stanzas.is_empty() {
        return vec![line_subtle("no records".to_string())];
    }
    stanzas
        .iter()
        .enumerate()
        .flat_map(|(index, stanza)| stanza_lines(stanza, width, index == cursor))
        .collect()
}

// ── Depth 2: record zoom ────────────────────────────────────────────────────

pub(super) fn render_record(
    frame: &mut Frame<'_>,
    body: Rect,
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
) {
    let (title, lines) = record_view(nav, model, body.width.saturating_sub(2) as usize);
    let block = pane_block(&title, true, PaneRole::Dominant);
    render_scroll_pane(frame, body, block, lines, &nav.record_scroll);
}

pub(super) fn record_view(
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
    width: usize,
) -> (String, Vec<Line<'static>>) {
    match nav.tab {
        DrawerTab::Triage => stanza_record(&model.drawer.triage, nav.drawer_row, width),
        DrawerTab::Proof => stanza_record(&model.drawer.proof, nav.drawer_row, width),
        DrawerTab::Log => (
            "SCANNER LOG".to_string(),
            model.drawer.log.iter().cloned().map(line_muted).collect(),
        ),
        DrawerTab::Code => (
            "CODE".to_string(),
            model.drawer.code.iter().cloned().map(line_muted).collect(),
        ),
    }
}

fn stanza_record(stanzas: &[Stanza], cursor: usize, width: usize) -> (String, Vec<Line<'static>>) {
    match stanzas.get(cursor) {
        Some(stanza) => (
            format!("{} · {}", stanza.id, stanza.state),
            wrap_text(&stanza.body, width)
                .into_iter()
                .map(line_muted)
                .collect(),
        ),
        None => (
            "RECORD".to_string(),
            vec![line_subtle("no record selected".to_string())],
        ),
    }
}
