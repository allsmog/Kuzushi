//! Shared row builders and chrome text for the depth stack (finding rows,
//! breadcrumb, focus echo, leg glyph/tone). Pure `Line` producers reused by the
//! frame renderer and the plain projection.

use super::widgets::{cols, elide, Elide};
use crate::app::{FindingPane, WorkbenchDepth, WorkbenchNav};
use crate::theme;
use crate::ui_view_models::{FindingRow, LegKind, WorkbenchModel};
use ratatui::style::Style;
use ratatui::text::{Line, Span};

/// Window the findings around the selection to fit `rows`, then map each with
/// `build`. Shared by the Depth-0 worklist and the Depth-1 spine.
pub(super) fn row_window(
    model: &WorkbenchModel,
    rows: usize,
    width: usize,
    build: fn(&FindingRow, bool, usize) -> Line<'static>,
) -> Vec<Line<'static>> {
    if rows == 0 {
        return Vec::new();
    }
    let start = window_start(model.selected, rows, model.findings.len());
    model
        .findings
        .iter()
        .enumerate()
        .skip(start)
        .take(rows)
        .map(|(index, row)| build(row, index == model.selected, width))
        .collect()
}

fn window_start(cursor: usize, rows: usize, len: usize) -> usize {
    if len <= rows {
        return 0;
    }
    cursor.saturating_sub(rows / 2).min(len - rows)
}

pub(super) fn worklist_row(row: &FindingRow, selected: bool, width: usize) -> Line<'static> {
    let marker = if selected { "▶" } else { " " };
    let head = format!("{marker} {}  ", row.alias);
    let severity = format!(
        "{} {} ",
        severity_abbrev(&row.severity_label),
        row.proof_marker
    );
    let title = elide(
        &row.title,
        Elide::Prose,
        width.saturating_sub(cols(&head) + cols(&severity)),
    );
    Line::from(vec![
        Span::styled(
            head,
            if selected {
                theme::accent()
            } else {
                theme::muted()
            },
        ),
        Span::styled(severity, theme::severity_tone(row.severity)),
        Span::styled(
            title,
            if selected {
                theme::primary()
            } else {
                theme::muted()
            },
        ),
    ])
}

/// Fixed 4-column severity tag (`CRIT`/`HIGH`/`MED `/`LOW `) so worklist rows
/// stay aligned. Truthful — reuses the projected severity label.
fn severity_abbrev(label: &str) -> String {
    let upper: String = label.to_uppercase().chars().take(4).collect();
    format!("{upper:<4}")
}

pub(super) fn spine_row(row: &FindingRow, selected: bool, width: usize) -> Line<'static> {
    let marker = if selected { "▶" } else { " " };
    let alias = elide(&row.alias, Elide::Id, width.saturating_sub(3));
    Line::from(vec![
        Span::styled(
            format!("{marker}{alias} "),
            if selected {
                theme::accent()
            } else {
                theme::muted()
            },
        ),
        // Proof marker toned by severity — the compressed rail's one live signal.
        Span::styled(
            row.proof_marker.to_string(),
            theme::severity_tone(row.severity),
        ),
    ])
}

pub(super) fn breadcrumb(nav: &WorkbenchNav, model: &WorkbenchModel) -> Line<'static> {
    let alias = selected_alias(model);
    let trail = match nav.depth {
        WorkbenchDepth::List => "review › findings".to_string(),
        WorkbenchDepth::Finding => format!("review › {alias}"),
        WorkbenchDepth::Record => format!("review › {alias} › {}", nav.tab.label()),
    };
    Line::from(vec![
        Span::styled(trail, theme::muted()),
        Span::raw("   "),
        Span::styled("Esc: back", theme::subtle()),
    ])
}

pub(super) fn echo(nav: &WorkbenchNav, model: &WorkbenchModel) -> String {
    match nav.depth {
        WorkbenchDepth::List => format!(
            "{} · {}/{}",
            selected_alias(model),
            model.selected + 1,
            model.findings.len().max(1)
        ),
        WorkbenchDepth::Finding => finding_echo(nav, model),
        WorkbenchDepth::Record => format!("{} · {}", selected_alias(model), nav.tab.label()),
    }
}

fn finding_echo(nav: &WorkbenchNav, model: &WorkbenchModel) -> String {
    match nav.pane {
        FindingPane::Ladder => model
            .legs
            .get(nav.leg)
            .map(|leg| format!("leg {}/{}", leg.index, model.legs.len()))
            .unwrap_or_else(|| "no data-flow".to_string()),
        FindingPane::Drawer => format!("{} · row {}", nav.tab.label(), nav.drawer_row + 1),
        FindingPane::Spine => selected_alias(model),
    }
}

pub(super) fn selected_alias(model: &WorkbenchModel) -> String {
    model
        .findings
        .get(model.selected)
        .map(|row| row.alias.clone())
        .unwrap_or_else(|| "—".to_string())
}

pub(super) fn circled(index: u16) -> String {
    if (1..=9).contains(&index) {
        char::from_u32(0x2460 + u32::from(index) - 1)
            .map(String::from)
            .unwrap_or_else(|| format!("{index}."))
    } else {
        format!("{index}.")
    }
}

pub(super) fn kind_glyph(kind: LegKind) -> &'static str {
    match kind {
        LegKind::Source => "●",
        LegKind::Hop => "○",
        LegKind::Sink => "◆",
    }
}

pub(super) fn kind_style(kind: LegKind) -> Style {
    match kind {
        LegKind::Source => theme::accent(),
        LegKind::Hop => theme::muted(),
        LegKind::Sink => theme::danger(),
    }
}

pub(super) fn line_muted(text: String) -> Line<'static> {
    Line::from(Span::styled(text, theme::muted()))
}

pub(super) fn line_subtle(text: String) -> Line<'static> {
    Line::from(Span::styled(text, theme::subtle()))
}
