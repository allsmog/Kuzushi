//! Pure pane-body line builders for the Workbench command center. Shared by the
//! frame renderer (each list drawn inside a bordered `Block`) and the plain
//! `workbench_lines` path (each list stacked under a text divider).

use super::*;
use crate::ui_view_models::{
    threat_dfd_view, CodePaneModel, CodePaneRow, DfdLineKind, FindingListRow, FindingsModel,
    SeverityCounts, SeverityTone, SourceTreeModel, SourceTreeRow, WorkbenchCenter,
    WorkbenchCenterBody,
};
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Span};

pub(super) fn sep() -> Span<'static> {
    Span::styled(theme::STATUS_SEPARATOR, theme::subtle())
}

fn pane_empty_state(
    glyph_label: &str,
    explanations: &[&str],
    ctas: &[(&str, &str)],
) -> Vec<Line<'static>> {
    empty_state_panel(glyph_label, explanations, ctas)
}

// ── SOURCE pane ──────────────────────────────────────────────────────────────

pub(super) fn source_title(model: &SourceTreeModel) -> String {
    format!("SOURCE · {} files", model.file_count)
}

pub(super) fn source_pane_lines(model: &SourceTreeModel) -> Vec<Line<'static>> {
    if let Some(hint) = model.empty_hint {
        return pane_empty_state(
            "no source tree",
            &[hint],
            &[("scan", "populate finding-bearing files")],
        );
    }
    model.rows.iter().map(source_row_line).collect()
}

fn source_row_line(row: &SourceTreeRow) -> Line<'static> {
    let indent = " ".repeat(row.depth * 2);
    let name = if row.is_dir {
        format!("{}/", row.name)
    } else {
        row.name.clone()
    };
    let name_style = if row.is_dir {
        theme::label()
    } else {
        theme::primary()
    };
    let mut spans = vec![Span::raw(indent), Span::styled(name, name_style)];
    if row.finding_count > 0 {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("· {}", row.finding_count),
            theme::muted(),
        ));
    }
    Line::from(spans)
}

// ── CENTER pane ──────────────────────────────────────────────────────────────

pub(super) fn center_pane_lines(
    app: &ShellApp,
    center: &WorkbenchCenter,
    width: usize,
) -> Vec<Line<'static>> {
    match &center.body {
        WorkbenchCenterBody::Code(code) => code_pane_lines(code, width),
        WorkbenchCenterBody::Dfd { empty_hint } => dfd_pane_lines(app, *empty_hint, width),
    }
}

fn dfd_pane_lines(
    app: &ShellApp,
    empty_hint: Option<&'static str>,
    width: usize,
) -> Vec<Line<'static>> {
    if let Some(hint) = empty_hint {
        return pane_empty_state(
            "no data-flow diagram",
            &[hint],
            &[("threat-model:build", "map trust zones and flows")],
        );
    }
    match threat_dfd_view(app, width.max(8)) {
        Some(diagram) => diagram.into_iter().map(dfd_line).collect(),
        None => pane_empty_state(
            "no data-flow nodes",
            &["threat model present but has no data-flow nodes."],
            &[("threat-model:build", "refresh the data-flow model")],
        ),
    }
}

fn code_pane_lines(code: &CodePaneModel, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = &code.empty_hint {
        return pane_empty_state(
            "source unavailable",
            &[hint],
            &[("open <id>", "select another finding with source context")],
        );
    }
    code.rows
        .iter()
        .map(|row| code_row_line(row, width))
        .collect()
}

fn code_row_line(row: &CodePaneRow, width: usize) -> Line<'static> {
    let code_budget = width.saturating_sub(10).max(8);
    let style = code_row_style(row);
    Line::from(vec![
        Span::styled(code_row_marker(row), style),
        Span::raw(" "),
        Span::styled(format!("{:>4}", row.number), theme::subtle()),
        Span::styled(" │ ", theme::subtle()),
        Span::styled(fit(&row.text, code_budget), style),
    ])
}

fn code_row_marker(row: &CodePaneRow) -> &'static str {
    if row.highlighted {
        "▶"
    } else if row.evidence {
        "•"
    } else {
        " "
    }
}

fn code_row_style(row: &CodePaneRow) -> ratatui::style::Style {
    if row.highlighted {
        theme::warn()
    } else if row.evidence {
        theme::accent()
    } else {
        theme::primary()
    }
}

fn dfd_line(line: crate::ui_view_models::DfdDiagramLine) -> Line<'static> {
    Line::from(Span::styled(line.text, dfd_style(line.kind)))
}

fn dfd_style(kind: DfdLineKind) -> ratatui::style::Style {
    match kind {
        DfdLineKind::Title | DfdLineKind::Zone => theme::accent(),
        DfdLineKind::Boundary => theme::warn(),
        DfdLineKind::Flow => theme::muted(),
        DfdLineKind::Node | DfdLineKind::Summary => theme::subtle(),
    }
}

// ── FINDINGS pane ────────────────────────────────────────────────────────────

pub(super) fn findings_pane_lines(model: &FindingsModel, inner: Rect) -> Vec<Line<'static>> {
    if model.rows.is_empty() {
        let mut lines = vec![filter_chip_line(&model.counts, model.total)];
        let mut ctas = vec![("scan", model.empty.hint)];
        if let Some(context_cta) = model.empty.context_cta {
            ctas.push(context_cta);
        }
        lines.extend(pane_empty_state(
            "no findings yet",
            &["the findings ledger is empty for this target."],
            &ctas,
        ));
        return lines;
    }
    let mut lines = vec![filter_chip_line(&model.counts, model.total)];
    let visible = (inner.height as usize).saturating_sub(1).max(1);
    let start = viewport_start_for_cursor(model.rows.len(), visible, model.cursor);
    let width = inner.width as usize;
    lines.extend(
        model
            .rows
            .iter()
            .skip(start)
            .take(visible)
            .map(|row| finding_row_line(row, width)),
    );
    lines
}

fn filter_chip_line(counts: &SeverityCounts, total: usize) -> Line<'static> {
    let mut spans = vec![Span::styled(format!("all:{total}"), theme::accent())];
    for (label, count, tone) in [
        ("crit", counts.critical, SeverityTone::Critical),
        ("high", counts.high, SeverityTone::High),
        ("med", counts.medium, SeverityTone::Medium),
        ("low", counts.low, SeverityTone::Low),
    ] {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("{label}:{count}"),
            theme::severity_tone(tone),
        ));
    }
    Line::from(spans)
}

fn finding_row_line(row: &FindingListRow, width: usize) -> Line<'static> {
    let (marker, marker_style) = row_marker(row);
    let title_budget = width.saturating_sub(20).max(8);
    Line::from(vec![
        Span::styled(marker.to_string(), marker_style),
        Span::styled(pad(&row.alias, 7), theme::accent()),
        Span::raw(" "),
        Span::styled(
            severity_chip(row.severity_tone),
            theme::severity_tone(row.severity_tone),
        ),
        Span::raw(" "),
        Span::styled(
            fit(&row.title, title_budget),
            theme::severity_tone(row.severity_tone),
        ),
    ])
}

fn severity_chip(tone: SeverityTone) -> String {
    pad(
        match tone {
            SeverityTone::Critical => "CRIT",
            SeverityTone::High => "HIGH",
            SeverityTone::Medium => "MED",
            SeverityTone::Low => "LOW",
            SeverityTone::Info => "INFO",
            SeverityTone::Unknown => "UNK",
        },
        5,
    )
}

fn row_marker(row: &FindingListRow) -> (&'static str, ratatui::style::Style) {
    if row.cursor {
        ("▌ ", theme::accent())
    } else if row.selected {
        ("* ", theme::warn())
    } else {
        ("  ", theme::subtle())
    }
}
