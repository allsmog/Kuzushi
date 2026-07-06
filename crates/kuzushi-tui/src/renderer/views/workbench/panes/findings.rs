#![cfg_attr(test, allow(dead_code))]

use super::*;
#[cfg(test)]
use crate::ui_view_models::SeverityTone;
#[cfg(test)]
use crate::ui_view_models::{
    CleanScanEmptyState, FilteredFindingsEmptyState, FindingListRow, FindingsEmptyState,
    FindingsModel, ProofTier,
};
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Span};

#[cfg(test)]
const FINDING_PROOF_LEGEND_MIN_HEIGHT: u16 = 10;
#[cfg(test)]
const FINDING_FULL_PROOF_MIN_WIDTH: usize = 56;
#[cfg(test)]
const FINDING_PROOF_LEGEND_MIN_WIDTH: u16 = 72;
#[cfg(test)]
const FINDING_FULL_SIGNAL_MIN_WIDTH: usize = 96;
#[cfg(test)]
const FINDING_FULL_METADATA_MIN_WIDTH: usize = 160;

#[cfg(test)]
pub(in crate::renderer::views::workbench) fn findings_pane_lines(
    model: &FindingsModel,
    inner: Rect,
) -> Vec<Line<'static>> {
    if model.rows.is_empty() {
        return empty_findings_pane_lines(model);
    }
    populated_findings_pane_lines(model, inner)
}

#[cfg(test)]
fn empty_findings_pane_lines(model: &FindingsModel) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(filtered) = &model.empty.filtered_out {
        lines.extend(filtered_empty_lines(filtered, &model.empty.ledger));
    } else if let Some(clean_scan) = &model.empty.clean_scan {
        lines.extend(clean_scan_empty_lines(clean_scan, &model.empty.ledger));
    } else {
        lines.extend(unscanned_empty_lines(&model.empty));
    }
    lines
}

#[cfg(test)]
fn filtered_empty_lines(filtered: &FilteredFindingsEmptyState, ledger: &str) -> Vec<Line<'static>> {
    let summary = format!("active filter matched no rows: {}", filtered.expression);
    let details = [
        summary.as_str(),
        "scanner findings were not changed; only this review list is empty.",
        ledger,
    ];
    let ctas = [
        ("findings", "clear the filter and reload all findings"),
        ("findings filter <expr>", "try another review filter"),
    ];
    pane_empty_state("filtered out", &details, &ctas)
}

#[cfg(test)]
fn clean_scan_empty_lines(clean_scan: &CleanScanEmptyState, ledger: &str) -> Vec<Line<'static>> {
    let details = [clean_scan.summary.as_str(), ledger];
    let ctas = [
        ("scan", "rerun scanners"),
        (
            "workspace export findings report.sarif",
            "export the clean report",
        ),
    ];
    pane_empty_state("0 findings", &details, &ctas)
}

#[cfg(test)]
fn unscanned_empty_lines(empty: &FindingsEmptyState) -> Vec<Line<'static>> {
    let mut ctas = vec![("scan", empty.hint)];
    if let Some(context_cta) = empty.context_cta {
        ctas.push(context_cta);
    }
    let details = [
        "the findings ledger is empty for this target.",
        empty.ledger.as_str(),
    ];
    pane_empty_state("no findings yet", &details, &ctas)
}

#[cfg(test)]
fn populated_findings_pane_lines(model: &FindingsModel, inner: Rect) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if inner.width >= 72 {
        lines.push(Line::styled(
            fit(&model.reconciliation_header, inner.width as usize),
            theme::muted(),
        ));
    }
    if should_show_proof_legend(inner.height, inner.width) {
        lines.push(proof_legend_line());
    }
    if let Some(notice) = &model.selected_out_of_window {
        lines.push(Line::styled(
            fit(notice, inner.width as usize),
            theme::warn(),
        ));
    }
    let chrome_rows = lines.len();
    let visible = (inner.height as usize).saturating_sub(chrome_rows).max(1);
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

#[cfg(test)]
fn should_show_proof_legend(height: u16, width: u16) -> bool {
    height >= FINDING_PROOF_LEGEND_MIN_HEIGHT && width >= FINDING_PROOF_LEGEND_MIN_WIDTH
}

#[cfg(test)]
fn proof_legend_line() -> Line<'static> {
    Line::from(vec![
        Span::styled("proof ", theme::muted()),
        proof_legend_span("✓ runtime", ProofTier::RuntimeVerified),
        Span::styled(" · ", theme::subtle()),
        proof_legend_span("◇ static", ProofTier::StaticLinked),
        Span::styled(" · ", theme::subtle()),
        proof_legend_span("? suspected", ProofTier::Suspected),
        Span::styled(" · ", theme::subtle()),
        proof_legend_span("! rejected", ProofTier::Rejected),
    ])
}

#[cfg(test)]
fn proof_legend_span(label: &'static str, tier: ProofTier) -> Span<'static> {
    Span::styled(label, proof_tier_style(tier))
}

#[cfg(test)]
fn finding_row_line(row: &FindingListRow, width: usize) -> Line<'static> {
    let (marker, marker_style) = row_marker(row);
    let signals = row_signal_text(row, width);
    let signals_width = signal_width(width);
    let title_budget = finding_title_budget(width, signals_width);
    let mut spans = vec![
        Span::styled(marker.to_string(), marker_style),
        Span::styled(pad(&row.alias, 7), row_alias_style(row)),
        Span::raw(" "),
        Span::styled(
            severity_glyph(row.severity_tone),
            row_style(row, theme::severity_tone(row.severity_tone)),
        ),
        Span::raw(" "),
        Span::styled(
            pad(&signals, signals_width),
            row_style(row, proof_label_style(row)),
        ),
        Span::raw(" "),
    ];
    spans.push(Span::styled(
        fit(&row_title_text(row, width), title_budget),
        row_style(row, theme::primary()),
    ));
    Line::from(spans)
}

#[cfg(test)]
fn row_style(row: &FindingListRow, fallback: ratatui::style::Style) -> ratatui::style::Style {
    if row.cursor {
        theme::selection()
    } else {
        fallback
    }
}

#[cfg(test)]
fn row_alias_style(row: &FindingListRow) -> ratatui::style::Style {
    row_style(row, theme::label())
}

#[cfg(test)]
fn finding_title_budget(width: usize, proof_width: usize) -> usize {
    let prefix_width = 2 + 7 + 1 + 1 + 1 + proof_width + 1;
    width.saturating_sub(prefix_width).max(8)
}

#[cfg(test)]
fn row_signal_text(row: &FindingListRow, width: usize) -> String {
    if width < FINDING_FULL_PROOF_MIN_WIDTH {
        return row.proof_marker.to_string();
    }
    if width < FINDING_FULL_SIGNAL_MIN_WIDTH {
        return compact_signal_summary(row);
    }
    if width >= FINDING_FULL_METADATA_MIN_WIDTH {
        return full_signal_summary_with_identity(row, signal_width(width));
    }
    full_signal_summary(row, signal_width(width))
}

#[cfg(test)]
fn signal_width(width: usize) -> usize {
    if width < FINDING_FULL_PROOF_MIN_WIDTH {
        1
    } else if width < FINDING_FULL_SIGNAL_MIN_WIDTH {
        8
    } else if width >= FINDING_FULL_METADATA_MIN_WIDTH {
        width.saturating_sub(58).clamp(82, 110)
    } else {
        width.saturating_sub(38).clamp(54, 82)
    }
}

#[cfg(test)]
fn proof_label_style(row: &FindingListRow) -> ratatui::style::Style {
    proof_tier_style(row.proof_tier)
}

#[cfg(test)]
fn proof_tier_style(tier: ProofTier) -> ratatui::style::Style {
    match tier {
        ProofTier::RuntimeVerified => theme::success(),
        ProofTier::StaticLinked => theme::accent(),
        ProofTier::Suspected => theme::muted(),
        ProofTier::Rejected => theme::danger(),
    }
}

#[cfg(test)]
fn compact_signal_summary(row: &FindingListRow) -> String {
    format!("{} {}", row.priority_label, row.proof_marker)
}

#[cfg(test)]
fn row_title_text(row: &FindingListRow, width: usize) -> String {
    if width < FINDING_FULL_METADATA_MIN_WIDTH {
        return row.title.clone();
    }
    format!("{} · {}", row.title, row.location)
}

#[cfg(test)]
fn full_signal_summary_with_identity(row: &FindingListRow, width: usize) -> String {
    fit(
        &format!(
            "{} {} conf:{} status:{}{} decision:{} proof:{}{}",
            row.identity_label,
            row.priority_label,
            row.confidence,
            row.lifecycle_status,
            row_conflict_segment(row),
            row_decision_label(row),
            row.proof_marker,
            row.proof_label
        ),
        width,
    )
}

#[cfg(test)]
fn full_signal_summary(row: &FindingListRow, width: usize) -> String {
    fit(
        &format!(
            "{} conf:{} status:{}{} decision:{} proof:{}{}",
            row.priority_label,
            row.confidence,
            row.lifecycle_status,
            row_conflict_segment(row),
            row_decision_label(row),
            row.proof_marker,
            row.proof_label
        ),
        width,
    )
}

#[cfg(test)]
fn row_conflict_segment(row: &FindingListRow) -> String {
    row.decision_conflict
        .as_ref()
        .map(|_| " conflict:reappeared".to_string())
        .unwrap_or_default()
}

#[cfg(test)]
fn row_decision_label(row: &FindingListRow) -> &str {
    if row.decision_conflict.is_some() && row.decision == "rejected_false_positive" {
        return "rejected_fp";
    }
    &row.decision
}

#[cfg(test)]
fn severity_glyph(tone: SeverityTone) -> &'static str {
    match tone {
        SeverityTone::Critical => "C",
        SeverityTone::High => "H",
        SeverityTone::Medium => "M",
        SeverityTone::Low => "L",
        SeverityTone::Info => "I",
        SeverityTone::Unknown => "?",
    }
}

#[cfg(test)]
fn row_marker(row: &FindingListRow) -> (&'static str, ratatui::style::Style) {
    if row.cursor {
        ("  ", theme::selection())
    } else if row.selected {
        ("▌ ", theme::warn())
    } else {
        ("  ", theme::subtle())
    }
}

#[cfg(test)]
#[path = "findings/tests.rs"]
mod tests;
