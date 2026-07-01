//! Finding detail line builder for the Workbench DETAILS pane.

use super::panes::sep;
use super::*;
use crate::ui_view_models::{FindingDetailModel, FindingEvidenceRow, TriageSummaryModel};
use ratatui::prelude::{Line, Span};
use ratatui::style::Style;

pub(super) fn detail_pane_lines(
    detail: &Option<FindingDetailModel>,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(detail) = detail else {
        return no_detail_lines();
    };
    let budget = width.saturating_sub(2).max(16);
    detail_lines_for_model(detail, budget)
}

fn no_detail_lines() -> Vec<Line<'static>> {
    vec![muted(
        "no finding selected — press Enter on a FINDINGS row to inspect it.",
    )]
}

fn detail_lines_for_model(detail: &FindingDetailModel, budget: usize) -> Vec<Line<'static>> {
    let mut lines = detail_title_lines(detail, budget);
    lines.push(blank_line());
    push_detail_metadata(&mut lines, detail, budget);
    push_message_section(&mut lines, detail, budget);
    push_triage_section(&mut lines, &detail.triage, budget);
    push_evidence_section(&mut lines, &detail.evidence, budget);
    push_fingerprint_section(&mut lines, detail, budget);
    lines
}

fn push_detail_metadata(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    push_detail_kv(lines, "location", &detail.location, budget);
    push_detail_kv(lines, "rule", &detail.rule, budget);
    push_detail_kv(lines, "tool", &detail.tool, budget);
    push_detail_kv(lines, "proof", &detail.proof_state, budget);
    push_detail_kv(lines, "verification", &detail.runtime_verification, budget);
}

fn push_message_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    lines.push(section_line("MESSAGE"));
    if detail.message_lines.is_empty() {
        lines.push(muted("  no message recorded"));
        return;
    }
    for message in &detail.message_lines {
        push_wrapped(lines, message, budget, "  ", theme::primary());
    }
}

fn push_triage_section(
    lines: &mut Vec<Line<'static>>,
    triage: &Option<TriageSummaryModel>,
    budget: usize,
) {
    let Some(triage) = triage else {
        return;
    };
    lines.push(section_line("TRIAGE"));
    push_wrapped(
        lines,
        &format!("{} · confidence {}", triage.verdict, triage.confidence),
        budget,
        "  ",
        theme::label(),
    );
    push_wrapped(lines, &triage.rationale, budget, "  ", theme::muted());
}

fn push_evidence_section(
    lines: &mut Vec<Line<'static>>,
    evidence: &[FindingEvidenceRow],
    budget: usize,
) {
    lines.push(section_line("EVIDENCE"));
    if evidence.is_empty() {
        lines.push(muted("  no evidence rows recorded"));
        return;
    }
    for (index, row) in evidence.iter().enumerate() {
        push_evidence_row(lines, row, budget, index > 0);
    }
}

fn push_evidence_row(
    lines: &mut Vec<Line<'static>>,
    evidence: &FindingEvidenceRow,
    budget: usize,
    separated: bool,
) {
    if separated {
        lines.push(blank_line());
    }
    push_wrapped(lines, &evidence.header, budget, "  ", theme::label());
    push_optional_wrapped(lines, &evidence.snippet, budget, "    ", theme::primary());
    push_optional_wrapped(lines, &evidence.rationale, budget, "    ", theme::muted());
}

fn push_fingerprint_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    lines.push(section_line("FINGERPRINT"));
    push_wrapped(lines, &detail.fingerprint, budget, "  ", theme::subtle());
}

fn detail_title_lines(detail: &FindingDetailModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::styled(
            detail
                .alias
                .clone()
                .unwrap_or_else(|| "selected".to_string()),
            theme::accent(),
        ),
        sep(),
        Span::styled(
            detail.severity_label.to_uppercase(),
            theme::severity_tone(detail.severity_tone),
        ),
    ])];
    push_wrapped(&mut lines, &detail.title, width, "", theme::heading());
    lines
}

fn push_detail_kv(lines: &mut Vec<Line<'static>>, key: &'static str, value: &str, width: usize) {
    if value.trim().is_empty() || value == "-" {
        return;
    }
    push_wrapped(lines, &format!("{key}: {value}"), width, "", theme::muted());
}

fn section_line(label: &'static str) -> Line<'static> {
    Line::from(Span::styled(label, theme::accent()))
}

fn blank_line() -> Line<'static> {
    Line::raw(String::new())
}

fn push_wrapped(
    lines: &mut Vec<Line<'static>>,
    value: &str,
    width: usize,
    prefix: &'static str,
    style: Style,
) {
    let budget = width.saturating_sub(prefix.chars().count()).max(8);
    for chunk in crate::renderer::shared::text::wrap_text(value, budget) {
        lines.push(Line::from(vec![
            Span::raw(prefix.to_string()),
            Span::styled(chunk, style),
        ]));
    }
}

fn push_optional_wrapped(
    lines: &mut Vec<Line<'static>>,
    value: &str,
    width: usize,
    prefix: &'static str,
    style: Style,
) {
    if value.trim().is_empty() {
        return;
    }
    push_wrapped(lines, value, width, prefix, style);
}
