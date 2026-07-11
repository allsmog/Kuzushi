use super::*;
use crate::ui_view_models::{ReviewQueueModel, ReviewQueueRow, SeverityTone};
use kuzushi_core::ProofConfidence;
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Span};

const REVIEW_FULL_SIGNAL_MIN_WIDTH: usize = 96;
const REVIEW_FULL_METADATA_MIN_WIDTH: usize = 96;

pub(in crate::renderer::views::workbench) fn review_queue_pane_lines(
    model: &ReviewQueueModel,
    inner: Rect,
) -> Vec<Line<'static>> {
    if model.rows.is_empty() {
        return review_queue_empty_lines(model, inner.width as usize);
    }
    populated_review_queue_pane_lines(model, inner)
}

fn review_queue_empty_lines(model: &ReviewQueueModel, width: usize) -> Vec<Line<'static>> {
    let reason = model
        .empty_reason
        .as_deref()
        .unwrap_or("no review rows match this mode");
    vec![
        Line::styled("∅ review queue empty", theme::muted()),
        Line::raw(fit(reason, width)),
        Line::styled("▸ findings", theme::accent()),
        Line::styled("▸ filter completeness:open", theme::accent()),
    ]
}

fn populated_review_queue_pane_lines(model: &ReviewQueueModel, inner: Rect) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if inner.width >= 72 {
        lines.push(Line::styled(
            fit(
                &review_queue_reconciliation_line(model),
                inner.width as usize,
            ),
            theme::muted(),
        ));
    }
    let chrome_rows = lines.len();
    let visible = (inner.height as usize).saturating_sub(chrome_rows).max(1);
    let cursor = model.rows.iter().position(|row| row.selected).unwrap_or(0);
    let start = viewport_start_for_cursor(model.rows.len(), visible, cursor);
    let width = inner.width as usize;
    lines.extend(
        model
            .rows
            .iter()
            .skip(start)
            .take(visible)
            .map(|row| review_queue_row_line(row, width)),
    );
    lines
}

fn review_queue_reconciliation_line(model: &ReviewQueueModel) -> String {
    format!(
        "{} · mode:{} · filter:{}",
        model.header, model.completeness_mode, model.filter_label
    )
}

fn review_queue_row_line(row: &ReviewQueueRow, width: usize) -> Line<'static> {
    let signals = review_queue_signal_text(row, width);
    let signals_width = review_queue_signal_width(width);
    let chip = review_queue_confidence_chip(row, width);
    let title_budget = review_queue_title_budget(width, signals_width, chip.chars().count());
    if row.selected {
        return selected_review_queue_row(row, width, &signals, signals_width, &chip, title_budget);
    }
    Line::from(vec![
        Span::styled(" ", theme::muted()),
        Span::styled(
            pad(&row.alias, 7),
            review_queue_row_style(row, theme::label()),
        ),
        Span::raw(" "),
        Span::styled(
            severity_glyph(row.severity_tone),
            review_queue_row_style(row, theme::severity_tone(row.severity_tone)),
        ),
        Span::raw(" "),
        Span::styled(
            chip,
            review_queue_row_style(row, theme::proof_confidence_tone(row.proof_confidence)),
        ),
        Span::raw(" "),
        Span::styled(
            pad(&signals, signals_width),
            review_queue_row_style(row, review_queue_decision_style(row)),
        ),
        Span::raw(" "),
        Span::styled(
            fit(&review_queue_title_text(row, width), title_budget),
            review_queue_row_style(row, theme::primary()),
        ),
    ])
}

fn selected_review_queue_row(
    row: &ReviewQueueRow,
    width: usize,
    signals: &str,
    signals_width: usize,
    chip: &str,
    title_budget: usize,
) -> Line<'static> {
    let body = format!(
        "▸{} {} {} {} {}",
        pad(&row.alias, 7),
        severity_glyph(row.severity_tone),
        chip,
        pad(signals, signals_width),
        fit(&review_queue_title_text(row, width), title_budget),
    );
    Line::styled(pad(&fit(&body, width), width), theme::selection())
}

/// The confidence chip that sits between the severity glyph and the decision
/// signals. Full word (`CONFIRMED`) at readable widths, a one-char marker
/// (`✓ ◇ ? !`) when the row is too narrow to spend on a word.
fn review_queue_confidence_chip(row: &ReviewQueueRow, width: usize) -> String {
    if width < REVIEW_FULL_METADATA_MIN_WIDTH {
        return proof_confidence_code(row).to_string();
    }
    row.proof_confidence_label.clone()
}

fn proof_confidence_code(row: &ReviewQueueRow) -> &'static str {
    match row.proof_confidence {
        ProofConfidence::Confirmed => "rt",
        ProofConfidence::Likely => "src",
        ProofConfidence::Unverified if row.evidence_state != "message-only" => "sig",
        ProofConfidence::Unverified | ProofConfidence::Dismissed => "unv",
    }
}

fn review_queue_signal_text(row: &ReviewQueueRow, width: usize) -> String {
    if width < REVIEW_FULL_SIGNAL_MIN_WIDTH {
        return review_queue_compact_decision(row).to_string();
    }
    fit(
        &review_queue_full_signal_summary(row),
        review_queue_signal_width(width),
    )
}

fn review_queue_signal_width(width: usize) -> usize {
    if width < REVIEW_FULL_SIGNAL_MIN_WIDTH {
        10
    } else if width >= REVIEW_FULL_METADATA_MIN_WIDTH {
        width.saturating_sub(72).clamp(32, 120)
    } else {
        width.saturating_sub(38).clamp(58, 112)
    }
}

fn review_queue_title_budget(width: usize, signal_width: usize, chip_width: usize) -> usize {
    let prefix_width = 2 + 7 + 1 + 1 + 1 + chip_width + 1 + signal_width + 1;
    width.saturating_sub(prefix_width).max(8)
}

fn review_queue_title_text(row: &ReviewQueueRow, width: usize) -> String {
    if width < REVIEW_FULL_METADATA_MIN_WIDTH {
        return row.title.clone();
    }
    format!("{} · {}", row.title, row.location)
}

fn review_queue_full_signal_summary(row: &ReviewQueueRow) -> String {
    format!(
        "{} {} decision:{}{} {} next:{} status:{} conf:{}",
        row.identity_label,
        row.priority_label,
        review_queue_decision_label(row),
        review_queue_conflict_segment(row),
        row.evidence_state,
        row.next_action,
        row.lifecycle_status,
        row.confidence_label
    )
}

fn review_queue_conflict_segment(row: &ReviewQueueRow) -> String {
    row.decision_conflict
        .as_ref()
        .map(|_| " conflict:reappeared".to_string())
        .unwrap_or_default()
}

fn review_queue_decision_label(row: &ReviewQueueRow) -> &str {
    if row.decision_conflict.is_some() && row.decision == "rejected_false_positive" {
        return "rejected_fp";
    }
    &row.decision
}

fn review_queue_compact_decision(row: &ReviewQueueRow) -> &'static str {
    if row.decision_conflict.is_some() {
        return "conflict";
    }
    match row.decision.as_str() {
        "confirmed" => "confirmed",
        "rejected_false_positive" | "false_positive" => "false-pos",
        "suppressed" => "suppressed",
        "deferred" => "deferred",
        "accepted_risk" => "risk",
        _ => "open",
    }
}

fn review_queue_decision_style(row: &ReviewQueueRow) -> ratatui::style::Style {
    if row.decision_conflict.is_some() {
        return theme::warn();
    }
    match row.decision.as_str() {
        "confirmed" => theme::success(),
        "rejected_false_positive" | "false_positive" | "suppressed" => theme::accent(),
        "deferred" | "accepted_risk" => theme::warn(),
        _ => theme::muted(),
    }
}

fn review_queue_row_style(
    row: &ReviewQueueRow,
    fallback: ratatui::style::Style,
) -> ratatui::style::Style {
    if row.selected {
        theme::selection()
    } else {
        fallback
    }
}

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
mod tests {
    use super::*;
    use crate::ui_view_models::ReviewWorkflowGroup;

    fn review_row() -> ReviewQueueRow {
        ReviewQueueRow {
            alias: "F-0001".to_string(),
            identity_label: "FI-12345678".to_string(),
            severity_tone: SeverityTone::High,
            severity_label: "HIGH".to_string(),
            proof_confidence: ProofConfidence::Confirmed,
            proof_confidence_label: "CONFIRMED".to_string(),
            confidence_label: "91%".to_string(),
            priority_label: "review-order:1".to_string(),
            lifecycle_status: "statically_supported".to_string(),
            decision: "needs_review".to_string(),
            decision_conflict: None,
            decision_complete: false,
            decision_author: "unknown".to_string(),
            title: "request reaches sink".to_string(),
            location: "crates/kuzushi-tui/src/app/example.rs:42".to_string(),
            rule: "CWE-89".to_string(),
            tool: "semgrep".to_string(),
            proof_label: "source_sink_linked".to_string(),
            evidence_state: "evidence:1".to_string(),
            next_action: "validate".to_string(),
            selected: true,
            workflow_group: ReviewWorkflowGroup::NeedsReview,
        }
    }

    fn grouped_row(alias: &str, group: ReviewWorkflowGroup, selected: bool) -> ReviewQueueRow {
        let mut row = review_row();
        row.alias = alias.to_string();
        row.workflow_group = group;
        row.selected = selected;
        row
    }

    fn review_model(rows: Vec<ReviewQueueRow>) -> ReviewQueueModel {
        ReviewQueueModel {
            total_count: rows.len(),
            visible_count: rows.len(),
            open_count: rows.len(),
            complete_count: 0,
            filter_label: "completeness:all".to_string(),
            completeness_mode: "all",
            header: format!("REVIEW QUEUE - showing {} of {}", rows.len(), rows.len()),
            empty_reason: None,
            rows,
        }
    }

    fn line_text(line: Line<'static>) -> String {
        line.spans
            .into_iter()
            .map(|span| span.content.into_owned())
            .collect::<String>()
    }

    fn lines_text(lines: Vec<Line<'static>>) -> String {
        lines
            .into_iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn row_names_decision_evidence_and_next_action() {
        let row = review_row();
        let text = line_text(review_queue_row_line(&row, 140));
        let wide_text = line_text(review_queue_row_line(&row, 220));

        assert!(text.contains("F-0001"), "{text}");
        assert!(text.contains("FI-12345678"), "{text}");
        assert!(
            wide_text.contains("status:statically_supported"),
            "{wide_text}"
        );
        assert!(text.contains("decision:needs_review"), "{text}");
        assert!(text.contains("evidence:1"), "{text}");
        assert!(wide_text.contains("next:validate"), "{wide_text}");
        assert!(text.contains("request reaches sink"), "{text}");
    }

    #[test]
    fn row_shows_confidence_chip_after_severity_glyph() {
        let row = review_row();
        let wide = line_text(review_queue_row_line(&row, 220));
        // At metadata widths the full band word sits right after the severity glyph.
        assert!(wide.contains("CONFIRMED"), "{wide}");
        assert!(wide.contains("H CONFIRMED"), "{wide}");
    }

    #[test]
    fn row_collapses_confidence_to_marker_when_narrow() {
        let row = review_row();
        let narrow = line_text(review_queue_row_line(&row, 60));
        assert!(!narrow.contains("CONFIRMED"), "{narrow}");
        assert!(narrow.contains("rt"), "{narrow}");
        assert!(narrow.contains("open"), "{narrow}");
        assert!(!narrow.contains("review-order"), "{narrow}");
        assert!(!narrow.contains('✓'), "{narrow}");
    }

    #[test]
    fn row_names_reappeared_rejection_conflict() {
        let mut row = review_row();
        row.decision = "rejected_false_positive".to_string();
        row.decision_conflict = Some("reappeared_after_rejection".to_string());

        let text = line_text(review_queue_row_line(&row, 160));

        assert!(text.contains("decision:rejected_fp"), "{text}");
        assert!(text.contains("conflict:reappeared"), "{text}");
    }

    #[test]
    fn display_preserves_canonical_row_order_without_workflow_headers() {
        let model = review_model(vec![
            grouped_row("F-0001", ReviewWorkflowGroup::Closed, false),
            grouped_row("F-0002", ReviewWorkflowGroup::NeedsReview, true),
            grouped_row("F-0003", ReviewWorkflowGroup::Deferred, false),
            grouped_row("F-0004", ReviewWorkflowGroup::NeedsReview, false),
            grouped_row("F-0005", ReviewWorkflowGroup::Confirmed, false),
        ]);

        let joined = lines_text(populated_review_queue_pane_lines(
            &model,
            Rect::new(0, 0, 120, 14),
        ));
        let positions = ["F-0001", "F-0002", "F-0003", "F-0004", "F-0005"]
            .map(|label| joined.find(label).expect("projected row rendered"));

        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "{joined}"
        );
        assert!(joined.contains("▸F-0002"), "{joined}");
        assert_eq!(joined.matches('▸').count(), 1, "{joined}");
        assert!(!joined.contains("NEEDS REVIEW ·"), "{joined}");
        assert!(!joined.contains("CONFIRMED ·"), "{joined}");
        assert!(!joined.contains("DEFERRED ·"), "{joined}");
        assert!(!joined.contains("CLOSED ·"), "{joined}");
    }

    #[test]
    fn viewport_tracks_selected_finding_in_the_canonical_row_list() {
        let model = review_model(vec![
            grouped_row("F-0001", ReviewWorkflowGroup::NeedsReview, false),
            grouped_row("F-0002", ReviewWorkflowGroup::NeedsReview, false),
            grouped_row("F-0003", ReviewWorkflowGroup::Confirmed, true),
            grouped_row("F-0004", ReviewWorkflowGroup::Deferred, false),
            grouped_row("F-0005", ReviewWorkflowGroup::Closed, false),
        ]);

        let text = lines_text(populated_review_queue_pane_lines(
            &model,
            Rect::new(0, 0, 80, 5),
        ));
        assert!(text.contains("▸F-0003"), "{text}");
        assert!(text.contains("F-0004"), "{text}");
        assert!(text.contains("F-0005"), "{text}");
        assert_eq!(text.matches('▸').count(), 1, "{text}");
    }

    #[test]
    fn empty_state_says_only_queue_is_empty() {
        let model = ReviewQueueModel {
            total_count: 2,
            visible_count: 0,
            open_count: 0,
            complete_count: 2,
            filter_label: "completeness:open".to_string(),
            completeness_mode: "open",
            header: "REVIEW QUEUE - showing 0 of 2 - 0 open - 2 complete".to_string(),
            empty_reason: Some("all visible findings have terminal decisions".to_string()),
            rows: Vec::new(),
        };

        let text = lines_text(review_queue_empty_lines(&model, 80));

        assert!(text.contains("review queue empty"), "{text}");
        assert!(
            text.contains("all visible findings have terminal decisions"),
            "{text}"
        );
        assert!(text.contains("filter completeness:open"), "{text}");
    }
}
