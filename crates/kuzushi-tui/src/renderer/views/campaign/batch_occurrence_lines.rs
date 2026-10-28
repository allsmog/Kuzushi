use super::*;
use kuzushi_core::findings::presentation::batch_severity_summary;
use kuzushi_core::findings::{BatchOccurrenceReport, BatchOccurrenceRow};

pub(super) fn append_batch_occurrence(
    lines: &mut Vec<Line<'static>>,
    report: &BatchOccurrenceReport,
    area: Rect,
) {
    lines.push(blank());
    lines.push(divider("FOUND ACROSS PASSES", area.width));
    lines.extend(batch_wrapped(
        &batch_summary(report),
        area.width as usize,
        theme::primary(),
    ));
    lines.extend(batch_wrapped(
        &batch_severity_summary(report.gate.as_ref()),
        area.width as usize,
        theme::primary(),
    ));
    lines.extend(batch_wrapped(
        "How many discovery passes found each finding. Recurrence shows stability; it does not establish proof.",
        area.width as usize,
        theme::muted(),
    ));
    if report.rows.is_empty() {
        lines.extend(batch_wrapped(
            "no findings observed in completed logical trials",
            area.width as usize,
            theme::muted(),
        ));
    }
    lines.extend(
        report
            .rows
            .iter()
            .flat_map(|row| batch_occurrence_row(row, area.width as usize)),
    );
    append_batch_receipt(lines, report, area.width as usize);
}

fn append_batch_receipt(
    lines: &mut Vec<Line<'static>>,
    report: &BatchOccurrenceReport,
    width: usize,
) {
    lines.push(blank());
    lines.extend(batch_wrapped(
        &format!("Equivalence: {}", report.equivalence_key),
        width,
        theme::muted(),
    ));
    if let Some(gate) = report
        .gate
        .as_ref()
        .filter(|gate| gate.policy.sarif.is_some())
    {
        let status = if gate.sarif_written {
            "saved"
        } else {
            "not saved"
        };
        lines.extend(batch_wrapped(
            &format!("SARIF: {status}"),
            width,
            theme::muted(),
        ));
    }
}

fn batch_summary(report: &BatchOccurrenceReport) -> String {
    format!(
        "  {} of {} passes completed · {} failed · {} pending",
        report.completed, report.planned, report.failed, report.pending
    )
}

fn batch_occurrence_row(row: &BatchOccurrenceRow, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![blank()];
    lines.extend(batch_title_lines(row, width));
    if let Some(hint) = row.completed_pass_hint() {
        lines.extend(batch_wrapped(hint, width, theme::muted()));
    }
    lines.extend(batch_wrapped(
        &recurrence_label(row),
        width,
        theme::primary(),
    ));
    lines.extend(batch_wrapped(
        &row.representative_location,
        width,
        theme::accent(),
    ));
    lines.extend(batch_wrapped(
        &format!("finding id {}", row.representative_fingerprint),
        width,
        theme::subtle(),
    ));
    let runs = if row.run_ids.is_empty() {
        "found by —".to_string()
    } else {
        format!("found by {}", row.run_ids.join(", "))
    };
    lines.extend(batch_wrapped(&runs, width, theme::subtle()));
    lines
}

/// `found in 1 of 2 completed passes`, adding planned and failed passes only
/// when they differ from the completed count, so it reads as a sentence.
fn recurrence_label(row: &BatchOccurrenceRow) -> String {
    let mut label = format!(
        "found in {} of {} completed passes",
        row.seen, row.completed
    );
    if row.planned != row.completed {
        label.push_str(&format!(" · {} planned", row.planned));
    }
    if row.failed > 0 {
        label.push_str(&format!(" · {} failed", row.failed));
    }
    label
}

/// `critical · SQL injection in login…` with the severity in its tone and the
/// title bold, so each occurrence block starts with what matters.
fn batch_title_lines(row: &BatchOccurrenceRow, width: usize) -> Vec<Line<'static>> {
    let severity = row.representative_severity.as_str();
    let prefix = format!("  {severity} · ");
    let budget = width.saturating_sub(prefix.chars().count()).max(1);
    let mut titles = wrap_text(&row.representative_title, budget).into_iter();
    let first = Line::from(vec![
        Span::styled(
            format!("  {severity}"),
            theme::severity_tone(severity_tone(severity)),
        ),
        Span::styled(" · ", theme::muted()),
        Span::styled(titles.next().unwrap_or_default(), theme::heading()),
    ]);
    let indent = " ".repeat(prefix.chars().count());
    std::iter::once(first)
        .chain(titles.map(|rest| Line::styled(format!("{indent}{rest}"), theme::heading())))
        .collect()
}

fn severity_tone(severity: &str) -> crate::ui_view_models::SeverityTone {
    use crate::ui_view_models::SeverityTone;
    match severity.to_ascii_lowercase().as_str() {
        "critical" => SeverityTone::Critical,
        "high" => SeverityTone::High,
        "medium" => SeverityTone::Medium,
        "low" => SeverityTone::Low,
        "info" => SeverityTone::Info,
        _ => SeverityTone::Unknown,
    }
}

fn batch_wrapped(text: &str, width: usize, style: ratatui::style::Style) -> Vec<Line<'static>> {
    wrap_text(text.trim(), width.saturating_sub(2).max(1))
        .into_iter()
        .map(|line| Line::styled(format!("  {line}"), style))
        .collect()
}

#[cfg(test)]
mod tests;
