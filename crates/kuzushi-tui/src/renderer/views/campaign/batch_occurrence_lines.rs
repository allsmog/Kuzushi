use super::*;
use kuzushi_core::findings::presentation::batch_severity_summary;
use kuzushi_core::findings::{BatchOccurrenceReport, BatchOccurrenceRow};

pub(super) fn append_batch_occurrence(
    lines: &mut Vec<Line<'static>>,
    report: &BatchOccurrenceReport,
    area: Rect,
) {
    lines.push(blank());
    lines.push(divider("BATCH OCCURRENCE", area.width));
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
        "Occurrence counts completed trials; it does not establish proof.",
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
        "  completed {} / planned {} · failed {} · pending {}",
        report.completed, report.planned, report.failed, report.pending
    )
}

fn batch_occurrence_row(row: &BatchOccurrenceRow, width: usize) -> Vec<Line<'static>> {
    let title = format!(
        "{} · {}",
        row.representative_severity, row.representative_title
    );
    let mut lines = vec![blank()];
    lines.extend(batch_wrapped(&title, width, theme::primary()));
    if let Some(hint) = row.completed_pass_hint() {
        lines.extend(batch_wrapped(hint, width, theme::muted()));
    }
    lines.extend(batch_wrapped(
        &format!(
            "seen {} / completed {} · planned {} · failed {}",
            row.seen, row.completed, row.planned, row.failed
        ),
        width,
        theme::primary(),
    ));
    lines.extend(batch_wrapped(
        &row.representative_location,
        width,
        theme::primary(),
    ));
    lines.extend(batch_wrapped(
        &format!("finding {}", row.representative_fingerprint),
        width,
        theme::subtle(),
    ));
    let runs = if row.run_ids.is_empty() {
        "runs —".to_string()
    } else {
        format!("runs {}", row.run_ids.join(", "))
    };
    lines.extend(batch_wrapped(&runs, width, theme::subtle()));
    lines
}

fn batch_wrapped(text: &str, width: usize, style: ratatui::style::Style) -> Vec<Line<'static>> {
    wrap_text(text.trim(), width.saturating_sub(2).max(1))
        .into_iter()
        .map(|line| Line::styled(format!("  {line}"), style))
        .collect()
}

#[cfg(test)]
mod tests;
