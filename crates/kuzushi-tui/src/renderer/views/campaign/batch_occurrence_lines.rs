use super::*;
use kuzushi_core::capabilities::campaign::{
    BatchOperationalStatus, BatchSecurityGateStatus, ScanBatchGateOutcome,
};
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
        theme::subtle(),
    ));
    if let Some(gate) = &report.gate {
        lines.extend(batch_wrapped(
            &batch_gate_summary(gate),
            area.width as usize,
            theme::subtle(),
        ));
    }
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
        return;
    }
    lines.extend(
        report
            .rows
            .iter()
            .flat_map(|row| batch_occurrence_row(row, area.width as usize)),
    );
}

fn batch_gate_summary(gate: &ScanBatchGateOutcome) -> String {
    format!(
        "  gate {} · operational {} · security {} · blocking {} · SARIF {}",
        gate.status.as_str(),
        operational_status_label(gate.operational_status),
        security_status_label(gate.security_status),
        gate.blocking_safe_fold_count,
        if gate.sarif_written {
            "written"
        } else {
            "not written"
        }
    )
}

fn operational_status_label(status: BatchOperationalStatus) -> &'static str {
    match status {
        BatchOperationalStatus::Complete => "complete",
        BatchOperationalStatus::Incomplete => "incomplete",
    }
}

fn security_status_label(status: BatchSecurityGateStatus) -> &'static str {
    match status {
        BatchSecurityGateStatus::Disabled => "disabled",
        BatchSecurityGateStatus::Passed => "passed",
        BatchSecurityGateStatus::Failed => "failed",
    }
}

fn batch_summary(report: &BatchOccurrenceReport) -> String {
    format!(
        "  completed {} / planned {} · failed {} · pending {} · equivalence {}",
        report.completed, report.planned, report.failed, report.pending, report.equivalence_key
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
        theme::subtle(),
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
