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
    lines.push(Line::styled(batch_summary(report), theme::subtle()));
    if let Some(gate) = &report.gate {
        lines.push(Line::styled(batch_gate_summary(gate), theme::subtle()));
    }
    lines.push(Line::styled(
        "  OCCURRENCE                          SEVERITY  LOCATION  TITLE · RUNS",
        theme::muted(),
    ));
    if report.rows.is_empty() {
        lines.push(Line::styled(
            "  no findings observed in completed logical trials",
            theme::muted(),
        ));
        return;
    }
    lines.extend(
        report
            .rows
            .iter()
            .map(|row| batch_occurrence_row(row, area.width as usize)),
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

fn batch_occurrence_row(row: &BatchOccurrenceRow, width: usize) -> Line<'static> {
    let occurrence = format!(
        "seen {} / completed {} · planned {} · failed {}",
        row.seen, row.completed, row.planned, row.failed
    );
    let runs = if row.run_ids.is_empty() {
        "runs —".to_string()
    } else {
        format!("runs {}", row.run_ids.join(","))
    };
    let label = format!(
        "  {occurrence:<36} {:<9} {}  {} · {runs}",
        row.representative_severity, row.representative_location, row.representative_title
    );
    Line::styled(fit(&label, width), theme::primary())
}
