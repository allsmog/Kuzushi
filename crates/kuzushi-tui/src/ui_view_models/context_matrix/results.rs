use crate::app::{BatchScanConfig, ShellApp};
use crate::renderer::shared::text::{fit, fit_path, wrap_text};
use kuzushi_core::findings::{ContextCaseOccurrenceReport, ContextMatrixOccurrenceReport};

pub(super) fn recorded_matrix_lines(
    app: &ShellApp,
    report: &ContextMatrixOccurrenceReport,
    width: usize,
    rows: usize,
) -> Vec<String> {
    let Some(config) = app.router.campaign().batch_scan_config.as_ref() else {
        return vec![fit(
            "Study configuration unavailable. Reopen the study to read results.",
            width,
        )];
    };
    if config.study.matrix.pass_selection.is_some() {
        return pass_lines(config, report, width, rows);
    }
    let mut lines = heading(config, width);
    let available = rows.saturating_sub(lines.len());
    let count = available.saturating_sub(2).max(1).min(report.cases.len());
    let selected = config.study.matrix.cursor;
    let start = selected.saturating_sub(count.saturating_sub(1));
    append_cases(&mut lines, report, selected, start, count, width);
    append_detail(&mut lines, config, report, width, rows);
    lines.truncate(rows);
    lines
}

fn heading(config: &BatchScanConfig, width: usize) -> Vec<String> {
    let mut lines = vec![fit("Absence never establishes a fix.", width)];
    lines.extend(config.notice.iter().map(|notice| fit(notice, width)));
    lines
}

fn append_cases(
    lines: &mut Vec<String>,
    report: &ContextMatrixOccurrenceReport,
    selected: usize,
    start: usize,
    count: usize,
    width: usize,
) {
    for (index, case) in report.cases.iter().enumerate().skip(start).take(count) {
        let marker = if index == selected { "▸" } else { " " };
        let counts = format!(
            "{marker} {}/{} complete · ",
            case.occurrence.completed, case.occurrence.planned
        );
        let label = fit_path(&case.label, width.saturating_sub(counts.chars().count()));
        lines.push(format!("{counts}{label}"));
    }
}

fn detail_lines(case: &ContextCaseOccurrenceReport, width: usize) -> Vec<String> {
    let mut lines = vec![format!(
        "{} failed · {} pending",
        case.occurrence.failed, case.occurrence.pending
    )];
    for row in &case.occurrence.rows {
        lines.push(format!(
            "observed {} / {} · {}",
            row.seen, case.occurrence.completed, row.representative_title
        ));
    }
    if case.occurrence.rows.is_empty() {
        lines.push("No recorded observations. Decisions stay unchanged.".into());
    }
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn append_detail(
    lines: &mut Vec<String>,
    config: &BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    width: usize,
    rows: usize,
) {
    let Some(case) = report.cases.get(config.study.matrix.cursor) else {
        return;
    };
    let detail = detail_lines(case, width);
    let count = rows.saturating_sub(lines.len());
    let start = config
        .study
        .matrix
        .detail_scroll
        .min(detail.len().saturating_sub(count));
    lines.extend(detail.into_iter().skip(start).take(count));
}

fn pass_case<'a>(
    config: &BatchScanConfig,
    report: &'a ContextMatrixOccurrenceReport,
) -> Option<&'a ContextCaseOccurrenceReport> {
    if config.study.matrix.pass_selection == Some(true) {
        return report
            .cases
            .iter()
            .find(|case| case.id == report.baseline_case_id);
    }
    report.cases.get(config.study.matrix.cursor)
}

fn pass_lines(
    config: &BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    width: usize,
    rows: usize,
) -> Vec<String> {
    let Some(case) = pass_case(config, report) else {
        return vec!["Recorded case is unavailable. r refreshes.".into()];
    };
    let mut lines = vec![fit(&format!("Choose {} pass", case.label), width)];
    lines.extend(config.notice.iter().map(|notice| fit(notice, width)));
    let count = rows.saturating_sub(lines.len()).max(1);
    let selected = config.study.matrix.pass_cursor;
    let start = selected.saturating_sub(count.saturating_sub(1));
    for (index, trial) in case
        .occurrence
        .trials
        .iter()
        .enumerate()
        .skip(start)
        .take(count)
    {
        lines.push(fit(
            &format!(
                "{} Pass {} · {}",
                if index == selected { "▸" } else { " " },
                index + 1,
                trial.state
            ),
            width,
        ));
    }
    lines.truncate(rows);
    lines
}
