use crate::app::BatchScanConfig;
use crate::renderer::shared::text::{fit, fit_path, wrap_text};
use kuzushi_core::findings::{ContextCaseOccurrenceReport, ContextMatrixOccurrenceReport};

pub(super) fn recorded_matrix_lines(
    config: &BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    width: usize,
    rows: usize,
) -> Vec<String> {
    if config.study.matrix.observation_key.is_some() {
        return super::observations::lines(config, report, width, rows);
    }
    if config.study.matrix.pass_selection.is_some() {
        return pass_lines(config, report, width, rows);
    }
    let mut lines = heading(config, width);
    let available = rows.saturating_sub(lines.len());
    let count = case_count(available, report.cases.len());
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

pub(super) fn unavailable_lines(error: &str, width: usize) -> Vec<String> {
    [
        "Recorded results unavailable.",
        "r retries the read; no work starts.",
        error,
    ]
    .into_iter()
    .flat_map(|line| wrap_text(line, width.max(1)))
    .collect()
}

pub(super) fn failure_lines(
    config: &BatchScanConfig,
    error: &str,
    width: usize,
    rows: usize,
) -> Vec<String> {
    let lines = unavailable_lines(error, width);
    let start = config
        .study
        .matrix
        .detail_scroll
        .min(lines.len().saturating_sub(rows));
    lines.into_iter().skip(start).take(rows).collect()
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
        let role = if case.id == report.baseline_case_id {
            "baseline"
        } else {
            "candidate"
        };
        let counts = format!(
            "{marker} {}/{} · {role} · ",
            case.occurrence.completed, case.occurrence.planned
        );
        let label = fit_path(&case.label, width.saturating_sub(counts.chars().count()));
        lines.push(format!("{counts}{label}"));
    }
}

fn case_count(available: usize, cases: usize) -> usize {
    available.saturating_sub(3).max(1).min(cases)
}

pub(super) fn detail_capacity(
    config: &BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    rows: usize,
) -> usize {
    let available = rows.saturating_sub(heading(config, 1).len());
    available.saturating_sub(case_count(available, report.cases.len()))
}

pub(super) fn detail_lines(
    config: &BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    case: &ContextCaseOccurrenceReport,
    width: usize,
) -> Vec<String> {
    super::result_detail::recorded_case_detail(config, report, case)
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
    let detail = detail_lines(config, report, case, width);
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
