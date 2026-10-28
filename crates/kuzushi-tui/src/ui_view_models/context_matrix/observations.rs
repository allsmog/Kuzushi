//! Recorded case rows link to Review without changing recurrence or confidence.
use super::*;
use kuzushi_core::findings::{
    BatchOccurrenceRow, ContextCaseOccurrenceReport, ContextMatrixOccurrenceReport,
};

fn selected<'a>(
    config: &BatchScanConfig,
    report: &'a ContextMatrixOccurrenceReport,
) -> Option<(&'a ContextCaseOccurrenceReport, usize)> {
    let matrix = &config.study.matrix;
    let case = report.cases.get(matrix.cursor)?;
    let index = case
        .occurrence
        .rows
        .iter()
        .position(|row| Some(&row.fold_key) == matrix.observation_key.as_ref())?;
    Some((case, index))
}

fn list_capacity(rows: usize, count: usize) -> usize {
    (rows / 3).max(1).min(count)
}

fn detail(config: &BatchScanConfig, row: &BatchOccurrenceRow, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    lines.extend(config.study.matrix.observation_notice.iter().cloned());
    crate::ui_view_models::occurrence_evidence::append_observation_summary(
        &mut lines,
        row,
        row.completed,
    );
    lines.push(row.representative_observation_ref.as_ref().map_or_else(
        || "Exact observation unavailable. Refresh before opening Review.".into(),
        |reference| format!("Recorded observation: {reference}"),
    ));
    lines.push("Review shows evidence confidence and recorded decisions. Recurrence does not establish proof.".into());
    lines
        .into_iter()
        .flat_map(|line| {
            crate::renderer::shared::text::wrap_document_text(&line, width.max(1), width.max(1))
        })
        .collect()
}

pub(super) fn read_limits(
    config: &BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    body: ratatui::layout::Rect,
) -> Option<MatrixResultReadLimits> {
    let (case, index) = selected(config, report)?;
    let page = usize::from(body.height)
        .saturating_sub(1 + list_capacity(body.height.into(), case.occurrence.rows.len()))
        .max(1);
    let total_lines = detail(config, &case.occurrence.rows[index], body.width.into()).len();
    Some(MatrixResultReadLimits {
        page,
        total_lines,
        max_scroll: total_lines.saturating_sub(page),
    })
}

pub(super) fn lines(
    config: &BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    width: usize,
    rows: usize,
) -> Vec<String> {
    let Some((case, index)) = selected(config, report) else {
        return wrap_text("The selected observation is unavailable. Choose another, refresh, or Esc back to cases.", width.max(1));
    };
    let mut lines = vec![fit_path(
        &format!("Recorded findings: {}", case.label),
        width,
    )];
    let count = list_capacity(rows, case.occurrence.rows.len());
    let start = index.saturating_sub(count.saturating_sub(1));
    append_rows(&mut lines, case, start, count, index, width);
    let detail = detail(config, &case.occurrence.rows[index], width);
    let remaining = rows.saturating_sub(lines.len());
    let scroll = config
        .study
        .matrix
        .observation_scroll
        .min(detail.len().saturating_sub(remaining));
    lines.extend(detail.into_iter().skip(scroll).take(remaining));
    lines
}

fn append_rows(
    lines: &mut Vec<String>,
    case: &ContextCaseOccurrenceReport,
    start: usize,
    count: usize,
    index: usize,
    width: usize,
) {
    for (position, row) in case
        .occurrence
        .rows
        .iter()
        .enumerate()
        .skip(start)
        .take(count)
    {
        let marker = if position == index { "▸" } else { " " };
        let prefix = format!("{marker} {} · ", row.representative_severity);
        let title_width =
            width.saturating_sub(unicode_width::UnicodeWidthStr::width(prefix.as_str()));
        lines.push(format!(
            "{prefix}{}",
            crate::renderer::shared::text::fit(&row.representative_title, title_width)
        ));
    }
}
