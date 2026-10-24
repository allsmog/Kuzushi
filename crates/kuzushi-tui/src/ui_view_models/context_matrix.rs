//! Finite case editor projection; no stores or runtime calls.
use crate::app::BatchScanConfig;
use crate::renderer::shared::text::{fit_path, wrap_text};
use kuzushi_core::capabilities::campaign::ContextCaseInput;
use kuzushi_core::capabilities::campaign::ContextMatrixReceipt;

mod controls;
mod plain;
pub(crate) use controls::matrix_result_controls;
mod result_detail;
mod results;
pub(crate) use plain::matrix_plain_lines;

pub(crate) fn case_name_notice(config: &BatchScanConfig) -> &str {
    config
        .context_case_name_edit()
        .and_then(|edit| edit.error.as_deref())
        .unwrap_or("Naming keeps context, baseline and spending unchanged.")
}

pub(crate) fn case_name_plain_lines(config: &BatchScanConfig, width: usize) -> Option<Vec<String>> {
    let edit = config.context_case_name_edit()?;
    let mut lines = vec!["NAME CONTEXT CASE".into()];
    lines.extend(wrap_text(edit.field.text(), width.max(1)));
    lines.extend(wrap_text(case_name_notice(config), width.max(1)));
    lines.push("Enter save · Esc back (keeps draft)".into());
    Some(lines)
}

pub(crate) fn matrix_result_state(
    app: &crate::app::ShellApp,
) -> crate::app::ViewDataState<Result<kuzushi_core::findings::ContextMatrixOccurrenceReport, String>>
{
    app.cached_context_matrix_report()
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MatrixResultReadLimits {
    pub(crate) page: usize,
    pub(crate) max_scroll: usize,
    pub(crate) total_lines: usize,
}

pub(crate) fn matrix_body(area: ratatui::layout::Rect, results: bool) -> ratatui::layout::Rect {
    let mut body = area.inner(ratatui::layout::Margin::new(2, 1));
    let controls = if body.width < 50 && !results { 4 } else { 3 };
    body.height = body.height.saturating_sub(controls);
    body
}

pub(crate) fn matrix_result_read_limits(
    app: &crate::app::ShellApp,
) -> Option<MatrixResultReadLimits> {
    let config = app.router.campaign().batch_scan_config.as_ref()?;
    let viewport = app.viewport();
    let body = matrix_body(
        super::study_config::study_config_area(viewport.columns, viewport.rows),
        true,
    );
    match matrix_result_state(app) {
        crate::app::ViewDataState::Ready(Ok(report)) => case_read_limits(config, &report, body),
        crate::app::ViewDataState::Ready(Err(error)) => {
            let page = usize::from(body.height).max(1);
            let count = results::unavailable_lines(&error, usize::from(body.width)).len();
            Some(MatrixResultReadLimits {
                page,
                max_scroll: count.saturating_sub(page),
                total_lines: count,
            })
        }
        _ => None,
    }
}

fn case_read_limits(
    config: &BatchScanConfig,
    report: &kuzushi_core::findings::ContextMatrixOccurrenceReport,
    body: ratatui::layout::Rect,
) -> Option<MatrixResultReadLimits> {
    let case = report.cases.get(config.study.matrix.cursor)?;
    let page = results::detail_capacity(config, report, usize::from(body.height)).max(1);
    let count = results::detail_lines(config, report, case, usize::from(body.width)).len();
    Some(MatrixResultReadLimits {
        page,
        max_scroll: count.saturating_sub(page),
        total_lines: count,
    })
}

pub(crate) fn matrix_result_lines(
    app: &crate::app::ShellApp,
    width: usize,
    rows: usize,
) -> Vec<String> {
    let Some(config) = app.router.campaign().batch_scan_config.as_ref() else {
        return wrap_text(
            "No study selected. Open a study from Campaigns to compare its cases.",
            width.max(1),
        );
    };
    match matrix_result_state(app) {
        crate::app::ViewDataState::Ready(Ok(report)) => {
            results::recorded_matrix_lines(config, &report, width, rows)
        }
        crate::app::ViewDataState::Ready(Err(error)) => {
            results::failure_lines(config, &error, width, rows)
        }
        _ => wrap_text(
            "Loading recorded case results in the background. No model request.",
            width.max(1),
        )
        .into_iter()
        .take(rows)
        .collect(),
    }
}

pub(crate) fn context_matrix_lines(
    config: &BatchScanConfig,
    width: usize,
    rows: usize,
) -> Vec<String> {
    let matrix = &config.study.matrix;
    let mut lines = matrix_heading(config);
    let count = rows.saturating_sub(lines.len()).max(1);
    let start = matrix.cursor.saturating_sub(count.saturating_sub(1));
    for (index, case) in matrix.cases.iter().enumerate().skip(start).take(count) {
        lines.push(case_line(
            case,
            index == matrix.cursor,
            matrix.baseline_case_id.as_deref(),
            width,
        ));
    }
    append_matrix_guidance(&mut lines, config, width, rows);
    lines
}

fn matrix_heading(config: &BatchScanConfig) -> Vec<String> {
    let matrix = &config.study.matrix;
    let mut lines = vec![format!(
        "{} cases · {} fixed jobs",
        matrix.cases.len(),
        matrix.planned_jobs()
    )];
    if matrix.baseline_case_id.is_none() {
        lines.push("b chooses an explicit baseline.".into());
    }
    lines
}

fn case_line(
    case: &ContextCaseInput,
    selected: bool,
    baseline: Option<&str>,
    width: usize,
) -> String {
    let role = if baseline == Some(case.id.as_str()) {
        "baseline"
    } else {
        "candidate"
    };
    let marker = if selected { "▸" } else { " " };
    let suffix = format!(" · {role} · {} passes", case.passes);
    let name_width =
        width.saturating_sub(unicode_width::UnicodeWidthStr::width(suffix.as_str()) + 2);
    format!("{marker} {}{suffix}", fit_path(&case.label, name_width))
}

fn append_matrix_guidance(
    lines: &mut Vec<String>,
    config: &BatchScanConfig,
    width: usize,
    rows: usize,
) {
    let message = if config.study.matrix.cases.is_empty() {
        "a opens contexts. Inspect one, then + adds it or b sets the baseline."
    } else {
        config.notice.as_deref().unwrap_or(
            "Recurrence stays within each case. All jobs need approval and share the allowance.",
        )
    };
    let remaining = rows.saturating_sub(lines.len());
    let wrapped = wrap_text(message, width.max(1));
    if wrapped.len() > remaining && remaining > 0 {
        lines.push("Esc back to read details and notices.".into());
        return;
    }
    lines.extend(wrapped.into_iter().take(remaining));
}

pub(crate) fn context_matrix_conditions(receipt: &ContextMatrixReceipt) -> Vec<String> {
    let Ok(baseline) = receipt.matrix.baseline() else {
        return vec!["Matrix baseline is unavailable. Reload the saved plan before work.".into()];
    };
    let source = &baseline.equivalence.components;
    let mut lines = vec![
        format!("Matrix: {}", receipt.campaign_id),
        format!(
            "{} contexts · {} fixed jobs · {} workers",
            receipt.matrix.cases.len(),
            receipt.job_count,
            receipt.workers
        ),
        format!("Baseline: {} · {} passes", baseline.label, baseline.passes),
        "Only context differs. Source, scope, model, runtime, options and prompts stay fixed."
            .into(),
        source.target_git.as_ref().map_or_else(
            || "Git SHA unavailable".into(),
            |git| format!("Git SHA: {} · dirty: {}", git.sha, git.dirty),
        ),
        format!("Source content: {}", source.workspace_identity),
        format!(
            "Model: {}",
            source.model.as_deref().unwrap_or("Runtime-free selection")
        ),
        format!("Scope: {}", source.scope_sha256),
        format!("Plan digest: {}", receipt.plan_sha256),
    ];
    append_case_conditions(&mut lines, receipt);
    lines.push(super::study_config::supporting_context_summary(
        &baseline.base_input,
        receipt.supporting_context.as_deref(),
    ));
    lines
}

fn append_case_conditions(lines: &mut Vec<String>, receipt: &ContextMatrixReceipt) {
    for case in &receipt.matrix.cases {
        lines.extend([
            format!("{} · {} passes", case.label, case.passes),
            format!(
                "Context: {}",
                super::study_config::context_reference_summary(&case.base_input)
            ),
            format!("Conditions: {}", case.equivalence.sha256),
        ]);
    }
}
