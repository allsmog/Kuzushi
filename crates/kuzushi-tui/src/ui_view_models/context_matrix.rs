//! Finite case editor projection; no stores or runtime calls.
use crate::app::BatchScanConfig;
use crate::renderer::shared::text::wrap_text;
use kuzushi_core::capabilities::campaign::ContextCaseInput;
use kuzushi_core::capabilities::campaign::ContextMatrixReceipt;

mod results;

pub(crate) fn matrix_result_state(
    app: &crate::app::ShellApp,
) -> crate::app::ViewDataState<Result<kuzushi_core::findings::ContextMatrixOccurrenceReport, String>>
{
    app.cached_context_matrix_report()
}

pub(crate) fn matrix_result_lines(
    app: &crate::app::ShellApp,
    width: usize,
    rows: usize,
) -> Vec<String> {
    match matrix_result_state(app) {
        crate::app::ViewDataState::Ready(Ok(report)) => {
            results::recorded_matrix_lines(app, &report, width, rows)
        }
        crate::app::ViewDataState::Ready(Err(error)) => vec![
            "Recorded results unavailable. r retries; no work starts.".into(),
            error,
        ],
        _ => vec!["Loading recorded case results in the background. No model request.".into()],
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

fn case_line(case: &ContextCaseInput, selected: bool, baseline: Option<&str>) -> String {
    let role = if baseline == Some(case.id.as_str()) {
        "baseline"
    } else {
        "candidate"
    };
    let marker = if selected { "▸" } else { " " };
    format!("{marker} {role} · {} passes · {}", case.passes, case.label)
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
