use crate::app::{ShellApp, ViewDataState};
use crate::renderer::shared::text::wrap_text;

pub(crate) fn matrix_plain_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    let config = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .filter(|config| config.study.matrix.open)?;
    let mut lines = vec!["CONTEXT CASES".into()];
    append_allowance(&mut lines, app, width);
    if !config.study.matrix.results {
        lines.extend(super::context_matrix_lines(config, width, usize::MAX));
        return Some(lines);
    }
    match super::matrix_result_state(app) {
        ViewDataState::Ready(Ok(report)) => {
            lines.extend(wrap_text(
                "Recurrence stays within each case. Absence never establishes a fix.",
                width.max(1),
            ));
            for case in &report.cases {
                lines.extend(super::results::detail_lines(config, &report, case, width));
                lines.push(String::new());
            }
        }
        ViewDataState::Ready(Err(error)) => {
            lines.extend(super::results::unavailable_lines(&error, width))
        }
        _ => lines.extend(wrap_text(
            "Loading recorded case results. No model request.",
            width.max(1),
        )),
    }
    Some(lines)
}

fn append_allowance(lines: &mut Vec<String>, app: &ShellApp, width: usize) {
    lines.extend(super::matrix_allowance_lines(app, width));
    if let Some(allowance) = super::super::investigation_allowance_model(app) {
        lines.extend(allowance.rows);
    }
}
