use super::*;
use crate::ui_view_models::{run_diff_model, RunDiffFindingRow};

const DIFF_ROW_LIMIT: usize = 10;

pub(crate) fn run_diff_lines(
    app: &ShellApp,
    area: Rect,
    left: &str,
    right: &str,
) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = run_diff_model(app, left, right);
    lines.push(blank());
    lines.push(divider("RUN DIFF", area.width));
    lines.push(Line::from(format!(
        "{} ({})  ->  {} ({})",
        model.left_run, model.left_revision, model.right_run, model.right_revision
    )));
    lines.push(Line::from(format!(
        "+{} added   -{} removed   ={} unchanged",
        model.added.len(),
        model.removed.len(),
        model.unchanged_count
    )));
    append_warnings(&mut lines, &model.warnings);
    append_section(&mut lines, "ADDED IN RIGHT", '+', &model.added);
    append_section(&mut lines, "REMOVED FROM RIGHT", '-', &model.removed);
    lines.push(blank());
    lines.push(command_list_line(
        &["runs", "replay <runId>", "trace <runId>", "back"],
        area.width as usize,
    ));
    lines
}

fn append_warnings(lines: &mut Vec<Line<'static>>, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    lines.push(blank());
    for warning in warnings.iter().take(3) {
        lines.push(Line::styled(format!("! {warning}"), theme::warn()));
    }
}

fn append_section(
    lines: &mut Vec<Line<'static>>,
    title: &str,
    marker: char,
    rows: &[RunDiffFindingRow],
) {
    lines.push(blank());
    lines.push(Line::styled(title.to_string(), theme::accent()));
    if rows.is_empty() {
        lines.push(Line::styled("  none".to_string(), theme::muted()));
        return;
    }
    for row in rows.iter().take(DIFF_ROW_LIMIT) {
        lines.push(run_diff_row(marker, row));
    }
    if rows.len() > DIFF_ROW_LIMIT {
        lines.push(Line::styled(
            format!("  +{} more", rows.len() - DIFF_ROW_LIMIT),
            theme::muted(),
        ));
    }
}

fn run_diff_row(marker: char, row: &RunDiffFindingRow) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{marker} "), theme::accent()),
        Span::styled(format!("{:<8}", row.severity), theme::muted()),
        Span::raw(format!(" {} ", row.title)),
        Span::styled(format!("{} ", row.location), theme::muted()),
        Span::styled(format!("[{}]", row.tool), theme::muted()),
    ])
}
