use super::*;
use crate::ui_view_models::{
    run_diff_model, RunDiffChangedRow, RunDiffDecisionSummary, RunDiffFindingRow,
    RunDiffUncertainMatchRow,
};

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
    lines.push(Line::styled(
        format!("status: {} -> {}", model.left_status, model.right_status),
        theme::muted(),
    ));
    lines.push(Line::from(format!(
        "+{} new   ~{} changed   ?{} uncertain   -{} not seen   ={} unchanged",
        model.new_findings.len(),
        model.changed_findings.len(),
        model.uncertain_matches.len(),
        model.not_seen.len(),
        model.unchanged_count
    )));
    append_decision_summary(&mut lines, model.decision_summary.as_ref());
    append_warnings(&mut lines, &model.warnings);
    append_section(&mut lines, "NEW IN RIGHT", '+', &model.new_findings);
    append_changed_section(&mut lines, &model.changed_findings);
    append_uncertain_section(&mut lines, &model.uncertain_matches);
    append_section(&mut lines, "NOT SEEN IN RIGHT", '-', &model.not_seen);
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

fn append_decision_summary(
    lines: &mut Vec<Line<'static>>,
    summary: Option<&RunDiffDecisionSummary>,
) {
    let Some(summary) = summary else {
        return;
    };
    lines.push(Line::styled(
        format!(
            "decisions: identities={} stored={} carry_forward={} conflicts={}",
            summary.identities,
            summary.with_stored_decision,
            summary.carry_forward,
            summary.conflicts
        ),
        theme::muted(),
    ));
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
        Span::styled(format!("{:<8}", row.state.severity), theme::muted()),
        Span::raw(format!(" {} ", row.title)),
        Span::styled(format!("{} ", row.location), theme::muted()),
        Span::styled(format!("[{}]", row.tool), theme::muted()),
    ])
}

fn append_changed_section(lines: &mut Vec<Line<'static>>, rows: &[RunDiffChangedRow]) {
    lines.push(blank());
    lines.push(Line::styled(
        "CHANGED IN RIGHT".to_string(),
        theme::accent(),
    ));
    if rows.is_empty() {
        lines.push(Line::styled("  none".to_string(), theme::muted()));
        return;
    }
    for row in rows.iter().take(DIFF_ROW_LIMIT) {
        lines.push(run_diff_changed_row(row));
    }
    if rows.len() > DIFF_ROW_LIMIT {
        lines.push(Line::styled(
            format!("  +{} more", rows.len() - DIFF_ROW_LIMIT),
            theme::muted(),
        ));
    }
}

fn append_uncertain_section(lines: &mut Vec<Line<'static>>, rows: &[RunDiffUncertainMatchRow]) {
    lines.push(blank());
    lines.push(Line::styled(
        "UNCERTAIN MATCHES".to_string(),
        theme::accent(),
    ));
    if rows.is_empty() {
        lines.push(Line::styled("  none".to_string(), theme::muted()));
        return;
    }
    for row in rows.iter().take(DIFF_ROW_LIMIT) {
        lines.push(run_diff_uncertain_row(row));
        lines.push(Line::styled(format!("    {}", row.reason), theme::muted()));
    }
    if rows.len() > DIFF_ROW_LIMIT {
        lines.push(Line::styled(
            format!("  +{} more", rows.len() - DIFF_ROW_LIMIT),
            theme::muted(),
        ));
    }
}

fn run_diff_uncertain_row(row: &RunDiffUncertainMatchRow) -> Line<'static> {
    Line::from(vec![
        Span::styled("? ", theme::accent()),
        Span::styled(
            state_change_label_for_states(&row.before, &row.after),
            theme::muted(),
        ),
        Span::raw(format!(" {} ", row.title)),
        Span::styled(
            format!("{} -> {} ", row.left_location, row.right_location),
            theme::muted(),
        ),
        Span::styled(format!("[{}]", row.tool), theme::muted()),
    ])
}

fn run_diff_changed_row(row: &RunDiffChangedRow) -> Line<'static> {
    Line::from(vec![
        Span::styled("~ ", theme::accent()),
        Span::styled(state_change_label(row), theme::muted()),
        Span::raw(format!(" {} ", row.title)),
        Span::styled(format!("{} ", row.location), theme::muted()),
        Span::styled(format!("[{}]", row.tool), theme::muted()),
    ])
}

fn state_change_label(row: &RunDiffChangedRow) -> String {
    state_change_label_for_states(&row.before, &row.after)
}

fn state_change_label_for_states(
    before: &crate::ui_view_models::RunDiffFindingState,
    after: &crate::ui_view_models::RunDiffFindingState,
) -> String {
    format!(
        "sev:{}->{} conf:{}->{} decision:{}->{}",
        before.severity,
        after.severity,
        before.confidence,
        after.confidence,
        before.verdict,
        after.verdict
    )
}
