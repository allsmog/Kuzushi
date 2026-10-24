use super::*;
use crate::ui_view_models::{
    run_diff_model, RunDiffChangedRow, RunDiffDecisionSummary, RunDiffFindingRow,
    RunDiffUncertainMatchRow,
};

pub(crate) fn run_diff_lines(
    app: &ShellApp,
    area: Rect,
    left: &str,
    right: &str,
) -> Vec<Line<'static>> {
    let mut lines = vec![divider("RUN DIFF", area.width), comparison_tabs(app)];
    let model = run_diff_model(app, left, right);
    if app.router.run_diff().sources_open() {
        append_run_pair(&mut lines, &model);
        append_sources(&mut lines, &model);
    } else {
        append_findings(&mut lines, &model);
    }
    wrap_document_lines(lines, area.width)
}

pub(crate) fn run_diff_document_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let route = app.router.run_diff();
    let model = run_diff_model(app, route.left(), route.right());
    let mut lines = vec![divider("RUN DIFF", area.width)];
    append_findings(&mut lines, &model);
    lines.push(blank());
    append_sources(&mut lines, &model);
    wrap_document_lines(lines, area.width)
}

fn comparison_tabs(app: &ShellApp) -> Line<'static> {
    let (findings, sources) = if app.router.run_diff().sources_open() {
        (
            Span::styled(" Findings ", theme::muted()),
            Span::styled("[Sources & context]", theme::selection()),
        )
    } else {
        (
            Span::styled("[Findings]", theme::selection()),
            Span::styled(" Sources & context ", theme::muted()),
        )
    };
    Line::from(vec![
        findings,
        Span::raw(" "),
        sources,
        Span::styled(" · Tab", theme::muted()),
    ])
}

fn append_run_pair(lines: &mut Vec<Line<'static>>, model: &crate::ui_view_models::RunDiffModel) {
    lines.push(Line::from(format!(
        "{} ({})  ->  {} ({})",
        model.left_run, model.left_revision, model.right_run, model.right_revision
    )));
    lines.push(Line::styled(
        format!("status: {} -> {}", model.left_status, model.right_status),
        theme::muted(),
    ));
}

fn append_sources(lines: &mut Vec<Line<'static>>, model: &crate::ui_view_models::RunDiffModel) {
    lines.push(Line::styled(
        "FULL SOURCE & CONTEXT REFERENCES",
        theme::accent(),
    ));
    lines.push(Line::from(format!("Base source: {}", model.left_source)));
    lines.push(Line::from(format!("Later source: {}", model.right_source)));
    lines.push(Line::styled(
        format!("Threat model: {}", model.context_status),
        theme::accent(),
    ));
    lines.push(Line::from(format!(
        "Base threat model: {}",
        model.left_context
    )));
    lines.push(Line::from(format!(
        "Later threat model: {}",
        model.right_context
    )));
    lines.push(Line::styled(model.source_note, theme::muted()));
}

fn append_findings(lines: &mut Vec<Line<'static>>, model: &crate::ui_view_models::RunDiffModel) {
    if !model.findings_ready {
        append_pending_comparison(lines, model);
        return;
    }
    append_finding_counts(lines, model);
    lines.push(Line::styled(
        "Absence does not establish a fix.",
        theme::muted(),
    ));
    lines.push(Line::styled(
        format!("Threat model: {}", model.context_status),
        theme::accent(),
    ));
    append_warnings(lines, &model.warnings);
    append_run_pair(lines, model);
    append_decision_summary(lines, model.decision_summary.as_ref());
    append_section(lines, "NEW IN RIGHT", '+', &model.new_findings);
    append_changed_section(lines, &model.changed_findings);
    append_uncertain_section(lines, &model.uncertain_matches);
    append_absence_sections(lines, &model.not_seen);
    append_section(lines, "SEEN AGAIN", '=', &model.unchanged_findings);
}

fn append_pending_comparison(
    lines: &mut Vec<Line<'static>>,
    model: &crate::ui_view_models::RunDiffModel,
) {
    lines.push(Line::styled(
        "Recorded findings are loading or unavailable. Comparison counts are pending.",
        theme::muted(),
    ));
    append_warnings(lines, &model.warnings);
    append_run_pair(lines, model);
}

fn append_finding_counts(
    lines: &mut Vec<Line<'static>>,
    model: &crate::ui_view_models::RunDiffModel,
) {
    let not_assessed = model
        .not_seen
        .iter()
        .filter(|row| row.reassessment_block.is_some())
        .count();
    lines.push(Line::from(format!(
        "+{} new · ~{} changed · {} seen again",
        model.new_findings.len(),
        model.changed_findings.len(),
        model.unchanged_findings.len() + model.changed_findings.len(),
    )));
    lines.push(Line::from(format!(
        "{} not observed · {} not reassessed",
        model.not_seen.len() - not_assessed,
        not_assessed,
    )));
    if !model.uncertain_matches.is_empty() {
        lines.push(Line::styled(
            format!("?{} uncertain matches", model.uncertain_matches.len()),
            theme::warn(),
        ));
    }
}

fn append_absence_sections(lines: &mut Vec<Line<'static>>, rows: &[RunDiffFindingRow]) {
    let (not_assessed, not_observed): (Vec<_>, Vec<_>) = rows
        .iter()
        .cloned()
        .partition(|row| row.reassessment_block.is_some());
    append_section(lines, "NOT OBSERVED IN COVERED WORK", '-', &not_observed);
    append_section(lines, "NOT REASSESSED IN RIGHT", '?', &not_assessed);
}

fn append_warnings(lines: &mut Vec<Line<'static>>, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    lines.push(blank());
    for warning in warnings {
        lines.push(Line::styled(format!("! {warning}"), theme::warn()));
    }
}

fn append_decision_summary(
    lines: &mut Vec<Line<'static>>,
    summary: Option<&RunDiffDecisionSummary>,
) {
    let Some(summary) = summary.filter(|summary| summary.identities > 0) else {
        return;
    };
    lines.push(Line::styled(
        format!(
            "Recorded decisions: {} of {} finding identities.",
            summary.with_stored_decision, summary.identities,
        ),
        theme::muted(),
    ));
    lines.push(Line::styled(
        "Check decision sources in Review before reusing a verdict.",
        theme::muted(),
    ));
    if summary.conflicts > 0 {
        lines.push(Line::styled(
            format!("Differing snapshot verdicts: {}", summary.conflicts),
            theme::warn(),
        ));
    }
}

fn append_section(
    lines: &mut Vec<Line<'static>>,
    title: &str,
    marker: char,
    rows: &[RunDiffFindingRow],
) {
    if rows.is_empty() {
        return;
    }
    lines.push(blank());
    lines.push(Line::styled(title.to_string(), theme::accent()));
    for row in rows {
        lines.push(run_diff_row(marker, row));
        append_reassessment_reason(lines, row);
    }
}

fn append_reassessment_reason(lines: &mut Vec<Line<'static>>, row: &RunDiffFindingRow) {
    if let Some(reason) = &row.reassessment_block {
        lines.push(Line::styled(format!("    {reason}"), theme::muted()));
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
    if rows.is_empty() {
        return;
    }
    lines.push(blank());
    lines.push(Line::styled(
        "CHANGED IN RIGHT".to_string(),
        theme::accent(),
    ));
    for row in rows {
        lines.push(run_diff_changed_row(row));
    }
}

fn append_uncertain_section(lines: &mut Vec<Line<'static>>, rows: &[RunDiffUncertainMatchRow]) {
    if rows.is_empty() {
        return;
    }
    lines.push(blank());
    lines.push(Line::styled(
        "UNCERTAIN MATCHES".to_string(),
        theme::accent(),
    ));
    for row in rows {
        lines.push(run_diff_uncertain_row(row));
        lines.push(Line::styled(format!("    {}", row.reason), theme::muted()));
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
