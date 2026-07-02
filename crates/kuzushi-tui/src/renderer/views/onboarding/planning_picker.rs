use super::*;
use crate::app::{row_disposition, PlanningArtifactState, PlanningTaskRow, WorkflowPhase};
use crate::ui_view_models::{
    enter_plan, format_relative_age, latest_cached_modified, workspace_history, RowOutcome,
    WorkspaceHistory,
};
use std::time::SystemTime;

pub(crate) fn planning_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    push_phase_header(app, area.width, &mut lines);
    if app.planning_tasks.is_empty() {
        lines.push(muted("(no tasks in this phase)"));
        lines.push(blank());
        // Even with nothing to pick, the picker is still a modal — say how
        // to leave it instead of presenting a dead end.
        lines.push(keybind_hint_line(&[
            ("Enter", "continue"),
            ("Esc/q", "skip phase"),
        ]));
        return lines;
    }
    lines.push(blank());
    lines.push(prior_state_banner(app, area.width));
    lines.push(blank());
    lines.push(legend_line(area.width));
    lines.push(blank());
    if let Some(header) = column_header(area.width) {
        lines.push(header);
    }
    for (idx, row) in app.planning_tasks.iter().enumerate() {
        lines.push(planning_row_line(app, idx, row, area.width));
    }
    lines.push(blank());
    lines.push(enter_summary_line(app));
    lines.push(keybind_hint_line(&[
        ("↑/↓/j/k", "move"),
        ("Space", "check/uncheck"),
        ("g", "rebuild cached"),
        ("a", "all"),
        ("n", "none"),
        ("Enter", "run checked"),
        ("Esc/q", "skip phase"),
    ]));
    lines
}

/// Announce the current judo phase (組→崩→作→掛) and its intent.
fn push_phase_header(app: &ShellApp, width: u16, lines: &mut Vec<Line<'static>>) {
    match app.workflow_phase {
        Some(phase) => {
            lines.push(divider(phase.label(), width));
            lines.push(blank());
            lines.push(muted(&format!(
                "phase {} of {} — {}",
                phase.position(),
                WorkflowPhase::ORDER.len(),
                phase.intent()
            )));
        }
        None => {
            lines.push(divider("PLAN THE WORKSPACE", width));
            lines.push(blank());
            lines.push(muted(
                "Select tasks. Dependencies auto-toggle. Steps run in order.",
            ));
        }
    }
}

/// Tell a returning operator, up front, whether Kuzushi found prior work for
/// this target — the single biggest missing signal in the old picker.
fn prior_state_banner(app: &ShellApp, _width: u16) -> Line<'static> {
    let last_activity = latest_cached_modified(&app.planning_tasks)
        .and_then(|then| format_relative_age(SystemTime::now(), then));
    match workspace_history(&app.planning_tasks, app.findings.len(), last_activity) {
        WorkspaceHistory::Fresh => Line::from(vec![
            Span::styled("▌ ", theme::subtle()),
            Span::styled("Fresh target".to_string(), theme::label()),
            Span::styled(
                " — no prior Kuzushi state here; everything below is new work.".to_string(),
                theme::muted(),
            ),
        ]),
        WorkspaceHistory::Prior(state) => Line::from(vec![
            Span::styled("▌ ", theme::success()),
            Span::styled(
                "Resuming — Kuzushi found prior work: ".to_string(),
                theme::success().add_modifier(Modifier::BOLD),
            ),
            Span::styled(state.headline(), theme::primary()),
        ]),
    }
}

/// A colour-keyed legend so the outcome words in the rows are never load-
/// bearing on their own. Full glosses when they fit; just the coloured words
/// on a narrow terminal.
fn legend_line(width: u16) -> Line<'static> {
    let full = legend_spans(true);
    if spans_width(&full) <= width as usize {
        return Line::from(full);
    }
    Line::from(legend_spans(false))
}

fn legend_spans(with_gloss: bool) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled(" outcome: ", theme::muted())];
    for (idx, outcome) in RowOutcome::LEGEND.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::styled("   ", theme::subtle()));
        }
        spans.push(Span::styled(
            outcome.word().to_string(),
            outcome_style(*outcome),
        ));
        if with_gloss {
            spans.push(Span::styled(
                format!(" {}", outcome.gloss()),
                theme::muted(),
            ));
        }
    }
    spans
}

fn spans_width(spans: &[Span<'static>]) -> usize {
    spans.iter().map(|span| span.content.chars().count()).sum()
}

/// A subtle column header so operators can read the grid. Dropped entirely on
/// very narrow terminals, where rows collapse to outcome + task.
fn column_header(width: u16) -> Option<Line<'static>> {
    let w = width as usize;
    let body = if w >= WIDE {
        format!(
            "    {:<7} {:<30} {:<22} {}",
            "OUTCOME", "TASK", "TOOL", "WHY"
        )
    } else if w >= MEDIUM {
        format!("    {:<7} {:<28} {}", "OUTCOME", "TASK", "WHY")
    } else {
        return None;
    };
    Some(styled(&fit(&body, w), theme::subtle()))
}

const WIDE: usize = 88;
const MEDIUM: usize = 60;

fn planning_row_line(
    app: &ShellApp,
    idx: usize,
    row: &PlanningTaskRow,
    width: u16,
) -> Line<'static> {
    let disposition = row_disposition(row, &app.planning_selected, &app.planning_rebuild);
    let outcome = RowOutcome::from_disposition(disposition);
    let marker = if idx == app.planning_cursor { ">" } else { " " };
    let note = planning_row_note(app, row, outcome);
    let w = width as usize;
    let body = if w >= WIDE {
        format!(
            "  {marker} {outcome:<7} {label:<30} {tool:<22} {note}",
            outcome = outcome.word(),
            label = row.label,
            tool = row.tool_name,
        )
    } else if w >= MEDIUM {
        format!(
            "  {marker} {outcome:<7} {label:<28} {note}",
            outcome = outcome.word(),
            label = row.label,
        )
    } else {
        format!(
            "  {marker} {outcome:<7} {label}",
            outcome = outcome.word(),
            label = row.label,
        )
    };
    Line::styled(fit(&body, w), planning_row_style(app, idx, outcome))
}

/// The row's "why" column: the artifact reality plus the one cost/blocker the
/// operator needs to act on, phrased so it agrees with the outcome word.
fn planning_row_note(app: &ShellApp, row: &PlanningTaskRow, outcome: RowOutcome) -> String {
    if outcome == RowOutcome::Blocked {
        return format!("requires {} on PATH", row.required_cli.unwrap_or("a tool"));
    }
    if row.model_backed && app.config.model.is_none() {
        return "needs model — run /model first".to_string();
    }
    match outcome {
        RowOutcome::Reuse => "cached — press g to rebuild".to_string(),
        RowOutcome::Run if app.planning_rebuild.contains(&row.id) => {
            with_cost(row, "rebuild (overwrites cache)")
        }
        RowOutcome::Run | RowOutcome::Skip => with_cost(row, artifact_reason(row)),
        RowOutcome::Blocked => unreachable!("blocked handled above"),
    }
}

fn artifact_reason(row: &PlanningTaskRow) -> &'static str {
    match row.artifact_state {
        PlanningArtifactState::Cached => "cached",
        PlanningArtifactState::Missing => "not built yet",
        PlanningArtifactState::Invalid => "cached but invalid",
        PlanningArtifactState::Action => "runs a scan/action",
    }
}

fn with_cost(row: &PlanningTaskRow, base: &str) -> String {
    if row.model_backed {
        format!("{base} · model-backed")
    } else {
        base.to_string()
    }
}

/// State exactly what Enter will do, styled green only when something actually
/// runs — a reused/skipped-only plan stays muted so the colour can't overclaim.
fn enter_summary_line(app: &ShellApp) -> Line<'static> {
    let plan = enter_plan(
        &app.planning_tasks,
        &app.planning_selected,
        &app.planning_rebuild,
    );
    let style = if plan.run > 0 {
        theme::success().add_modifier(Modifier::BOLD)
    } else {
        theme::muted()
    };
    styled(&format!(" {}", plan.summary_line()), style)
}

fn outcome_style(outcome: RowOutcome) -> Style {
    match outcome {
        RowOutcome::Run => theme::success(),
        RowOutcome::Reuse => theme::accent(),
        RowOutcome::Skip => theme::subtle(),
        RowOutcome::Blocked => theme::danger(),
    }
}

/// Green is reserved for rows Enter will actually run; reused rows stay muted,
/// skipped rows dim, blocked rows disabled — the colour tracks the outcome word.
fn planning_row_style(app: &ShellApp, idx: usize, outcome: RowOutcome) -> Style {
    let base = match outcome {
        RowOutcome::Run => theme::success(),
        RowOutcome::Reuse => theme::muted(),
        RowOutcome::Skip => theme::primary(),
        RowOutcome::Blocked => theme::disabled(),
    };
    if idx == app.planning_cursor {
        return planning_cursor_style(base, outcome);
    }
    base
}

fn planning_cursor_style(base: Style, outcome: RowOutcome) -> Style {
    if outcome == RowOutcome::Run {
        base.add_modifier(Modifier::BOLD)
    } else {
        theme::accent().add_modifier(Modifier::BOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn legend_drops_glosses_when_it_cannot_fit() {
        let wide = legend_line(200);
        assert!(line_text(&wide).contains("runs now"), "wide keeps glosses");
        let narrow = legend_line(30);
        let text = line_text(&narrow);
        assert!(text.contains("RUN"), "narrow keeps the words");
        assert!(!text.contains("runs now"), "narrow drops the glosses");
    }

    #[test]
    fn legend_covers_every_outcome_word() {
        let text = line_text(&legend_line(200));
        for outcome in RowOutcome::LEGEND {
            assert!(
                text.contains(outcome.word()),
                "legend lists {}",
                outcome.word()
            );
        }
    }

    #[test]
    fn column_header_collapses_on_narrow_terminals() {
        assert!(line_text(&column_header(120).unwrap()).contains("TOOL"));
        assert!(!line_text(&column_header(70).unwrap()).contains("TOOL"));
        assert!(column_header(40).is_none());
    }
}
