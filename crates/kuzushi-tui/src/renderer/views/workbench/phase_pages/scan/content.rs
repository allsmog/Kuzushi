use super::format::{
    compact_summary_lines as formatted_compact_summary_lines, optional_count, outcome_style,
    outcome_symbol, receipt_metrics_lines, receipt_reference_lines, receipt_status_lines,
    severity_chip_label, severity_chip_style,
};
use super::*;
use crate::ui_view_models::{ScanEngineOutcomeModel, ScanPhaseModel};

pub(super) fn render_scope(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ScanPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "SCOPE / PLAN",
        scope_lines(model, area.width.saturating_sub(2) as usize),
        WorkbenchPane::Source,
        state,
    );
}

pub(super) fn scope_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(fit(&model.scope, width), theme::primary()),
        Line::styled(fit(&model.plan, width), theme::muted()),
    ];
    if let Some(hint) = model.empty_hint.as_deref() {
        lines.push(Line::styled(fit(hint, width), theme::warn()));
    }
    lines
}

pub(super) fn render_engines(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ScanPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "RECORDED ENGINE OUTCOMES",
        engine_lines(model, area.width.saturating_sub(2) as usize),
        WorkbenchPane::Center,
        state,
    );
}

pub(super) fn engine_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    if model.engine_outcomes.is_empty() {
        return vec![Line::styled(
            fit("no terminal scanner outcome recorded", width),
            theme::muted(),
        )];
    }
    model
        .engine_outcomes
        .iter()
        .flat_map(|outcome| {
            let mut lines = vec![engine_line(outcome, width)];
            if let Some(detail) = outcome.detail.as_deref() {
                lines.push(Line::styled(
                    fit(&format!("  {detail}"), width),
                    theme::muted(),
                ));
            }
            lines
        })
        .collect()
}

fn engine_line(outcome: &ScanEngineOutcomeModel, width: usize) -> Line<'static> {
    let run = outcome
        .run_ref
        .as_deref()
        .map(|run_ref| format!(" · r:{}", short_ref(run_ref)))
        .unwrap_or_default();
    let suffix = format!(" · {}{run}", outcome.outcome);
    let content_width = width.saturating_sub(2);
    let engine = compact_engine_label(
        &outcome.engine,
        content_width.saturating_sub(suffix.chars().count()),
    );
    Line::from(vec![
        Span::styled(
            format!("{} ", outcome_symbol(&outcome.outcome)),
            outcome_style(&outcome.outcome),
        ),
        Span::styled(
            fit(&format!("{engine}{suffix}"), content_width),
            theme::primary(),
        ),
    ])
}

fn compact_engine_label(engine: &str, max_width: usize) -> String {
    if engine.chars().count() <= max_width {
        return engine.to_string();
    }
    if max_width <= 1 {
        return "…".chars().take(max_width).collect();
    }
    format!(
        "{}…",
        engine.chars().take(max_width - 1).collect::<String>()
    )
}

pub(super) fn render_findings(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ScanPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "FINDING / ARTIFACT DELTA",
        finding_delta_lines(model, area.width.saturating_sub(2) as usize),
        WorkbenchPane::Findings,
        state,
    );
}

pub(super) fn finding_delta_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(attempt) = model.attempt.as_ref() else {
        return vec![Line::styled(
            "delta unavailable before a Scan run",
            theme::muted(),
        )];
    };
    let mut lines = vec![Line::styled(
        fit(&finding_delta_label(attempt), width),
        theme::primary(),
    )];
    if !attempt.severity_counts.is_empty() {
        lines.push(Line::styled(
            fit(&severity_chip_label(&attempt.severity_counts), width),
            severity_chip_style(&attempt.severity_counts),
        ));
    }
    lines.push(Line::styled(
        fit(
            &format!("artifacts {} recorded", attempt.artifact_count),
            width,
        ),
        theme::muted(),
    ));
    lines
        .into_iter()
        .chain(
            attempt
                .artifact_paths
                .iter()
                .take(2)
                .map(|path| Line::styled(fit(&format!("+ {path}"), width), theme::muted())),
        )
        .collect()
}

fn finding_delta_label(attempt: &crate::ui_view_models::ScanAttemptModel) -> String {
    match (attempt.findings_added, attempt.findings_updated) {
        (Some(added), Some(updated)) => format!("findings +{added} added · {updated} updated"),
        _ => format!("findings {}", optional_count(attempt.findings)),
    }
}

fn short_ref(run_ref: &str) -> String {
    run_ref.chars().take(10).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_pane_renders_severity_chips_between_delta_and_artifacts() {
        let model = ScanPhaseModel {
            scope: "target".to_string(),
            plan: "manual".to_string(),
            attempt: Some(crate::ui_view_models::ScanAttemptModel {
                attempt_id: None,
                run_id: "run-1".to_string(),
                run_refs: vec!["run-1".to_string()],
                outcome: "completed".to_string(),
                disposition: "selected".to_string(),
                freshness: "current revision".to_string(),
                findings: Some(3),
                findings_added: Some(3),
                findings_updated: Some(0),
                severity_counts: vec![("critical".to_string(), 1), ("medium".to_string(), 2)],
                artifact_count: 0,
                artifact_paths: Vec::new(),
                duration_secs: None,
                cost_usd: None,
                cost_complete: None,
                error: None,
            }),
            engine_outcomes: Vec::new(),
            empty_hint: None,
        };

        let text = finding_delta_lines(&model, 60)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("1 critical · 2 medium"), "{text}");
        let empty_model = ScanPhaseModel {
            attempt: model.attempt.clone().map(|mut attempt| {
                attempt.severity_counts.clear();
                attempt
            }),
            ..model
        };
        let quiet = finding_delta_lines(&empty_model, 60)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !quiet.contains("critical"),
            "no chips may be invented when severity was never recorded: {quiet}"
        );
    }

    #[test]
    fn engine_row_retains_compact_run_reference_at_eighty_column_pane_width() {
        let outcome = ScanEngineOutcomeModel {
            engine: "taint-iris-next".to_string(),
            tool_key: Some("taint-iris-next:hunt".to_string()),
            outcome: "complete".to_string(),
            run_ref: Some("1234567890abcdef".to_string()),
            detail: None,
        };

        let line = engine_line(&outcome, 35);
        let text = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(text.contains("· r:1234567890"), "{text:?}");
    }
}

pub(super) fn render_receipt(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ScanPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "SCAN RECEIPT",
        receipt_lines(model, area.width.saturating_sub(2) as usize),
        WorkbenchPane::Details,
        state,
    );
}

pub(super) fn receipt_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(attempt) = model.attempt.as_ref() else {
        return empty_state_panel(
            "no Scan receipt",
            &["live progress belongs in Run Focus"],
            &[("Shift+Tab", "select Scan, then describe what to scan")],
        );
    };
    let mut lines = receipt_status_lines(attempt, width);
    lines.extend(receipt_reference_lines(attempt, width));
    lines.extend(receipt_metrics_lines(model, attempt, width));
    if let Some(error) = attempt.error.as_deref() {
        lines.push(Line::styled(fit(error, width), theme::danger()));
    }
    lines
}

pub(super) fn compact_summary_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    formatted_compact_summary_lines(model, width)
}
