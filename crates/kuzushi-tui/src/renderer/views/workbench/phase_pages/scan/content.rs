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
        PhaseSurfaceId::ScanScope,
        state,
    );
}

pub(super) fn scope_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    if model.study.is_some() {
        return super::study::scope_lines(model, width);
    }
    let mut lines = vec![
        Line::styled(fit(&model.scope, width), theme::primary()),
        Line::styled(fit(&model.plan, width), theme::muted()),
        Line::styled(fit("b plan study and allowance", width), theme::accent()),
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
        if model.study.is_some() {
            "STUDY JOBS"
        } else {
            "RECORDED ENGINE OUTCOMES"
        },
        engine_lines(model, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ScanEngines,
        state,
    );
}

pub(super) fn engine_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    if model.study.is_some() {
        return super::study::job_lines(model, width);
    }
    let mut live = live_scan_lines(model, width);
    if model.engine_outcomes.is_empty() {
        live.push(Line::styled(
            fit("no terminal scanner outcome recorded", width),
            theme::muted(),
        ));
        return live;
    }
    if !live.is_empty() {
        live.extend(engine_outcome_lines(&model.engine_outcomes, width));
        return live;
    }
    engine_outcome_lines(&model.engine_outcomes, width)
}

pub(super) fn engine_outcome_lines(
    outcomes: &[ScanEngineOutcomeModel],
    width: usize,
) -> Vec<Line<'static>> {
    outcomes
        .iter()
        .flat_map(|outcome| {
            let mut lines = vec![engine_line(outcome, width)];
            if let Some(detail) = outcome.detail.as_deref() {
                lines.extend(
                    crate::renderer::shared::text::wrap_text(detail, width.saturating_sub(2))
                        .into_iter()
                        .map(|line| Line::styled(format!("  {line}"), theme::muted())),
                );
            }
            lines
        })
        .collect()
}

/// One status line while a scan run is in flight. The dashboard names the
/// run and its coarse stage; the trace itself belongs to Run Focus.
fn live_scan_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(live) = model.live.as_ref() else {
        return Vec::new();
    };
    let run = live.run_id.as_deref().unwrap_or("run pending");
    vec![Line::styled(
        fit(
            &format!(
                "⟳ scan in flight · {run} · stage {} · {} finding(s) so far — live output: `activity`",
                live.stage, live.findings
            ),
            width,
        ),
        theme::warn(),
    )]
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
        if model.study.is_some() {
            "APPROVED STUDY"
        } else {
            "FINDING / ARTIFACT DELTA"
        },
        finding_delta_lines(model, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ScanDelta,
        state,
    );
}

pub(super) fn finding_delta_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    if model.study.is_some() {
        return super::study::summary_lines(model, width);
    }
    let Some(attempt) = model.attempt.as_ref() else {
        return vec![Line::styled(
            "delta unavailable before a Scan run",
            theme::muted(),
        )];
    };
    let mut lines = finding_count_lines(attempt, width);
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

fn finding_count_lines(
    attempt: &crate::ui_view_models::ScanAttemptModel,
    width: usize,
) -> Vec<Line<'static>> {
    let label = finding_delta_label(attempt);
    let groups = if unicode_width::UnicodeWidthStr::width(label.as_str()) > width {
        label.split(" · ").collect::<Vec<_>>()
    } else {
        vec![label.as_str()]
    };
    groups
        .into_iter()
        .flat_map(|group| crate::renderer::shared::text::wrap_text(group, width))
        .map(|line| Line::styled(line, theme::primary()))
        .collect()
}

fn finding_delta_label(attempt: &crate::ui_view_models::ScanAttemptModel) -> String {
    match (attempt.findings_added, attempt.findings_updated) {
        (Some(added), Some(updated)) => format!("findings +{added} added · {updated} updated"),
        _ => match (attempt.findings, attempt.findings_observed) {
            (Some(findings), Some(observations)) => {
                format!("findings {findings} distinct · {observations} observations")
            }
            _ => format!("findings {}", optional_count(attempt.findings)),
        },
    }
}

fn short_ref(run_ref: &str) -> String {
    run_ref.chars().take(10).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_engine_detail_remains_readable_at_narrow_widths() {
        let model = ScanPhaseModel {
            study: None,
            scope: "service".into(),
            plan: "manual".into(),
            attempt: None,
            empty_hint: None,
            live: None,
            engine_outcomes: vec![ScanEngineOutcomeModel {
                tool_key: Some("secret-scan:scan".into()),
                engine: "secret-scan".into(),
                outcome: "partial".into(),
                run_ref: None,
                detail: Some(
                    "Incomplete coverage: 1 gap; service: unreadable.js: permission denied".into(),
                ),
            }],
        };
        for width in [20, 38, 58, 78, 118, 158] {
            let lines = engine_lines(&model, width);
            assert!(lines.iter().all(|line| line.width() <= width), "{lines:?}");
            let text = lines[1..]
                .iter()
                .map(|line| line.to_string().trim().to_string())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(text.contains("Incomplete coverage: 1 gap"), "{text}");
            assert!(text.contains("unreadable.js: permission denied"), "{text}");
        }
    }

    #[test]
    fn live_scan_line_names_the_run_and_defers_output_to_run_focus() {
        let model = ScanPhaseModel {
            study: None,
            scope: "target".to_string(),
            plan: "manual".to_string(),
            attempt: None,
            engine_outcomes: Vec::new(),
            empty_hint: None,
            live: Some(crate::ui_view_models::LiveScanModel {
                run_id: Some("run-live".to_string()),
                stage: "scanning".to_string(),
                findings: 2,
            }),
        };

        let text = engine_lines(&model, 120)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("scan in flight"), "{text}");
        assert!(text.contains("run-live"), "{text}");
        assert!(text.contains("`activity`"), "{text}");
    }

    #[test]
    fn delta_pane_renders_severity_chips_between_delta_and_artifacts() {
        let model = ScanPhaseModel {
            study: None,
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
                findings_observed: None,
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
            live: None,
        };

        let text = finding_delta_lines(&model, 60)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("1 critical · 2 medium"), "{text}");
        let empty_model = ScanPhaseModel {
            study: None,
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

    /// The delta panel used to print the runs' raw observation count as
    /// "findings" beside a severity breakdown of the distinct findings the
    /// ledger actually holds, so the same frame read `findings 27` over
    /// `20 high · 5 medium`. Issue #172, 2026-09-28 audit.
    #[test]
    fn delta_pane_never_prints_a_total_its_own_breakdown_contradicts() {
        let model = folded_scan_model();

        let text = finding_delta_lines(&model, 80)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            text.contains("findings 25 distinct · 27 observations"),
            "the total must be the one the breakdown adds up to, with the \
             observations behind it named: {text}"
        );
        assert!(text.contains("20 high · 5 medium"), "{text}");
    }

    #[test]
    fn folded_counts_wrap_without_losing_the_observation_unit() {
        let model = folded_scan_model();
        for width in [16, 24, 34, 80] {
            let rows = finding_count_lines(model.attempt.as_ref().unwrap(), width)
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>();
            let text = rows.join(" ");
            assert!(rows.iter().any(|row| row.contains("27 observations")));
            assert!(
                text.replace(" · ", " ") == "findings 25 distinct 27 observations",
                "{width}: {text}"
            );
            assert!(!text.contains('…'), "{width}: {text}");
            assert!(rows
                .iter()
                .all(|row| unicode_width::UnicodeWidthStr::width(row.as_str()) <= width));
        }
    }

    fn folded_scan_model() -> ScanPhaseModel {
        ScanPhaseModel {
            study: None,
            scope: "target".to_string(),
            plan: "manual".to_string(),
            attempt: Some(crate::ui_view_models::ScanAttemptModel {
                attempt_id: None,
                run_id: "run-1".to_string(),
                run_refs: vec!["run-1".to_string()],
                outcome: "completed".to_string(),
                disposition: "selected".to_string(),
                freshness: "current revision".to_string(),
                findings: Some(25),
                findings_observed: Some(27),
                findings_added: None,
                findings_updated: None,
                severity_counts: vec![("high".to_string(), 20), ("medium".to_string(), 5)],
                artifact_count: 0,
                artifact_paths: Vec::new(),
                duration_secs: None,
                cost_usd: None,
                cost_complete: None,
                error: None,
            }),
            engine_outcomes: Vec::new(),
            empty_hint: None,
            live: None,
        }
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
        if model.study.is_some() {
            "RECORDED RESULT"
        } else {
            "SCAN RECEIPT"
        },
        if model.study.is_some() {
            super::study::result_lines(model, area.width.saturating_sub(2) as usize)
        } else {
            receipt_lines(model, area.width.saturating_sub(2) as usize)
        },
        PhaseSurfaceId::ScanReceipt,
        state,
    );
}

pub(super) fn receipt_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(attempt) = model.attempt.as_ref() else {
        if model.study.is_some() {
            return super::study::receipt_lines(model, width);
        }
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
    if model.study.is_some() {
        return super::study::summary_lines(model, width);
    }
    let mut lines = super::study::summary_lines(model, width);
    lines.extend(formatted_compact_summary_lines(model, width));
    if model
        .engine_outcomes
        .iter()
        .any(|engine| engine.outcome == "partial")
    {
        lines.extend(engine_lines(model, width));
    }
    lines
}
