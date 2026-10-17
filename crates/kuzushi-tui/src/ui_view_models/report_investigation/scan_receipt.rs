use super::*;
use crate::ui_view_models::{PhaseCockpitBody, ScanPhaseModel};
use kuzushi_core::WorkflowPhase;

pub(super) fn lines(app: &ShellApp) -> Vec<String> {
    let cockpit = crate::ui_view_models::phase_cockpit_model_for_phase(app, WorkflowPhase::Scan);
    let PhaseCockpitBody::Scan(scan) = cockpit.body else {
        return Vec::new();
    };
    receipt_lines(&scan)
}

fn receipt_lines(scan: &ScanPhaseModel) -> Vec<String> {
    let Some(attempt) = &scan.attempt else {
        return Vec::new();
    };
    let mut lines = vec![
        format!(
            "Displayed Scan: {} · {} · {}{}",
            attempt.outcome,
            attempt.disposition,
            attempt.run_id,
            additional_runs_label(attempt.run_refs.len())
        ),
        format!(
            "Recorded Scan source: {} · scope {}",
            attempt.freshness, scan.scope
        ),
        "Scan receipt does not establish complete repository coverage.".into(),
    ];
    lines.extend(engine_disclosure_lines(scan));
    lines
}

/// A multi-pass attempt is named by its first run; the rest stay visible.
fn additional_runs_label(run_count: usize) -> String {
    match run_count.saturating_sub(1) {
        0 => String::new(),
        more => format!(" +{more} more run(s)"),
    }
}

fn engine_disclosure_lines(scan: &ScanPhaseModel) -> Vec<String> {
    let engines = scan
        .engine_outcomes
        .iter()
        .filter(|engine| {
            engine
                .detail
                .as_deref()
                .is_some_and(|detail| !detail.is_empty())
                || !matches!(engine.outcome.as_str(), "complete" | "completed")
        })
        .collect::<Vec<_>>();
    let mut lines = engines
        .iter()
        .take(3)
        .map(|engine| {
            format!(
                "{}: {} · {}",
                engine.engine,
                engine.outcome,
                engine
                    .detail
                    .as_deref()
                    .unwrap_or("coverage detail not recorded")
            )
        })
        .collect::<Vec<_>>();
    if engines.len() > 3 {
        lines.push(format!(
            "{} more engine outcomes in Scan; receipt preview is bounded.",
            engines.len() - 3
        ));
    }
    lines
}

#[cfg(test)]
mod tests;
