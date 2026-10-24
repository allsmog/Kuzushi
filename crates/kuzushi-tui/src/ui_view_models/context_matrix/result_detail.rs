use crate::app::BatchScanConfig;
use crate::ui_view_models::occurrence_evidence::{
    append_observation_receipt, append_observation_summary,
};
use kuzushi_core::findings::{ContextCaseOccurrenceReport, ContextMatrixOccurrenceReport};
use serde_json::Value;

pub(super) fn recorded_case_detail(
    config: &BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    case: &ContextCaseOccurrenceReport,
) -> Vec<String> {
    let mut lines = Vec::new();
    append_case_observations(&mut lines, case);
    lines.push(format!(
        "{} failed · {} pending",
        case.occurrence.failed, case.occurrence.pending
    ));
    append_case(&mut lines, report, case);
    append_source(&mut lines, config, report, case);
    for row in &case.occurrence.rows {
        append_observation_receipt(&mut lines, row);
    }
    lines.extend(
        config
            .notice
            .iter()
            .map(|notice| format!("Notice: {notice}")),
    );
    lines
}

fn append_case_observations(lines: &mut Vec<String>, case: &ContextCaseOccurrenceReport) {
    for row in &case.occurrence.rows {
        append_observation_summary(lines, row, case.occurrence.completed);
    }
    if case.occurrence.rows.is_empty() {
        lines.push("No recorded observations. Decisions stay unchanged.".into());
    }
}

fn append_case(
    lines: &mut Vec<String>,
    report: &ContextMatrixOccurrenceReport,
    case: &ContextCaseOccurrenceReport,
) {
    let role = if case.id == report.baseline_case_id {
        "baseline"
    } else {
        "candidate"
    };
    lines.extend([
        format!("Case: {} · {role}", case.label),
        format!(
            "Case id: {} · baseline id: {}",
            case.id, report.baseline_case_id
        ),
    ]);
    append_context(lines, &case.threat_model_ref);
    lines.push(format!("Conditions: {}", case.occurrence.equivalence_key));
}

fn append_context(lines: &mut Vec<String>, context: &Value) {
    if context.is_null() {
        lines.push("Context: explicitly omitted.".into());
        return;
    }
    let Ok(context) = serde_json::from_value::<kuzushi_core::ThreatModelRef>(context.clone())
    else {
        lines.push("Context reference unavailable. Inspect the authenticated saved plan.".into());
        return;
    };
    lines.extend([
        format!("Context model: {}", context.model_id),
        format!("Context revision: {}", context.revision_id),
        format!("Context digest: {}", context.sha256),
    ]);
}

fn append_source(
    lines: &mut Vec<String>,
    config: &BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    case: &ContextCaseOccurrenceReport,
) {
    let frozen = frozen_case_for_report(config, report, case);
    let Some(frozen) = frozen else {
        lines.push("Source conditions unavailable. Read or refresh this exact saved plan.".into());
        return;
    };
    let source = &frozen.equivalence.components;
    lines.push(source.target_git.as_ref().map_or_else(
        || "Recorded Git SHA: unavailable".into(),
        |git| format!("Recorded Git SHA: {} · dirty: {}", git.sha, git.dirty),
    ));
    lines.push(format!(
        "Recorded source content: {}",
        source.workspace_identity
    ));
    lines.push(format!(
        "Execution model: {}",
        source
            .model
            .as_deref()
            .unwrap_or("not recorded for this native selection")
    ));
}

fn frozen_case_for_report<'a>(
    config: &'a BatchScanConfig,
    report: &ContextMatrixOccurrenceReport,
    case: &ContextCaseOccurrenceReport,
) -> Option<&'a kuzushi_core::capabilities::campaign::FrozenContextCase> {
    config
        .study
        .matrix
        .receipt
        .as_ref()
        .filter(|receipt| receipt.plan_sha256 == report.plan_sha256)
        .and_then(|receipt| {
            receipt
                .matrix
                .cases
                .iter()
                .find(|frozen| frozen.id == case.id)
        })
        .filter(|frozen| frozen.equivalence.sha256 == case.occurrence.equivalence_key)
}
