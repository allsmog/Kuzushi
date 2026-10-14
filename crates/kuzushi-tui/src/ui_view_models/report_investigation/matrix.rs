//! A report projects each context separately; counts never imply coverage or a fix.
use super::*;
use kuzushi_core::workspace::ContextMatrixInvestigationReceipt;

pub(super) fn lines(
    receipt: &ContextMatrixInvestigationReceipt,
    details: bool,
    current: bool,
) -> Vec<String> {
    let mut lines = vec![
        format!(
            "Scope: context matrix {} · s switches to workspace history",
            receipt.campaign_id
        ),
        format!(
            "Context cases: {} · recurrence stays within each case",
            receipt.cases.len()
        ),
        format!(
            "Evidence: {} raw observations · {} distinct {}",
            receipt.evidence.observation_count,
            receipt.evidence.finding_count,
            crate::ui_view_models::finding_summary::finding_noun(receipt.evidence.finding_count)
        ),
        "Coverage: completed work does not establish complete repository coverage.".into(),
        "Missing observations do not establish a fix or change decisions.".into(),
    ];
    lines.extend(source_currency_lines(current));
    lines.extend(case_lines(receipt));
    lines.extend(source_lines(receipt));
    lines.extend(scope::lines(&receipt.scope, details));
    lines.extend(shared_allowance_lines(receipt.allowance.as_ref()));
    if details {
        lines.extend(provenance_lines(receipt));
    }
    lines
}

fn source_lines(receipt: &ContextMatrixInvestigationReceipt) -> Vec<String> {
    let Some(baseline) = receipt
        .cases
        .iter()
        .find(|case| case.id == receipt.baseline_case_id)
    else {
        return vec!["Recorded matrix baseline is unavailable.".into()];
    };
    vec![
        source_components_label(&baseline.equivalence.components),
        format!(
            "Model: {} · {} worker(s)",
            baseline
                .equivalence
                .components
                .model
                .as_deref()
                .unwrap_or("none recorded for discovery"),
            receipt.workers
        ),
    ]
}

fn case_lines(receipt: &ContextMatrixInvestigationReceipt) -> Vec<String> {
    let mut lines = Vec::new();
    for case in &receipt.occurrence.cases {
        let role = if case.id == receipt.baseline_case_id {
            "baseline"
        } else {
            "candidate"
        };
        let work = &case.occurrence;
        lines.push(format!(
            "{role}: {} · {} completed / {} planned · {} failed · {} pending",
            case.label, work.completed, work.planned, work.failed, work.pending
        ));
        for finding in &work.rows {
            lines.push(format!(
                "  observed {} / {} · {}",
                finding.seen, work.completed, finding.representative_title
            ));
        }
    }
    lines
}

fn provenance_lines(receipt: &ContextMatrixInvestigationReceipt) -> Vec<String> {
    let mut lines = vec![format!("Plan digest: {}", receipt.plan_sha256)];
    for case in &receipt.cases {
        let source = &case.equivalence.components;
        lines.push(format!(
            "{} · conditions: {}",
            case.label, case.equivalence.sha256
        ));
        lines.push(format!("Recorded content: {}", source.workspace_identity));
        lines.push(format!(
            "Context reference: {}",
            source
                .threat_model
                .as_ref()
                .unwrap_or(&serde_json::Value::Null)
        ));
        lines.push(format!("Configuration digest: {}", source.config_sha256));
        lines.push(format!(
            "Prompt overrides digest: {}",
            source.prompt_overrides_sha256
        ));
    }
    lines.extend(receipt.limitations.iter().cloned());
    lines
}
