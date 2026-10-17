use super::*;
use kuzushi_core::workspace::ScopeStudyInvestigationReceipt;

pub(super) fn lines(
    receipt: &ScopeStudyInvestigationReceipt,
    details: bool,
    current: bool,
) -> Vec<String> {
    let mut lines = vec![format!(
        "Scope study: {} · {} boundaries · {} unplanned",
        receipt.campaign_id,
        receipt.cases.len(),
        receipt.unplanned_scope_ids.len()
    )];
    lines.extend(shared_allowance_lines(receipt.allowance.as_ref()));
    lines.extend(source_currency_lines(current));
    lines.extend(source_model_lines(receipt));
    lines.push("Recurrence is measured inside each scope's completed passes. Shared context is not additional discovery work; a missing observation does not establish a fix.".into());
    for boundary in &receipt.occurrence.cases {
        lines.push(boundary_summary(boundary));
        lines.extend(boundary_context_line(receipt, &boundary.id));
    }
    lines.push("Coverage: only selected discovery scopes were planned. Inventory and engine omissions remain; no complete repository coverage claim.".into());
    lines.push(format!(
        "Unplanned boundaries: {}",
        receipt.unplanned_scope_ids.join(", ")
    ));
    if details {
        lines.extend(boundary_detail_lines(receipt));
        lines.push(format!("Plan digest: {}", receipt.plan_sha256));
        lines.extend(receipt.limitations.iter().cloned());
    }
    lines
}

fn source_model_lines(receipt: &ScopeStudyInvestigationReceipt) -> Vec<String> {
    let Some(first) = receipt.cases.first() else {
        return vec!["Source and model: unavailable".into()];
    };
    let source = &first.equivalence.components;
    vec![
        source_components_label(source),
        discovery_model_line(source.model.as_deref(), receipt.workers),
    ]
}

fn boundary_context_line(receipt: &ScopeStudyInvestigationReceipt, id: &str) -> Option<String> {
    let boundary = receipt.cases.iter().find(|boundary| boundary.id == id)?;
    Some(format!(
        "{} · {}",
        boundary.label,
        context_components_label(&boundary.equivalence.components)
    ))
}

fn boundary_detail_lines(receipt: &ScopeStudyInvestigationReceipt) -> Vec<String> {
    receipt
        .cases
        .iter()
        .flat_map(|boundary| {
            let mut lines = scope::lines(&receipt.scope[&boundary.id], true);
            lines.extend(models::recorded_model_line(
                boundary.equivalence.components.model.as_deref(),
            ));
            lines
        })
        .collect()
}

fn boundary_summary(boundary: &kuzushi_core::findings::ContextCaseOccurrenceReport) -> String {
    let work = &boundary.occurrence;
    let suffix = if work.rows.len() == 1 {
        "finding"
    } else {
        "findings"
    };
    format!(
        "Boundary {}: {} completed / {} planned · {} failed · {} pending · {} {}",
        boundary.label,
        work.completed,
        work.planned,
        work.failed,
        work.pending,
        work.rows.len(),
        suffix
    )
}
