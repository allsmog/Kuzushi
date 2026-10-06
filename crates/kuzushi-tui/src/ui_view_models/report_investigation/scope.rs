//! Present recorded scope evidence; no current-source or filesystem reads.
use kuzushi_core::workspace::{ProposedScanScope, ScanScopeRef, ScanScopeReview};
use serde_json::Value;

pub(super) fn lines(scope: &Value, details: bool) -> Vec<String> {
    if scope.get("scanScopeRef").is_none() {
        return Vec::new();
    }
    let Some((reference, proposal)) = recorded_proposal(scope) else {
        return vec![
            "Boundary: recorded scope details unavailable; inspect the export receipt.".into(),
        ];
    };
    let selected = proposal
        .record
        .draft
        .scopes
        .iter()
        .chain(proposal.record.draft.shared_scope.iter())
        .find(|selected| selected.id == reference.scope_id);
    let Some(selected) = selected else {
        return vec!["Boundary: selected scope is missing from its recorded proposal.".into()];
    };
    selected_lines(&reference, &proposal, selected, details)
}

fn recorded_proposal(scope: &Value) -> Option<(ScanScopeRef, ScanScopeReview)> {
    let reference: ScanScopeRef = serde_json::from_value(scope["scanScopeRef"].clone()).ok()?;
    let proposal: ScanScopeReview =
        serde_json::from_value(scope["acceptedScopeProposal"].clone()).ok()?;
    if proposal.reference != reference.proposal || proposal.record.acceptance.is_none() {
        return None;
    }
    Some((reference, proposal))
}

fn selected_lines(
    reference: &ScanScopeRef,
    proposal: &ScanScopeReview,
    selected: &ProposedScanScope,
    details: bool,
) -> Vec<String> {
    let count = proposal
        .coverage
        .discovery_members
        .get(&reference.scope_id)
        .map_or(0, |members| members.total);
    let mut lines = vec![
        format!(
            "Boundary: {} · {count} planned discovery file(s)",
            selected.name
        ),
        format!("Included paths: {}", selected.paths.join(", ")),
        format!(
            "Proposal coverage: {} excluded · {} uncovered · {} overlap(s) · {}",
            proposal.coverage.excluded_files.total,
            proposal.coverage.uncovered_files.total,
            proposal.coverage.overlaps.total,
            if proposal.coverage.inventory_limited {
                "inventory limited"
            } else {
                "enumeration complete"
            }
        ),
        "Accepted membership describes the planned boundary, not completed scanner coverage."
            .into(),
    ];
    lines.extend(shared_lines(proposal, selected));
    if details {
        lines.extend(detail_lines(reference, proposal, selected));
    }
    lines
}

fn shared_lines(proposal: &ScanScopeReview, selected: &ProposedScanScope) -> Vec<String> {
    let mut lines = Vec::new();
    if !selected.shared_dependencies.is_empty() {
        lines.push(format!(
            "Shared dependencies: {}",
            selected.shared_dependencies.join(", ")
        ));
    }
    if let Some(shared) = proposal
        .record
        .draft
        .shared_scope
        .as_ref()
        .filter(|_| !proposal.record.draft.shared_discovery)
    {
        lines.push(format!(
            "Shared context only: {} · {}",
            shared.name,
            shared.paths.join(", ")
        ));
    }
    lines
}

fn detail_lines(
    reference: &ScanScopeRef,
    proposal: &ScanScopeReview,
    selected: &ProposedScanScope,
) -> Vec<String> {
    let mut lines = vec![
        format!("Boundary rationale: {}", selected.rationale),
        reference_line(reference),
        format!(
            "Scope source content: tree:{}",
            proposal.record.source.tree_hash
        ),
        "File lists in the receipt are bounded previews; totals refer to the accepted inventory."
            .into(),
    ];
    lines.extend(
        proposal
            .record
            .draft
            .exclusions
            .iter()
            .map(|excluded| format!("Excluded {}: {}", excluded.path, excluded.reason)),
    );
    lines.extend(proposal.coverage.limitations.iter().cloned());
    lines
}

fn reference_line(reference: &ScanScopeRef) -> String {
    let proposal = &reference.proposal;
    format!(
        "Scope reference: {} revision {} · record {} · scope {}",
        proposal.proposal_id, proposal.revision, proposal.record_hash, reference.scope_id
    )
}

#[cfg(test)]
mod tests;
