use super::*;
use anyhow::{Context, Result};
use kuzushi_core::workspace::ScanScopeRef;

impl ShellApp {
    pub(super) fn plan_selected_scope(&mut self) -> InputUpdate {
        let selection = selected_study_scope(self.scope_review());
        let result = selection
            .and_then(|(reference, summary)| self.open_selected_scope_study(reference, summary));
        if let Err(error) = result {
            self.scope_notice(format!("Study unavailable: {error:#}"));
        }
        InputUpdate::handled()
    }
}

fn selected_study_scope(state: Option<&ScopeReviewState>) -> Result<(ScanScopeRef, String)> {
    let state = state.context("Open scope review first.")?;
    let review = state
        .review
        .as_ref()
        .context("Build a scope draft first.")?;
    anyhow::ensure!(
        review.record.acceptance.is_some(),
        "Accept the exact scope revision before planning discovery."
    );
    let scope = selected_scope(state).context("Select a discovery boundary first.")?;
    let members = review
        .coverage
        .discovery_members
        .get(&scope.id)
        .context("This boundary supplies context only; it is not a discovery scope.")?;
    anyhow::ensure!(members.total > 0, "This boundary has no discovery files.");
    let reference = ScanScopeRef {
        proposal: review.reference.clone(),
        scope_id: scope.id.clone(),
    };
    let summary = format!("Selected scope: {} · {} files. Only this boundary is planned; other scopes remain unplanned. Your engine choices are preserved. Source is rechecked when preparing the draft. No jobs or model requests start here.", scope.name, members.total);
    Ok((reference, summary))
}
