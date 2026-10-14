use super::*;
use anyhow::{Context, Result};
use kuzushi_core::workspace::ScanScopeRef;

impl ShellApp {
    pub(super) fn plan_selected_scope(&mut self) -> InputUpdate {
        if self
            .scope_review()
            .is_some_and(|state| !state.study_scope_ids.is_empty())
        {
            return self.plan_marked_scopes();
        }
        let selection = selected_study_scope(self.scope_review());
        let result = selection
            .and_then(|(reference, summary)| self.open_selected_scope_study(reference, summary));
        if let Err(error) = result {
            self.scope_notice(format!("Study unavailable: {error:#}"));
        }
        InputUpdate::handled()
    }

    pub(super) fn toggle_study_scope_selection(&mut self) -> InputUpdate {
        let result = markable_scope(self.scope_review());
        match result {
            Ok(id) => {
                let state = self.router.scope_review_mut().as_mut().unwrap();
                if !state.study_scope_ids.remove(&id) {
                    state.study_scope_ids.insert(id);
                }
                state.notice = Some(format!("{} boundaries marked for planning. p reviews their finite workload; no jobs start.", state.study_scope_ids.len()));
            }
            Err(error) => self.scope_notice(format!("Selection unavailable: {error:#}")),
        }
        InputUpdate::handled()
    }

    fn plan_marked_scopes(&mut self) -> InputUpdate {
        let result = marked_scope_draft(self.scope_review())
            .and_then(|draft| self.open_selected_scopes_study(draft));
        if let Err(error) = result {
            self.scope_notice(format!("Scope study unavailable: {error:#}"));
        }
        InputUpdate::handled()
    }
}

fn markable_scope(state: Option<&ScopeReviewState>) -> Result<String> {
    let state = state.context("Open scope review first")?;
    let review = state
        .review
        .as_ref()
        .context("Build and accept boundaries first")?;
    anyhow::ensure!(
        review.record.acceptance.is_some(),
        "Accept exact boundaries before selecting scan work"
    );
    let id = state.selected_id().context("Select a discovery boundary")?;
    let members = review
        .coverage
        .discovery_members
        .get(id)
        .context("This boundary supplies context only")?;
    anyhow::ensure!(members.total > 0, "This boundary has no discovery files");
    Ok(id.into())
}

fn marked_scope_draft(
    state: Option<&ScopeReviewState>,
) -> Result<kuzushi_core::capabilities::campaign::ScopeStudyDraft> {
    let state = state.context("Open scope review first")?;
    let review = state.review.as_ref().context("Scope draft unavailable")?;
    anyhow::ensure!(
        review.record.acceptance.is_some(),
        "Accept boundaries before planning work"
    );
    let draft = kuzushi_core::capabilities::campaign::ScopeStudyDraft {
        proposal_ref: review.reference.clone(),
        cases: state
            .study_scope_ids
            .iter()
            .map(
                |id| kuzushi_core::capabilities::campaign::ScopeStudyCaseInput {
                    scope_id: id.clone(),
                    passes: 3,
                    threat_model_ref: None,
                },
            )
            .collect(),
    };
    draft.validate()?;
    Ok(draft)
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
