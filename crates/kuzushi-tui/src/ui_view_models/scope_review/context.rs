//! Project only associations belonging to this target and exact scope revision.
use super::*;
use crate::app::{BatchScanConfig, ScopeBranch, ShellApp};

pub(super) fn scope_context_detail(app: &ShellApp, state: &ScopeReviewState) -> Vec<String> {
    if state.form.is_some() || state.menu.is_some() || state.accepting {
        return Vec::new();
    }
    let Some(ScopeBranch::Scope(id)) = state.selected_row().map(|row| row.branch().clone()) else {
        return Vec::new();
    };
    let Some(config) = matching_study(app, state) else {
        return super::recorded_context::detail(app, state, &id)
            .unwrap_or_else(|| vec!["Scan context: no matching study.".into()]);
    };
    let Some(case) = config
        .study
        .scope_draft
        .as_ref()
        .and_then(|draft| draft.cases.iter().find(|case| case.scope_id == id))
    else {
        return vec!["Scan context: this boundary is not in the current study draft.".into()];
    };
    super::super::scope_context::association_detail(config, case)
}

fn matching_study<'a>(app: &'a ShellApp, state: &ScopeReviewState) -> Option<&'a BatchScanConfig> {
    let config = app.router.campaign().batch_scan_config.as_ref()?;
    let draft = config.study.scope_draft.as_ref()?;
    (config.target == state.target && draft.proposal_ref == state.review.as_ref()?.reference)
        .then_some(config)
}
