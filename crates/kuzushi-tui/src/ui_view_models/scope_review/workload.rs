//! Default workload is a preview, never a plan or permission to execute.
use crate::app::ScopeReviewState;
use anyhow::{Context, Result};
use kuzushi_core::capabilities::campaign::ScopeStudyDraft;
use kuzushi_core::workspace::ScanScopeReview;
use serde_json::json;

pub(super) fn all_jobs(review: &ScanScopeReview) -> Result<usize> {
    default_jobs(review, discovery_ids(review))
}

fn discovery_ids(review: &ScanScopeReview) -> Vec<&str> {
    review
        .coverage
        .discovery_members
        .iter()
        .filter(|(_, files)| files.total > 0)
        .map(|(id, _)| id.as_str())
        .collect()
}

fn default_jobs(review: &ScanScopeReview, ids: Vec<&str>) -> Result<usize> {
    if ids.is_empty() {
        return Ok(0);
    }
    let cases = ids
        .iter()
        .map(|id| json!({"scopeId":id}))
        .collect::<Vec<_>>();
    let input = json!({"scopeProposalRef":review.reference,"scopeCases":cases});
    // Resolve passes through the same domain defaults used by study preparation.
    let draft = ScopeStudyDraft::from_input(&input)?.context("Scope workload unavailable")?;
    Ok(draft.job_count())
}

fn next_jobs(state: &ScopeReviewState, review: &ScanScopeReview) -> Result<usize> {
    if !state.study_scope_ids.is_empty() {
        let ids: Vec<_> = state.study_scope_ids.iter().map(String::as_str).collect();
        let available = discovery_ids(review);
        anyhow::ensure!(
            ids.iter().all(|id| available.contains(id)),
            "Marked boundaries no longer supply discovery work"
        );
        return default_jobs(review, ids);
    }
    let selected = state.selected_id().context("Select a discovery boundary")?;
    anyhow::ensure!(
        discovery_ids(review).contains(&selected),
        "This row does not supply discovery work"
    );
    default_jobs(review, vec![selected])
}

pub(super) fn detail(state: &ScopeReviewState) -> Vec<String> {
    let mut lines = summary(state);
    lines.extend(guidance());
    lines
}

pub(super) fn summary(state: &ScopeReviewState) -> Vec<String> {
    let Some(review) = state.review.as_ref() else {
        return Vec::new();
    };
    vec![all_summary(review), next_summary(state, review)]
}

pub(super) fn guidance() -> Vec<String> {
    vec![
        "Preview only. One worker is the default; review passes, engines, context and allowance in the study before approving work.".into(),
        "Shared context adds no discovery jobs. Explicit shared discovery and overlapping boundaries can repeat work.".into(),
        "Provider requests and dollar cost are not estimated here; engine selection and the shared allowance still need review.".into()]
}

fn all_summary(review: &ScanScopeReview) -> String {
    let boundaries = discovery_ids(review).len();
    if boundaries == 0 {
        return "No discovery files included; default workload: 0 jobs.".into();
    }
    match all_jobs(review) {
        Ok(jobs) => format!(
            "All discovery boundaries: {boundaries} × {} default passes = {jobs} jobs.",
            jobs.checked_div(boundaries).unwrap_or(0)
        ),
        Err(error) => format!("Default workload unavailable: {error}"),
    }
}

fn next_summary(state: &ScopeReviewState, review: &ScanScopeReview) -> String {
    let selection = if state.study_scope_ids.is_empty() {
        "focused"
    } else {
        "marked"
    };
    match next_jobs(state, review) {
        Ok(jobs) => format!("Next study ({selection}): {jobs} jobs at default passes."),
        Err(error) => format!("Next study: {error}."),
    }
}
