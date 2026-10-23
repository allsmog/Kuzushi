//! Reconcile a completed local scope-history read with the inspected draft.
use super::*;

pub(super) fn install_latest_review(state: &mut ScopeReviewState, data: &Value) {
    let Some(value) = data.get("review") else {
        state.pending = None;
        state.notice = Some("Scope history reader returned no review field.".into());
        return;
    };
    match serde_json::from_value::<Option<ScanScopeReview>>(value.clone()) {
        Ok(Some(review)) => state.install(review),
        Ok(None) => {
            state.pending = None;
            state.notice = Some(empty_scope_history_notice(state.review.is_some()).into());
        }
        Err(error) => {
            state.pending = None;
            state.notice = Some(format!("Scope history unavailable: {error}"));
        }
    }
}

fn empty_scope_history_notice(previous_selection: bool) -> &'static str {
    if previous_selection {
        "Scope history is empty. The previously inspected revision is kept for reading."
    } else {
        "No saved scope inventory. Build inventory to review repository boundaries."
    }
}
