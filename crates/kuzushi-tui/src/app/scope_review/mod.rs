//! Scope review owns its input while open and consumes shared dispatch receipts.
mod actions;
pub(crate) use actions::{merge_destinations, selected_filter, selected_scope, SCOPE_ACTIONS};
mod forms;
mod keys;
mod state;
mod study;
mod suggestion;
#[cfg(test)]
mod tests;
use crate::app::{state_transitions::InputUpdate, ShellApp};
use kuzushi_core::workspace::{ScanScopeProposalRef, ScanScopeReview, ScopeFilePage};
use serde_json::{json, Value};
pub(crate) use state::*;

impl ShellApp {
    pub(crate) fn scope_review(&self) -> Option<&ScopeReviewState> {
        self.router
            .scope_review()
            .as_ref()
            .filter(|state| self.target_owned().as_ref() == Some(&state.target))
    }

    pub(crate) fn scope_review_is_visible(&self) -> bool {
        self.scope_review().is_some_and(|state| state.open)
            && !matches!(
                self.shell_view(),
                crate::app::ShellView::QuitConfirm | crate::app::ShellView::ConfirmDialog
            )
    }

    pub(crate) fn open_scope_review(&mut self) -> Vec<crate::app::ShellEffect> {
        let Some(target) = self.target_owned() else {
            self.log("scopes", "Select a repository with target <path> first.");
            return Vec::new();
        };
        if self.scope_review().is_some() {
            self.router.scope_review_mut().as_mut().unwrap().open = true;
            return Vec::new();
        }
        *self.router.scope_review_mut() = Some(ScopeReviewState::new(target.clone()));
        self.dispatch_scope_request(json!({"operation":"latest"}))
            .effects
    }

    pub(super) fn scope_notice(&mut self, message: impl Into<String>) {
        if let Some(state) = self.router.scope_review_mut().as_mut() {
            state.notice = Some(message.into());
        }
    }

    pub(super) fn dispatch_scope_request(&mut self, input: Value) -> InputUpdate {
        if self.has_running_work() {
            self.scope_notice("Wait for active work. Your scope draft is preserved.");
            return InputUpdate::handled();
        }
        let Some(state) = self.router.scope_review_mut().as_mut() else {
            return InputUpdate::handled();
        };
        state.pending = Some(ScopeRequest {
            operation: input["operation"].as_str().unwrap_or("create").into(),
            reference: serde_json::from_value(input["proposalRef"].clone()).ok(),
            filter: serde_json::from_value(input["fileFilter"].clone()).ok(),
            offset: input["offset"].as_u64().unwrap_or(0) as usize,
        });
        state.notice = Some(
            "Reading source and scope evidence. No model calls. Ctrl+C cancels active work.".into(),
        );
        InputUpdate::handled_with_effects(
            self.reduce_run_tool(Some("pack:scopes".into()), Some(input.to_string())),
        )
    }

    pub(crate) fn cache_scope_review_result(&mut self, tool: &str, data: &Value) -> bool {
        if tool != "pack:scopes" {
            return false;
        }
        if self.scope_review().is_none() {
            return true;
        }
        let state = self.router.scope_review_mut().as_mut().unwrap();
        let Some(request) = state.pending.clone() else {
            return true;
        };
        if request.operation == "latest" {
            install_latest_review(state, data);
            return true;
        }
        if request.operation == "files" {
            install_file_page(state, &request, data);
            return true;
        }
        match serde_json::from_value::<ScanScopeReview>(data.clone()) {
            Ok(review) if matches_requested_review(&request, &review.reference) => {
                state.install(review)
            }
            Ok(_) => {}
            Err(error) => {
                state.pending = None;
                state.notice = Some(format!("Scope receipt unavailable: {error}"));
            }
        }
        true
    }

    pub(crate) fn scope_review_failed(&mut self, tool: &str, error: &str) {
        if tool != "pack:scopes" || self.scope_review().is_none() {
            return;
        }
        let state = self.router.scope_review_mut().as_mut().unwrap();
        if state.pending.take().is_some() {
            state.notice = Some(format!("Action stopped: {error}. Your draft is preserved."));
        }
    }
}

fn matches_requested_review(request: &ScopeRequest, reference: &ScanScopeProposalRef) -> bool {
    let Some(expected) = &request.reference else {
        return request.operation == "create" && reference.revision == 1;
    };
    if request.operation == "read" {
        return reference == expected;
    }
    reference.proposal_id == expected.proposal_id
        && reference.revision == expected.revision.saturating_add(1)
}

fn install_file_page(state: &mut ScopeReviewState, request: &ScopeRequest, data: &Value) {
    let Some(filter) = &request.filter else {
        return;
    };
    match serde_json::from_value::<ScopeFilePage>(data.clone()) {
        Ok(page) if page.offset == request.offset => {
            state.files = Some(ScopeFiles {
                filter: filter.clone(),
                page,
            });
            state.pending = None;
            state.scroll = 0;
            state.notice = None;
        }
        Ok(_) => {}
        Err(error) => {
            state.pending = None;
            state.notice = Some(format!("Scope file page unavailable: {error}"));
        }
    }
}

fn install_latest_review(state: &mut ScopeReviewState, data: &Value) {
    let Some(value) = data.get("review") else {
        state.pending = None;
        state.notice = Some("Scope history reader returned no review field.".into());
        return;
    };
    match serde_json::from_value::<Option<ScanScopeReview>>(value.clone()) {
        Ok(Some(review)) => state.install(review),
        Ok(None) => {
            state.pending = None;
            state.notice = None;
        }
        Err(error) => {
            state.pending = None;
            state.notice = Some(format!("Scope history unavailable: {error}"));
        }
    }
}
