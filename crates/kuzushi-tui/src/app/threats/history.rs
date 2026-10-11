//! Exact, target-bound context history. Browsing never changes the active pointer.
use crate::app::{state_transitions::InputUpdate, ShellApp, ShellView, ThreatView};
use crossterm::event::{KeyCode, KeyEvent};
use kuzushi_core::ThreatModelRef;
use serde_json::{json, Value};

mod keys;
mod receipt;
mod state;
pub(crate) use state::{ContextHistoryRequest, ContextHistoryState};
#[cfg(test)]
mod tests;

impl ShellApp {
    pub(crate) fn context_history(&self) -> Option<&ContextHistoryState> {
        self.bound_context_history().filter(|state| {
            state.open
                && self.shell_view() == ShellView::Threat
                && self.router.threat().view() == ThreatView::Models
        })
    }

    fn bound_context_history(&self) -> Option<&ContextHistoryState> {
        self.router
            .threat()
            .history()
            .filter(|state| self.target() == Some(state.target.as_path()))
    }

    pub(crate) fn open_context_history(&mut self) {
        if self.context_history().is_some() {
            return;
        }
        let Some(target) = self.target_owned() else {
            return;
        };
        let origin = self.shell_view();
        let same_target = self
            .router
            .threat()
            .history()
            .is_some_and(|state| state.target == target);
        if !same_target {
            let state = match history_state(target, origin) {
                Ok(state) => state,
                Err(error) => {
                    self.log("context", error);
                    return;
                }
            };
            self.router.threat_mut().set_history(state);
        } else if let Some(state) = self.router.threat_mut().history_mut() {
            state.open = true;
            state.origin = origin;
        }
        self.capture_history_origin();
    }

    pub(crate) fn prepare_context_history_view(&mut self, view: ThreatView) {
        if view == ThreatView::Models {
            self.open_context_history();
        }
    }

    fn capture_history_origin(&mut self) {
        let view = self.router.threat().view();
        let scroll = self.router.default_scroll().offset();
        let state = self.router.threat_mut().history_mut().unwrap();
        state.origin_threat_view = view;
        state.origin_scroll = scroll;
    }

    pub(crate) fn leave_context_history(&mut self) {
        let Some(state) = self.router.threat_mut().history_mut() else {
            return;
        };
        state.open = false;
        let origin = state.origin;
        let view = state.origin_threat_view;
        let scroll = state.origin_scroll;
        self.router.threat_mut().open(view);
        self.router.default_scroll_mut().set(scroll);
        self.set_shell_view(origin);
    }

    pub(crate) fn leave_context_history_for_paste(&mut self) {
        if self.context_history().is_some() {
            self.leave_context_history();
        }
    }

    pub(crate) fn handle_context_history_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        self.context_history()?;
        if super::super::state_transitions::is_quit_chord(key) {
            return None;
        }
        if !key.modifiers.is_empty() {
            return Some(InputUpdate::handled());
        }
        Some(self.reduce_context_history_key(key.code))
    }

    fn dispatch_history_request(&mut self, request: ContextHistoryRequest) -> InputUpdate {
        if self.has_running_work() {
            self.history_notice("Wait for active work before reading context.");
            return InputUpdate::handled();
        }
        let (tool, input) = request_input(&request);
        self.router
            .threat_mut()
            .history_mut()
            .unwrap()
            .begin(request);
        InputUpdate::handled_with_effects(
            self.reduce_run_tool(Some(tool.into()), Some(input.to_string())),
        )
    }

    fn history_notice(&mut self, message: &str) {
        if let Some(state) = self.router.threat_mut().history_mut() {
            state.error = Some(message.into());
        }
    }

    fn dispatch_history_write(&mut self, tool: &str, reference: ThreatModelRef) -> InputUpdate {
        if self.has_running_work() {
            self.history_notice("Wait for active work before changing context.");
            return InputUpdate::handled();
        }
        let input = history_write_input(tool, &reference);
        let state = self.router.threat_mut().history_mut().unwrap();
        let label = state
            .selected_label
            .clone()
            .unwrap_or_else(|| reference.revision_id.to_string());
        state.pending_write = Some((tool.into(), reference, label));
        state.notice = Some("Applying the explicit local context change…".into());
        state.error = None;
        InputUpdate::handled_with_effects(
            self.reduce_run_tool(Some(tool.into()), Some(input.to_string())),
        )
    }
}

fn request_input(request: &ContextHistoryRequest) -> (&'static str, Value) {
    let input = match request {
        ContextHistoryRequest::Read(reference) => json!({"threatModelRef":reference}),
        ContextHistoryRequest::Compare {
            baseline,
            candidate,
        } => json!({"from":baseline.revision_id,"to":candidate.revision_id}),
    };
    (request.tool(), input)
}

fn history_write_input(tool: &str, reference: &ThreatModelRef) -> Value {
    if tool == "threat-model:restore" {
        return json!({"revisionId":reference.revision_id});
    }
    json!({"modelId":reference.model_id,"revisionId":reference.revision_id})
}

fn history_state(
    target: std::path::PathBuf,
    origin: ShellView,
) -> Result<ContextHistoryState, String> {
    let receipt_target = std::fs::canonicalize(&target).map_err(|error| {
        format!(
            "Cannot open context history for {}: {error}",
            target.display()
        )
    })?;
    let mut state = ContextHistoryState::new(target, origin);
    state.receipt_target = receipt_target;
    Ok(state)
}
