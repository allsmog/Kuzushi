use super::*;
use std::{path::Path, sync::Arc};

impl ShellApp {
    pub(crate) fn cache_context_history_result(&mut self, tool: &str, data: &Value) -> bool {
        if self.cache_context_history_write(tool, data) {
            return true;
        }
        self.cache_context_history_read(tool, data)
    }

    fn cache_context_history_read(&mut self, tool: &str, data: &Value) -> bool {
        let Some(state) = self.bound_context_history() else {
            return false;
        };
        let Some(request) = &state.request else {
            return false;
        };
        if request.tool() != tool || !receipt_matches(state, data) {
            return false;
        }
        let error = validate_history_payload(request, data).err();
        let state = self.router.threat_mut().history_mut().unwrap();
        state.error = error;
        state.data = Some(Arc::new(data.clone()));
        true
    }

    pub(crate) fn context_history_failed(&mut self, tool: &str, error: &str) {
        let owns_failure = self
            .bound_context_history()
            .is_some_and(|state| owns_history_tool(state, tool));
        if owns_failure {
            self.history_notice(error);
            let state = self.router.threat_mut().history_mut().unwrap();
            state.pending_write = None;
            state.notice = None;
        }
    }

    fn cache_context_history_write(&mut self, tool: &str, data: &Value) -> bool {
        let Some(state) = self.bound_context_history() else {
            return false;
        };
        if !history_write_matches(state, tool, data) {
            return false;
        }
        let label = &state.pending_write.as_ref().unwrap().2;
        let action = history_write_notice(tool, label);
        let state = self.router.threat_mut().history_mut().unwrap();
        state.pending_write = None;
        state.notice = Some(action);
        state.error = None;
        true
    }
}

fn owns_history_tool(state: &ContextHistoryState, tool: &str) -> bool {
    state
        .request
        .as_ref()
        .is_some_and(|request| request.tool() == tool)
        || state
            .pending_write
            .as_ref()
            .is_some_and(|(pending, _, _)| pending == tool)
}

fn history_write_matches(state: &ContextHistoryState, tool: &str, data: &Value) -> bool {
    let Some((pending, reference, _)) = &state.pending_write else {
        return false;
    };
    if pending != tool
        || data["target"].as_str().map(Path::new) != Some(state.receipt_target.as_path())
    {
        return false;
    }
    if tool == "threat-model:restore" {
        return data["sourceRevisionId"].as_str() == Some(reference.revision_id.as_str())
            && data["modelRef"]["modelId"].as_str() == Some(reference.model_id.as_str());
    }
    serde_json::from_value::<ThreatModelRef>(data["modelRef"].clone())
        .ok()
        .as_ref()
        == Some(reference)
}

fn history_write_notice(tool: &str, label: &str) -> String {
    if tool == "threat-model:restore" {
        return format!("Restored {label} as a new active revision.");
    }
    format!("Activated {label}.")
}

fn receipt_matches(state: &ContextHistoryState, data: &Value) -> bool {
    if data["target"].as_str().map(Path::new) != Some(state.receipt_target.as_path()) {
        return false;
    }
    match state.request.as_ref().unwrap() {
        ContextHistoryRequest::Read(reference) => {
            serde_json::from_value::<ThreatModelRef>(data["modelRef"].clone())
                .ok()
                .as_ref()
                == Some(reference)
        }
        ContextHistoryRequest::Compare {
            baseline,
            candidate,
        } => {
            diff_side_matches(&data["from"], baseline) && diff_side_matches(&data["to"], candidate)
        }
    }
}

fn diff_side_matches(data: &Value, reference: &ThreatModelRef) -> bool {
    data["modelId"].as_str() == Some(reference.model_id.as_str())
        && data["revisionId"].as_str() == Some(reference.revision_id.as_str())
        && data["sha256"].as_str() == Some(reference.sha256.as_str())
}

fn validate_history_payload(request: &ContextHistoryRequest, data: &Value) -> Result<(), String> {
    match request {
        ContextHistoryRequest::Read(_) if !data["document"].is_object() => Err(
            "The exact reader returned no context document. Enter retries the local read.".into(),
        ),
        ContextHistoryRequest::Compare { .. } if !data["contextText"].is_array() => {
            Err("The comparison returned no text differences. Enter retries the local read.".into())
        }
        _ => Ok(()),
    }
}
