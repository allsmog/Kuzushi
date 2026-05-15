use crate::ShellApp;
use kuzushi_core::run_artifacts::{load_run_failure_context, FailureToLlmContext};
use std::path::Path;

pub fn failure_handoff_context(app: &ShellApp) -> Option<FailureToLlmContext> {
    live_failure_context(app).or_else(|| persisted_failure_context(app))
}

fn live_failure_context(app: &ShellApp) -> Option<FailureToLlmContext> {
    app.agent_chat
        .as_ref()
        .and_then(|agent| agent.failure_context.clone())
}

fn persisted_failure_context(app: &ShellApp) -> Option<FailureToLlmContext> {
    let root = app.target.as_deref()?;
    let run_id = super::read_latest_run_id(root)?;
    load_latest_failure_context(root, &run_id)
}

fn load_latest_failure_context(root: &Path, run_id: &str) -> Option<FailureToLlmContext> {
    load_run_failure_context(root, run_id).ok().flatten()
}
