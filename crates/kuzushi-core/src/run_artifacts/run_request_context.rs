//! Authenticated recorded request and read-only allowance context for a named run.
use super::*;
use crate::allowance::{InvestigationWork, RunAllowanceContext};
use crate::workspace::{ScanScopeRef, WorkspaceTarget};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;
mod allowance;
mod investigation_allowance;
pub use investigation_allowance::load_investigation_allowance_for_runs;

#[derive(Clone, Debug, PartialEq)]
pub struct RunRequestContext {
    pub run_id: String,
    pub read_at_unix: u64,
    pub scope: Result<RecordedRequestScope, String>,
    pub allowance: Result<Option<RunAllowanceContext>, String>,
    pub allowance_origin: RecordedAllowanceOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordedAllowanceOrigin {
    Explicit,
    Inherited {
        accounting_run_id: String,
        work: InvestigationWork,
    },
    NotRecorded,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordedRequestScope {
    Accepted {
        name: String,
        reference: ScanScopeRef,
    },
    ExplicitPaths {
        count: usize,
    },
    NotRecorded,
}

/// Authenticate historical discovery membership without loading allowance state.
pub fn load_run_request_scope(target: &Path, run_id: &str) -> Result<RecordedRequestScope> {
    let input = authenticated_input(target, run_id)?;
    scope(&WorkspaceTarget::new(target)?, &input)
}

pub fn load_run_request_context(target: &Path, run_id: &str) -> Result<RunRequestContext> {
    let input = authenticated_input(target, run_id)?;
    let workspace = WorkspaceTarget::new(target)?;
    let (allowance, allowance_origin) = allowance::read_allowance(&workspace, run_id, &input);
    Ok(RunRequestContext {
        run_id: run_id.into(),
        read_at_unix: now_unix(),
        scope: scope(&workspace, &input).map_err(|error| format!("{error:#}")),
        allowance,
        allowance_origin,
    })
}

pub(crate) fn authenticated_input(target: &Path, run_id: &str) -> Result<Value> {
    let (_, text) = read_run_artifact_text_bounded(target, run_id, "input.json", MAX_INPUT_BYTES)?;
    let reference = load_run_artifact_object_reference(target, run_id, "input.json")?;
    anyhow::ensure!(
        reference.size_bytes == text.len() as u64
            && reference.hash == crate::content_store::object_hash(reference.kind, text.as_bytes()),
        "Recorded request changed since publication"
    );
    let input: Value = serde_json::from_str(&text)?;
    anyhow::ensure!(input.is_object(), "Recorded request must be an object");
    Ok(input)
}

fn scope(workspace: &WorkspaceTarget, input: &Value) -> Result<RecordedRequestScope> {
    if let Some(value) = input.get("scanScopeRef").filter(|value| !value.is_null()) {
        let reference: ScanScopeRef = serde_json::from_value(value.clone())?;
        let name = crate::workspace::recorded_scan_scope_name(workspace, &reference)?;
        return Ok(RecordedRequestScope::Accepted { name, reference });
    }
    if let Some(value) = input.get("paths").filter(|value| !value.is_null()) {
        let paths = value
            .as_array()
            .context("Recorded scope paths must be an array")?;
        anyhow::ensure!(
            paths.iter().all(Value::is_string),
            "Recorded scope paths are malformed"
        );
        return Ok(RecordedRequestScope::ExplicitPaths { count: paths.len() });
    }
    Ok(RecordedRequestScope::NotRecorded)
}

#[cfg(test)]
mod tests;
