use super::*;
use crate::workspace::{RejectedScopeCandidate, MAX_REJECTED_SCOPE_BYTES};

pub(super) fn retain(
    ctx: &ToolExecutionContext<'_>,
    input: &Value,
    response: &crate::runtime::AgentQueryResponse,
    error: anyhow::Error,
) -> anyhow::Error {
    if input["saveRejectedOutput"] != true {
        return error;
    }
    let reason = safe_reason(&error);
    match persist(ctx, response, &error) {
        Ok(()) => error.context(format!("{reason}; rejected scope output saved as rejected-scope-output.json. No scope accepted or repair request made")),
        Err(_) => error.context(format!("{reason}; rejected scope output could not be retained. The original scope and consumed request remain unchanged")),
    }
}

fn persist(
    ctx: &ToolExecutionContext<'_>,
    response: &crate::runtime::AgentQueryResponse,
    error: &anyhow::Error,
) -> Result<()> {
    let (root, run) = ctx
        .run_artifact_location()
        .context("scope diagnostic requires its owning run")?;
    let workspace = ctx
        .workspace
        .context("scope diagnostic requires a workspace")?;
    anyhow::ensure!(
        std::fs::canonicalize(&root)? == std::fs::canonicalize(workspace.root())?,
        "scope diagnostic must remain in its run workspace"
    );
    let candidate = diagnostic(response, error)?;
    crate::run_artifacts::write_run_artifact_json(
        root,
        &run,
        "rejected-scope-output.json",
        "Unaccepted scope output: may contain source text",
        &serde_json::to_value(candidate)?,
    )?;
    Ok(())
}

fn diagnostic(
    response: &crate::runtime::AgentQueryResponse,
    error: &anyhow::Error,
) -> Result<RejectedScopeCandidate> {
    crate::structured_output::ensure_response_material_budget(response)?;
    let raw = match &response.structured {
        Some(value) => serde_json::to_string(value)?,
        None => response.text.clone(),
    };
    let mut end = raw.len().min(MAX_REJECTED_SCOPE_BYTES);
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    let value = RejectedScopeCandidate {
        schema_version: 1,
        candidate: raw[..end].into(),
        original_bytes: raw.len(),
        complete: !response.truncated && end == raw.len(),
        reason: safe_reason(error),
    };
    value.validate()?;
    Ok(value)
}

fn safe_reason(error: &anyhow::Error) -> String {
    error
        .to_string()
        .chars()
        .take(1024)
        .flat_map(char::escape_debug)
        .collect()
}
