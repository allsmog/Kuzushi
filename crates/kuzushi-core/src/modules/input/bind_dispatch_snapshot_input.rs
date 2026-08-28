use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::Value;

/// Freezes workspace state that must remain exact between review and dispatch.
pub(in crate::modules) fn bind_dispatch_snapshot_input(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    if name != "sast:scan" {
        return Ok(input);
    }
    bind_sast_threat_model_reference(input, ctx)
}

fn bind_sast_threat_model_reference(
    mut input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let fields = input
        .as_object_mut()
        .context("sast:scan input must be an object")?;
    if fields.contains_key("threatModelRef") || fields.contains_key("threat_model_ref") {
        return Ok(input);
    }
    let workspace = ctx
        .workspace
        .context("sast:scan requires an active workspace before binding its threat model")?;
    crate::capabilities::threat_model::open_writable_threat_model_store(workspace.root())?;
    let model_ref = crate::capabilities::threat_model::load_active_threat_model(workspace.root())?
        .map(|active| active.model_ref);
    fields.insert("threatModelRef".to_string(), serde_json::to_value(model_ref)?);
    Ok(input)
}
