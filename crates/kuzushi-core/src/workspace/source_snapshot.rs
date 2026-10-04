use crate::{ToolExecutionContext, WorkspaceTarget};
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

pub(crate) struct SourceSnapshot {
    snapshot_hash: String,
    tree_hash: String,
}

/// Bind a module result to the source present before its work starts. A
/// changed target retains the output and spend as partial, never as current.
pub(crate) fn run_source_bound_tool(
    ctx: &ToolExecutionContext<'_>,
    tool: &str,
    target: &Path,
    run: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    let snapshot = SourceSnapshot::capture(ctx, tool, target)?;
    Ok(snapshot.finish(ctx, tool, target, run()?))
}

fn mark_source_unverified(output: &mut Value, error: &anyhow::Error) {
    output["status"] = json!("partial");
    output["summary"] = json!("Source could not be verified after the run. Review the saved result, then run against the current source.");
    let mut warnings = output["warnings"].as_array().cloned().unwrap_or_default();
    warnings.push(json!(format!("Source verification: {error}")));
    output["warnings"] = json!(warnings);
}

impl SourceSnapshot {
    pub(crate) fn finish(
        self, ctx: &ToolExecutionContext<'_>, tool: &str, target: &Path, mut output: Value,
    ) -> Value {
        if let Err(error) = self.ensure_current(ctx, tool, target) {
            mark_source_unverified(&mut output, &error);
        }
        self.attach(output)
    }

    pub(crate) fn capture(
        ctx: &ToolExecutionContext<'_>,
        tool: &str,
        target: &Path,
    ) -> Result<Self> {
        let workspace = WorkspaceTarget::new(target)?;
        let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
        let mut observer = |files: usize| {
            if heartbeat.ready() {
                emit_source_progress(ctx, tool, files);
            }
        };
        let snapshot = crate::incremental_index::register_workspace_tree_identity_with_observer(
            &workspace,
            &mut observer,
        )?;
        Ok(Self {
            snapshot_hash: snapshot.snapshot_hash,
            tree_hash: snapshot.tree_hash,
        })
    }

    pub(crate) fn ensure_current(
        &self,
        ctx: &ToolExecutionContext<'_>,
        tool: &str,
        target: &Path,
    ) -> Result<()> {
        let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
        let mut observer = |files: usize| {
            if heartbeat.ready() {
                emit_source_progress(ctx, tool, files);
            }
        };
        let current = crate::incremental_index::current_workspace_tree_hash_with_observer(
            target,
            &mut observer,
        )?;
        anyhow::ensure!(
            current == self.tree_hash,
            "source changed during execution; run the tool again against the current source"
        );
        Ok(())
    }

    pub(crate) fn attach(self, mut result: Value) -> Value {
        if let Some(data) = result.get_mut("data").and_then(Value::as_object_mut) {
            data.insert("snapshotHash".to_string(), json!(self.snapshot_hash));
            data.insert("treeHash".to_string(), json!(self.tree_hash));
        }
        result
    }
}

fn emit_source_progress(ctx: &ToolExecutionContext<'_>, tool: &str, files: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                tool,
                format!("source identity · {files} files hashed"),
            )
            .emit();
    }
}

#[cfg(test)]
mod tests;
