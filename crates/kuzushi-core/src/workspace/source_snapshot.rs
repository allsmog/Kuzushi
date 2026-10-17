use crate::module_result::{tool_result_status, ToolResultStatus};
use crate::{ToolExecutionContext, WorkspaceTarget};
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;
mod start_receipt;

#[derive(Debug, Clone)]
pub(crate) struct SourceSnapshot {
    snapshot_hash: String,
    tree_hash: String,
}

/// Bind a module result to the source present before its work starts. A
/// Changed source makes usable work partial without replacing prior failures.
pub(crate) fn run_source_bound_tool(
    ctx: &ToolExecutionContext<'_>,
    tool: &str,
    target: &Path,
    run: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    let snapshot = SourceSnapshot::capture(ctx, tool, target)?;
    let output = snapshot.bind_result(run())?;
    Ok(snapshot.finish(ctx, tool, target, output))
}

pub(crate) fn mark_source_unverified(output: &mut Value, error: &anyhow::Error) {
    match tool_result_status(output) {
        ToolResultStatus::Completed | ToolResultStatus::Partial => {
            output["status"] = json!("partial");
            output["summary"] = json!("Source could not be verified after the run. Review the saved result, then run against the current source.");
        }
        ToolResultStatus::Failed => output["status"] = json!("failed"),
        ToolResultStatus::Skipped => output["status"] = json!("skipped"),
    }
    record_source_check_current(output, false);
    let mut warnings = output["warnings"].as_array().cloned().unwrap_or_default();
    warnings.push(json!(format!("Source verification: {error}")));
    output["warnings"] = json!(warnings);
}

fn record_source_check_current(output: &mut Value, current: bool) {
    if let Some(data) = output.get_mut("data").and_then(Value::as_object_mut) {
        data.insert("sourceCheckCurrent".into(), json!(current));
    }
}

impl SourceSnapshot {
    pub(crate) fn hashes(&self) -> (&str, &str) {
        (&self.snapshot_hash, &self.tree_hash)
    }

    /// Preserve the host's pre-execution identity through error settlement.
    pub(crate) fn bind_result<T>(&self, result: Result<T>) -> Result<T> {
        result.map_err(|cause| {
            anyhow::Error::new(SourceBoundFailure {
                snapshot: self.clone(),
                cause,
            })
        })
    }

    pub(crate) fn finish(
        self,
        ctx: &ToolExecutionContext<'_>,
        tool: &str,
        target: &Path,
        mut output: Value,
    ) -> Value {
        match self.ensure_current(ctx, tool, target) {
            Ok(()) => record_source_check_current(&mut output, true),
            Err(error) => mark_source_unverified(&mut output, &error),
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
        let snapshot = crate::incremental_index::register_workspace_tree_identity_cancellable(
            &workspace,
            &mut observer,
            &|| ctx.is_cancelled(),
        )?;
        let source = Self {
            snapshot_hash: snapshot.snapshot_hash,
            tree_hash: snapshot.tree_hash,
        };
        start_receipt::persist(ctx, tool, target, &source)?;
        Ok(source)
    }

    pub(crate) fn ensure_current(
        &self,
        ctx: &ToolExecutionContext<'_>,
        tool: &str,
        target: &Path,
    ) -> Result<()> {
        let current = inspect_current_source_hash(ctx, tool, target)?;
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

#[derive(Debug)]
struct SourceBoundFailure {
    snapshot: SourceSnapshot,
    cause: anyhow::Error,
}

pub(crate) fn inspect_current_source_hash(
    ctx: &ToolExecutionContext<'_>,
    tool: &str,
    target: &Path,
) -> Result<String> {
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let mut observer = |files: usize| {
        if heartbeat.ready() {
            emit_source_progress(ctx, tool, files);
        }
    };
    crate::incremental_index::current_workspace_tree_hash_cancellable(
        target,
        &mut observer,
        &|| ctx.is_cancelled(),
    )
}

impl std::fmt::Display for SourceBoundFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.cause, formatter)
    }
}

impl std::error::Error for SourceBoundFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

pub(crate) fn failed_source_snapshot(error: &anyhow::Error) -> Option<SourceSnapshot> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<SourceBoundFailure>()
            .map(|failure| failure.snapshot.clone())
    })
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
