//! Human UI actions compile into the same prepared tool input as headless runs.
use crate::{
    FindingStore, ModuleRegistry, ScanCancellation, ToolExecutionContext, V2Config, WorkspaceTarget,
};
use anyhow::Result;
use serde_json::Value;

pub fn execute_source_review_action(
    workspace: &WorkspaceTarget,
    config: &V2Config,
    input: Value,
    cancellation: Option<&ScanCancellation>,
) -> Result<Value> {
    let store = FindingStore::open(workspace.findings_db_path())?;
    let ctx = ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("findings:review-source", input, &ctx, None)?
        .authorize_interactive_with_delegated_tools(&[]);
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}
