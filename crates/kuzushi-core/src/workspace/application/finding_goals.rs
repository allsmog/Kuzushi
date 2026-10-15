//! Goal review in the shell consumes the shared descriptor-backed tools.
use super::*;

pub fn execute_goal_review(
    workspace: &WorkspaceTarget,
    config: &crate::V2Config,
    name: &str,
    input: serde_json::Value,
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        matches!(name, "findings:goals" | "findings:goal-assess"),
        "Unsupported goal review action"
    );
    let store = crate::FindingStore::open(workspace.findings_db_path())?;
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let ctx = crate::ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry.prepare_dispatch_input(name, input, &ctx, None)?;
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}
