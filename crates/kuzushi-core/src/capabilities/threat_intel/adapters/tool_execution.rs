use crate::capabilities::threat_intel::application::{
    apply_threat_intel_catalog, harvest_threat_intel_catalog, list_threat_intel_catalog,
    resolve_catalog_path,
};
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use anyhow::Result;
use serde_json::Value;

pub fn execute_threat_intel_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    mut dispatch_tool: impl FnMut(&str, Value, &ToolExecutionContext<'_>, Option<&dyn AgentRuntime>) -> Result<Value>,
) -> Result<Value> {
    match name {
        "threat-intel:list" => {
            let catalog_path = resolve_catalog_path(&input, ctx)?;
            list_threat_intel_catalog(&catalog_path)
        }
        "threat-intel:apply" => {
            let catalog_path = resolve_catalog_path(&input, ctx)?;
            // `dryRun` defaults to true: planning is cheap and safe;
            // operators explicitly opt into the live dispatch path
            // because each dispatched entry may spend agent budget.
            let dry_run = input
                .get("dryRun")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            apply_threat_intel_catalog(
                &catalog_path,
                ctx,
                runtime,
                !dry_run,
                &mut dispatch_tool,
            )
        }
        "threat-intel:harvest" => {
            harvest_threat_intel_catalog(&input, ctx, runtime, &mut dispatch_tool)
        }
        other => anyhow::bail!("threat-intel: unknown tool {other:?}"),
    }
}
