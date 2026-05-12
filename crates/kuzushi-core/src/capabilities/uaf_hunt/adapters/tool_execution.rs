use crate::capabilities::uaf_hunt::adapters::output::report_to_tool_json;
use crate::capabilities::uaf_hunt::application::run_uaf_hunt_report;
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use anyhow::Result;
use serde_json::Value;

pub fn execute_uaf_hunt_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "uaf-hunt:hunt" => {
            let report = run_uaf_hunt_report(&input, ctx, runtime)?;
            Ok(report_to_tool_json(&report))
        }
        other => anyhow::bail!("uaf-hunt: unknown tool {other:?}"),
    }
}
