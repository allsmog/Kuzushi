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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;

    #[test]
    fn unknown_uaf_hunt_tool_errors_before_runtime_work() {
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };
        let err =
            execute_uaf_hunt_tool("uaf-hunt:nope", serde_json::json!({}), &ctx, None).unwrap_err();
        assert!(err.to_string().contains("unknown tool"));
    }
}
