use super::prelude::*;
use super::*;

pub(in crate::modules) fn dispatch_plugin_prompt_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "vuln-scout:audit" | "tob:audit" | "tob:skills" => Some(plugin_adapters::execute_tool(
            name,
            input.clone(),
            ctx,
            runtime,
        )),
        "shinsa:scan"
        | "shinsa:quick-check"
        | "shinsa:nist-scan"
        | "shinsa:nist-quick-check"
        | "shinsa:frameworks" => Some(plugin_adapters::execute_tool(
            name,
            input.clone(),
            ctx,
            runtime,
        )),
        "prompt-armor:scan"
        | "prompt-armor:analyze"
        | "prompt-armor:attack"
        | "prompt-armor:diff"
        | "prompt-armor:report"
        | "prompt-armor:config" => Some(prompt_armor::execute_tool(
            name,
            input.clone(),
            ctx,
            runtime,
        )),
        "pipeline:task-selector" => Some(run_pipeline_task_selector(input.clone(), ctx)),
        "pipeline:approval-before-verification" => Some(run_pipeline_approval_gate(input.clone())),
        _ => None,
    }
}
