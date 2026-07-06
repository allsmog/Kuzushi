use super::*;

pub(in crate::modules) fn dispatch_plugin_prompt_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    if plugin_adapter_tool(name) {
        return Some(plugin_adapters::execute_tool(
            name,
            input.clone(),
            ctx,
            runtime,
        ));
    }
    if prompt_armor_tool(name) {
        return Some(prompt_armor::execute_tool(
            name,
            input.clone(),
            ctx,
            runtime,
        ));
    }
    match name {
        "pipeline:task-selector" => Some(run_pipeline_task_selector(input.clone(), ctx)),
        "pipeline:approval-before-verification" => Some(run_pipeline_approval_gate(input.clone())),
        _ => None,
    }
}

fn plugin_adapter_tool(name: &str) -> bool {
    matches!(
        name,
        "wasm-plugin:analyze"
            | "vuln-scout:audit"
            | "tob:audit"
            | "tob:skills"
            | "shinsa:scan"
            | "shinsa:quick-check"
            | "shinsa:nist-scan"
            | "shinsa:nist-quick-check"
            | "shinsa:frameworks"
    )
}

fn prompt_armor_tool(name: &str) -> bool {
    matches!(
        name,
        "prompt-armor:scan"
            | "prompt-armor:analyze"
            | "prompt-armor:attack"
            | "prompt-armor:diff"
            | "prompt-armor:report"
            | "prompt-armor:config"
    )
}
