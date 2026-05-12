use super::*;

impl ModuleRegistry {
    pub fn execute_tool(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<Value> {
        self.execute_tool_with_runtime(name, input, ctx, None)
    }

    pub fn execute_tool_with_runtime(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        self.execute_tool_with_runtime_and_options(name, input, ctx, runtime, None)
    }

    pub fn execute_tool_with_runtime_and_options(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
        option_store: Option<&ToolOptionStore>,
    ) -> Result<Value> {
        let input = self.prepare_tool_input(name, input, option_store)?;

        self.dispatch_prepared_tool_with_runtime(name, input, ctx, runtime)
    }

    pub fn prepare_tool_input(
        &self,
        name: &str,
        input: Value,
        option_store: Option<&ToolOptionStore>,
    ) -> Result<Value> {
        let tool = self.resolve_tool(name);
        if tool.is_none() && !self.is_registered_dag_node(name) {
            anyhow::bail!("unknown tool {name:?}. Next: run catalog:tools or use the Rust shell `tools` command");
        }
        let input = if let Some(store) = option_store {
            store.effective_tool_input(name, input)?
        } else {
            input
        };
        Ok(if let Some(tool) = tool {
            validate_tool_input_options(tool, input)?
        } else {
            input
        })
    }

    pub(in crate::modules) fn dispatch_prepared_tool_with_runtime(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        if let Some(result) = self.dispatch_catalog_tool(name) {
            return result;
        }
        if let Some(result) = dispatch_context_workspace_tool(name, &input, ctx) {
            return result;
        }
        if let Some(result) = dispatch_native_security_tool(name, &input, ctx, runtime) {
            return result;
        }
        if let Some(result) = dispatch_agentic_security_tool(name, &input, ctx, runtime) {
            return result;
        }
        if let Some(result) = dispatch_systems_hunt_tool(name, &input, ctx, runtime) {
            return result;
        }
        if let Some(result) = dispatch_uaf_hunt_tool(name, &input, ctx, runtime) {
            return result;
        }
        if let Some(result) = dispatch_runtime_analysis_tool(name, &input, ctx, runtime) {
            return result;
        }
        if let Some(result) = dispatch_finding_action_tool(name, &input, ctx, runtime) {
            return result;
        }
        if let Some(result) = dispatch_recon_assessment_tool(name, &input, ctx, runtime) {
            return result;
        }
        if let Some(result) = dispatch_plugin_prompt_tool(name, &input, ctx, runtime) {
            return result;
        }
        anyhow::bail!("registered tool or DAG node {name:?} has no Rust executor mapping")
    }
}
