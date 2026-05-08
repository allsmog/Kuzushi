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
        // Stamp the trace handle with the module id derived from the tool name
        // so producers don't need to thread it themselves. `ctx.trace` is None
        // in non-shell contexts (kuzushi run, evals) — the stamping no-ops.
        let scoped_trace = ctx
            .trace
            .map(|handle| handle.for_module(module_id_from_tool_name(name)));
        let scoped_ctx;
        let ctx: &ToolExecutionContext<'_> = if let Some(handle) = scoped_trace.as_ref() {
            scoped_ctx = ToolExecutionContext {
                config: ctx.config,
                workspace: ctx.workspace,
                findings_store: ctx.findings_store,
                trace: Some(handle),
            };
            &scoped_ctx
        } else {
            ctx
        };

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

/// Derive a module id from a qualified tool name (`semgrep:scan` -> `semgrep`).
/// Returns the full name when the colon is missing so unprefixed entries still
/// flow through with a stable label.
pub fn module_id_from_tool_name(name: &str) -> &str {
    name.split_once(':').map(|(prefix, _)| prefix).unwrap_or(name)
}
