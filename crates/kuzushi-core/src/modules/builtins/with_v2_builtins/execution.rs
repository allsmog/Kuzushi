use super::*;
use crate::modules::registry::ToolDispatchResult;

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
        let scoped_trace = scoped_tool_trace(ctx, name);
        let scoped_ctx;
        let ctx: &ToolExecutionContext<'_> = if let Some(handle) = scoped_trace.as_ref() {
            scoped_ctx = scoped_tool_context(ctx, handle);
            &scoped_ctx
        } else {
            ctx
        };
        let traced_runtime = traced_tool_runtime(runtime, scoped_trace.as_ref());
        let runtime = active_tool_runtime(runtime, traced_runtime.as_ref());

        if let Some(result) = self.dispatch_prepared_tool_mapping(name, &input, ctx, runtime) {
            return result;
        }
        anyhow::bail!("registered tool or DAG node {name:?} has no Rust executor mapping")
    }

    fn dispatch_prepared_tool_mapping(
        &self,
        name: &str,
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> ToolDispatchResult {
        self.dispatch_catalog_tool(name)
            .or_else(|| dispatch_pre_threat_intel_tool(name, input, ctx, runtime))
            .or_else(|| self.dispatch_threat_intel_tool(name, input, ctx, runtime))
            .or_else(|| dispatch_post_threat_intel_tool(name, input, ctx, runtime))
    }
}

fn scoped_tool_trace(
    ctx: &ToolExecutionContext<'_>,
    name: &str,
) -> Option<crate::run_artifacts::TraceHandle> {
    ctx.trace
        .map(|handle| handle.for_module(module_id_from_tool_name(name)))
}

fn scoped_tool_context<'scope>(
    ctx: &'scope ToolExecutionContext<'_>,
    trace: &'scope crate::run_artifacts::TraceHandle,
) -> ToolExecutionContext<'scope> {
    ToolExecutionContext {
        config: ctx.config,
        workspace: ctx.workspace,
        findings_store: ctx.findings_store,
        trace: Some(trace),
    }
}

fn traced_tool_runtime<'scope>(
    runtime: Option<&'scope dyn AgentRuntime>,
    trace: Option<&'scope crate::run_artifacts::TraceHandle>,
) -> Option<crate::runtime::TracedRuntime<'scope>> {
    match (runtime, trace) {
        (Some(runtime), Some(trace)) => {
            Some(crate::runtime::TracedRuntime::new(runtime, trace.clone()))
        }
        _ => None,
    }
}

fn active_tool_runtime<'scope>(
    runtime: Option<&'scope dyn AgentRuntime>,
    traced_runtime: Option<&'scope crate::runtime::TracedRuntime<'scope>>,
) -> Option<&'scope dyn AgentRuntime> {
    traced_runtime
        .map(|runtime| runtime as &dyn AgentRuntime)
        .or(runtime)
}

fn dispatch_pre_threat_intel_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    dispatch_context_workspace_tool(name, input, ctx)
        .or_else(|| dispatch_native_security_tool(name, input, ctx, runtime))
        .or_else(|| dispatch_agentic_security_tool(name, input, ctx, runtime))
        .or_else(|| dispatch_systems_hunt_tool(name, input, ctx, runtime))
        .or_else(|| dispatch_uaf_hunt_tool(name, input, ctx, runtime))
        .or_else(|| dispatch_pwn_tool(name, input, ctx, runtime))
}

fn dispatch_post_threat_intel_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    dispatch_runtime_analysis_tool(name, input, ctx, runtime)
        .or_else(|| dispatch_finding_action_tool(name, input, ctx, runtime))
        .or_else(|| dispatch_recon_assessment_tool(name, input, ctx, runtime))
        .or_else(|| dispatch_plugin_prompt_tool(name, input, ctx, runtime))
}

/// Derive a module id from a qualified tool name (`semgrep:scan` -> `semgrep`).
/// Returns the full name when the colon is missing so unprefixed entries still
/// flow through with a stable label.
pub fn module_id_from_tool_name(name: &str) -> &str {
    name.split_once(':')
        .map(|(prefix, _)| prefix)
        .unwrap_or(name)
}

#[cfg(test)]
mod module_id_derivation_tests {
    use super::module_id_from_tool_name;

    #[test]
    fn module_id_strips_first_colon() {
        assert_eq!(module_id_from_tool_name("semgrep:scan"), "semgrep");
        assert_eq!(module_id_from_tool_name("triage:run"), "triage");
        assert_eq!(
            module_id_from_tool_name("agentic-sast:scan"),
            "agentic-sast"
        );
    }

    #[test]
    fn module_id_handles_unprefixed() {
        assert_eq!(module_id_from_tool_name("smoke"), "smoke");
    }

    #[test]
    fn module_id_only_strips_first_segment() {
        // Hidden internal nodes like `pipeline:taint-cwe-select` should still
        // collapse to their module id.
        assert_eq!(
            module_id_from_tool_name("pipeline:taint-cwe-select"),
            "pipeline"
        );
        assert_eq!(
            module_id_from_tool_name("systems-hunt:systems-trigger-synth"),
            "systems-hunt"
        );
    }
}
