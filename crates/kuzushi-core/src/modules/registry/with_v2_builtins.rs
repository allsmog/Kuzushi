use super::prelude::*;
use super::*;

impl ModuleRegistry {
    pub fn with_v2_builtins() -> Self {
        let mut registry = Self::default();

        registry.register(catalog_module());
        registry.register(config_module());
        registry.register(router_module());
        registry.register(full_mode_module());
        registry.register(classifier_gate_module());
        registry.register(deep_audit_module());
        registry.register(smoke_module());
        registry.register(workspace_module());
        context::register_context_modules(&mut registry);
        registry.register(sast_module());
        native_scanners::register_modules(&mut registry);
        registry.register(agentic_sast_module());
        registry.register(carlini_threat_hunt_module());
        registry.register(taint_iris_module());
        registry.register(taint_iris_next_module());
        registry.register(systems_hunt_module());
        registry.register(triage_module());
        registry.register(verify_module());
        registry.register(patch_module());
        registry.register(findings_module());
        registry.register(threat_model_module());
        registry.register(x_ray_module());
        registry.register(vendor_assessment::module());
        registry.register(chrome_rce::module());
        registry.register(dep_hygiene_module());
        registry.register(secret_scan_module());
        registry.register(pipeline_module());
        registry.register(variant_module());
        registry.register(ndiff_module());
        registry.register(randori_module());
        plugin_adapters::register_modules(&mut registry);
        registry.register(prompt_armor::module());
        registry.register(recon_module());

        registry
    }

    pub fn register(&mut self, module: BuiltinModule) {
        for tool in module.tools() {
            self.tools.insert(tool.name.clone(), tool.clone());
        }
        self.modules.insert(module.metadata().id.clone(), module);
    }

    pub fn modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules.values().filter(|module| !module.is_hidden())
    }

    pub fn all_modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules.values()
    }

    pub fn tools(&self) -> impl Iterator<Item = &ToolDescriptor> {
        self.tools.values()
    }

    pub fn resolve_tool(&self, name: &str) -> Option<&ToolDescriptor> {
        self.tools.get(name)
    }

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

    pub(in crate::modules) fn is_registered_dag_node(&self, name: &str) -> bool {
        self.all_modules()
            .flat_map(BuiltinModule::dag_nodes)
            .any(|node| node.id == name)
    }
}
