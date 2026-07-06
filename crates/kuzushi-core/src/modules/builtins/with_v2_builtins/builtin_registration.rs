use super::*;
use crate::modules::registry::ToolDispatchResult;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default)]
struct OptionalAdapterVisibility {
    prompt_armor: bool,
    shinsa: bool,
    tob: bool,
    vuln_scout: bool,
}

impl OptionalAdapterVisibility {
    fn detect() -> Self {
        Self {
            prompt_armor: optional_adapter_present(
                "promptarmor-plugin",
                "KUZUSHI_PROMPT_ARMOR_PLUGIN",
            ),
            shinsa: optional_adapter_present("shinsa-plugin", "KUZUSHI_SHINSA_PLUGIN"),
            tob: optional_adapter_present("@kuzushi/tob-skills", "KUZUSHI_TOB_SKILLS_DIR"),
            vuln_scout: optional_adapter_present(
                "@kuzushi/vuln-scout",
                "KUZUSHI_VULN_SCOUT_PLUGIN",
            ),
        }
    }

    fn plugin_adapters(self) -> plugin_adapters::PluginAdapterVisibility {
        plugin_adapters::PluginAdapterVisibility {
            shinsa: self.shinsa,
            tob: self.tob,
            vuln_scout: self.vuln_scout,
        }
    }
}

impl ModuleRegistry {
    pub fn with_v2_builtins() -> Self {
        Self::with_v2_builtins_for_optional_adapters(OptionalAdapterVisibility::detect())
    }

    fn with_v2_builtins_for_optional_adapters(adapters: OptionalAdapterVisibility) -> Self {
        let mut registry = Self::default();

        register_foundation_modules(&mut registry);
        register_workspace_catalog_modules(&mut registry);
        register_security_modules(&mut registry);
        plugin_adapters::register_modules(
            &mut registry,
            execute_plugin_prompt_tool,
            adapters.plugin_adapters(),
        );
        register_deferred_adapter_modules(&mut registry, adapters);

        registry
    }

    pub fn register(&mut self, builtin: BuiltinModule) {
        self.register_builtin_tools(&builtin);
        self.register_builtin_dag_executors(&builtin);
        self.modules.insert(builtin.metadata().id.clone(), builtin);
    }

    fn register_builtin_tools(&mut self, builtin: &BuiltinModule) {
        for tool in builtin.tools() {
            self.tools
                .insert(tool.name.clone(), descriptor_with_runtime_policy(tool));
            let executor = tool.executor.unwrap_or_else(|| {
                panic!(
                    "built-in tool {:?} in module {:?} has no descriptor executor",
                    tool.name,
                    builtin.metadata().id
                )
            });
            self.executors.insert(tool.name.clone(), executor);
        }
    }

    fn register_builtin_dag_executors(&mut self, builtin: &BuiltinModule) {
        for node in builtin.dag_nodes() {
            if !self.executors.contains_key(&node.id) {
                let executor = node.executor.unwrap_or_else(|| {
                    panic!(
                        "built-in DAG node {:?} in module {:?} has no descriptor executor",
                        node.id,
                        builtin.metadata().id
                    )
                });
                self.executors.insert(node.id.clone(), executor);
            }
        }
    }
}

fn execute_catalog_tool(
    registry: &ModuleRegistry,
    name: &str,
    _input: &Value,
    _ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(registry.dispatch_catalog_tool(name), name)
}

fn execute_module_recommender_tool(
    registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(
        registry.dispatch_module_recommender_tool(name, input, ctx, runtime),
        name,
    )
}

fn execute_context_workspace_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_context_workspace_tool(name, input, ctx), name)
}

fn execute_native_security_tool(
    registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(
        dispatch_native_security_tool(registry, name, input, ctx, runtime),
        name,
    )
}

fn execute_agentic_security_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(
        dispatch_agentic_security_tool(name, input, ctx, runtime),
        name,
    )
}

fn execute_systems_hunt_tool_mapping(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_systems_hunt_tool(name, input, ctx, runtime), name)
}

fn execute_uaf_hunt_tool_mapping(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_uaf_hunt_tool(name, input, ctx, runtime), name)
}

fn execute_pwn_tool_mapping(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_pwn_tool(name, input, ctx, runtime), name)
}

fn execute_offense_tool_mapping(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_offense_tool(name, input, ctx, runtime), name)
}

fn execute_threat_intel_tool_mapping(
    registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(
        registry.dispatch_threat_intel_tool(name, input, ctx, runtime),
        name,
    )
}

fn execute_runtime_analysis_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(
        dispatch_runtime_analysis_tool(name, input, ctx, runtime),
        name,
    )
}

fn execute_finding_action_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(
        dispatch_finding_action_tool(name, input, ctx, runtime),
        name,
    )
}

fn execute_recon_assessment_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(
        dispatch_recon_assessment_tool(name, input, ctx, runtime),
        name,
    )
}

fn execute_plugin_prompt_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_plugin_prompt_tool(name, input, ctx, runtime), name)
}

fn execute_pipeline_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(
        dispatch_plugin_prompt_tool(name, input, ctx, runtime)
            .or_else(|| dispatch_agentic_security_tool(name, input, ctx, runtime)),
        name,
    )
}

fn dispatch_result(result: ToolDispatchResult, name: &str) -> Result<Value> {
    result.with_context(|| format!("registered tool {name:?} has no executor mapping"))?
}

fn descriptor_with_runtime_policy(tool: &ToolDescriptor) -> ToolDescriptor {
    let mut descriptor = tool.clone();
    descriptor.runtime_requirement = runtime_requirement_for_tool(&descriptor.name);
    descriptor
}

fn runtime_requirement_for_tool(name: &str) -> RuntimeRequirement {
    if matches!(name, "sast:scan" | "full-mode:hunt" | "threat-model:build") {
        return RuntimeRequirement::InputAware;
    }
    if tool_uses_agent_runtime(name) || name == "pwn:auto-solve" {
        return RuntimeRequirement::Always;
    }
    RuntimeRequirement::Never
}

fn register_workspace_catalog_modules(registry: &mut ModuleRegistry) {
    registry.register(workspace_module().with_executor(execute_context_workspace_tool));
    registry.register(engagement_module().with_executor(execute_context_workspace_tool));
    registry.register(module_recommender_module().with_executor(execute_module_recommender_tool));
}

fn register_foundation_modules(registry: &mut ModuleRegistry) {
    registry.register(catalog_module().with_executor(execute_catalog_tool));
    registry.register(config_module().with_executor(execute_context_workspace_tool));
    registry.register(router_module().with_executor(execute_context_workspace_tool));
    registry.register(
        full_mode_module()
            .with_executor(execute_runtime_analysis_tool)
            .deferred(),
    );
    registry.register(classifier_gate_module().with_executor(execute_runtime_analysis_tool));
    registry.register(
        deep_audit_module()
            .with_executor(execute_runtime_analysis_tool)
            .deferred(),
    );
    context::register_context_modules(registry, execute_context_workspace_tool);
}

fn register_security_modules(registry: &mut ModuleRegistry) {
    registry.register(sast_module().with_executor(execute_native_security_tool));
    native_scanners::register_modules(registry, execute_native_security_tool);
    register_agentic_security_modules(registry);
    register_offense_hunt_modules(registry);
    register_finding_report_modules(registry);
    register_security_map_modules(registry);
    register_recon_assessment_modules(registry);
    register_misc_security_modules(registry);
}

fn register_agentic_security_modules(registry: &mut ModuleRegistry) {
    registry.register(agentic_sast_module().with_executor(execute_agentic_security_tool));
    registry.register(offense_review_module().with_executor(execute_agentic_security_tool));
    registry.register(
        carlini_threat_hunt_module()
            .with_executor(execute_agentic_security_tool)
            .deferred(),
    );
    registry.register(
        taint_iris_module()
            .with_executor(execute_agentic_security_tool)
            .deferred(),
    );
    registry.register(taint_iris_next_module().with_executor(execute_agentic_security_tool));
}

fn register_offense_hunt_modules(registry: &mut ModuleRegistry) {
    registry.register(systems_hunt_module().with_executor(execute_systems_hunt_tool_mapping));
    registry.register(
        uaf_hunt_module()
            .with_executor(execute_uaf_hunt_tool_mapping)
            .deferred(),
    );
    registry.register(
        pwn_module()
            .with_executor(execute_pwn_tool_mapping)
            .deferred(),
    );
    registry.register(
        offense_module()
            .with_executor(execute_offense_tool_mapping)
            .deferred(),
    );
    registry.register(threat_intel_module().with_executor(execute_threat_intel_tool_mapping));
}

fn register_finding_report_modules(registry: &mut ModuleRegistry) {
    registry.register(triage_module().with_executor(execute_finding_action_tool));
    registry.register(verify_module().with_executor(execute_finding_action_tool));
    registry.register(patch_module().with_executor(execute_finding_action_tool));
    registry.register(findings_module().with_executor(execute_context_workspace_tool));
    registry.register(report_module().with_executor(execute_context_workspace_tool));
}

fn register_security_map_modules(registry: &mut ModuleRegistry) {
    registry.register(threat_model_module().with_executor(execute_runtime_analysis_tool));
    registry.register(x_ray_module().with_executor(execute_runtime_analysis_tool));
    registry.register(entry_points_module().with_executor(execute_context_workspace_tool));
    registry.register(cpg_module().with_executor(execute_native_security_tool));
    registry.register(codeql_db_module().with_executor(execute_native_security_tool));
    registry.register(
        threat_leads_module()
            .with_executor(execute_runtime_analysis_tool)
            .deferred(),
    );
}

fn register_recon_assessment_modules(registry: &mut ModuleRegistry) {
    registry.register(
        vendor_assessment::module()
            .with_executor(execute_recon_assessment_tool)
            .deferred(),
    );
    registry.register(
        chrome_rce::module()
            .with_executor(execute_recon_assessment_tool)
            .deferred(),
    );
}

fn register_misc_security_modules(registry: &mut ModuleRegistry) {
    registry.register(dep_hygiene_module().with_executor(execute_native_security_tool));
    registry.register(secret_scan_module().with_executor(execute_native_security_tool));
    registry.register(pipeline_module().with_executor(execute_pipeline_tool));
    registry.register(variant_module().with_executor(execute_agentic_security_tool));
    registry.register(ndiff_module().with_executor(execute_agentic_security_tool));
    registry.register(randori_module().with_executor(execute_runtime_analysis_tool));
}

fn register_deferred_adapter_modules(
    registry: &mut ModuleRegistry,
    adapters: OptionalAdapterVisibility,
) {
    registry.register(visible_when(
        prompt_armor::module().with_executor(execute_plugin_prompt_tool),
        adapters.prompt_armor,
    ));
    registry.register(recon_module().with_executor(execute_recon_assessment_tool));
    registry.register(bounty_module().with_executor(execute_context_workspace_tool));
}

fn visible_when(module: BuiltinModule, visible: bool) -> BuiltinModule {
    if visible {
        module
    } else {
        module.deferred()
    }
}

fn optional_adapter_present(package_name: &str, env_var: &str) -> bool {
    adapter_env_configured(env_var) || node_package_installed(package_name)
}

fn adapter_env_configured(env_var: &str) -> bool {
    std::env::var_os(env_var).is_some_and(|value| !value.is_empty())
}

fn node_package_installed(package_name: &str) -> bool {
    package_search_roots()
        .into_iter()
        .any(|root| root.join("node_modules").join(package_name).exists())
}

fn package_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(current) = std::env::current_dir() {
        push_package_roots(&mut roots, &current);
    }
    push_package_roots(&mut roots, Path::new(env!("CARGO_MANIFEST_DIR")));
    roots
}

fn push_package_roots(roots: &mut Vec<PathBuf>, start: &Path) {
    for ancestor in start
        .ancestors()
        .filter(|path| path.join("package.json").exists())
    {
        let candidate = ancestor.to_path_buf();
        if !roots.contains(&candidate) {
            roots.push(candidate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_adapter_visibility_keeps_absent_plugins_hidden() {
        let registry =
            ModuleRegistry::with_v2_builtins_for_optional_adapters(OptionalAdapterVisibility {
                prompt_armor: false,
                shinsa: false,
                tob: false,
                vuln_scout: false,
            });

        assert!(!registry
            .modules()
            .any(|module| module.metadata().id == "prompt-armor"));
        assert!(registry.resolve_tool("prompt-armor:attack").is_some());
    }

    #[test]
    fn optional_adapter_visibility_surfaces_present_plugins() {
        let registry =
            ModuleRegistry::with_v2_builtins_for_optional_adapters(OptionalAdapterVisibility {
                prompt_armor: true,
                shinsa: true,
                tob: true,
                vuln_scout: true,
            });
        let visible_tools = registry
            .tools()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();

        assert!(visible_tools.contains(&"prompt-armor:attack"));
        assert!(visible_tools.contains(&"shinsa:scan"));
        assert!(visible_tools.contains(&"tob:audit"));
        assert!(visible_tools.contains(&"vuln-scout:audit"));
    }
}
