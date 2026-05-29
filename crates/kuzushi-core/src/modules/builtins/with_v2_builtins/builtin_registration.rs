use super::*;
use crate::modules::registry::{ToolDispatchResult, ToolExecutor};

impl ModuleRegistry {
    pub fn with_v2_builtins() -> Self {
        let mut registry = Self::default();

        register_foundation_modules(&mut registry);
        register_workspace_catalog_modules(&mut registry);
        register_security_modules(&mut registry);
        plugin_adapters::register_modules(&mut registry);
        register_deferred_adapter_modules(&mut registry);

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
            self.register_executor_if_available(&tool.name);
        }
    }

    fn register_builtin_dag_executors(&mut self, builtin: &BuiltinModule) {
        for node in builtin.dag_nodes() {
            if !self.executors.contains_key(&node.id) {
                self.register_executor_if_available(&node.id);
            }
        }
    }

    fn register_executor_if_available(&mut self, name: &str) {
        if let Some(executor) = executor_for_tool(name) {
            self.executors.insert(name.to_string(), executor);
        }
    }
}

fn executor_for_tool(name: &str) -> Option<ToolExecutor> {
    foundation_executor_for_tool(name)
        .or_else(|| security_executor_for_tool(name))
        .or_else(|| specialist_executor_for_tool(name))
        .or_else(|| runtime_executor_for_tool(name))
        .or_else(|| findings_executor_for_tool(name))
        .or_else(|| adapter_executor_for_tool(name))
}

fn foundation_executor_for_tool(name: &str) -> Option<ToolExecutor> {
    match name {
        "catalog:modules" | "catalog:tools" => Some(execute_catalog_tool),
        "module-recommender:recommend" => Some(execute_module_recommender_tool),
        "context:build" | "context-lite:index" | "config:show" | "router:show"
        | "workspace:status" | "workspace:export-findings" | "findings:list" | "report:build"
        | "entry-points:extract" => Some(execute_context_workspace_tool),
        _ => None,
    }
}

fn security_executor_for_tool(name: &str) -> Option<ToolExecutor> {
    match name {
        "dep-hygiene:check" | "secret-scan:scan" | "semgrep:scan" | "codeql:scan"
        | "iac-scan:scan" | "cargo-audit:scan" | "license-scan:scan" | "sbom-scan:scan"
        | "exploit-chain:scan" | "sast:scan" | "cpg:build" | "codeql:create-db" => {
            Some(execute_native_security_tool)
        }
        "agentic-sast:scan" | "variant:lift-pattern" | "variant:hunt" | "ndiff:fetch-cve"
        | "ndiff:extract-fix-pattern" | "ndiff:hunt-variants" | "carlini-threat-hunt:run"
        | "offense-review:threat-hunt" | "pipeline:taint-cwe-select" | "taint-iris:hunt"
        | "taint-iris-next:hunt" | "taint-iris-next:dataflow-plan"
        | "taint-iris-next:source-sink-trace" | "taint-iris-next:finding-review"
        | "taint-iris-next:catalog" | "taint-iris-next:codeql-db" => {
            Some(execute_agentic_security_tool)
        }
        _ => None,
    }
}

fn specialist_executor_for_tool(name: &str) -> Option<ToolExecutor> {
    match name {
        "systems-hunt:systems-context-gatherer"
        | "systems-hunt:systems-invariant-extract"
        | "systems-hunt:systems-hunt"
        | "systems-hunt:deep-semantic-cwe-select"
        | "systems-hunt:deep-semantic-hunt"
        | "systems-hunt:systems-trigger-synth" => Some(execute_systems_hunt_tool_mapping),
        "uaf-hunt:hunt" => Some(execute_uaf_hunt_tool_mapping),
        "pwn:profile-binary" | "pwn:reverse" | "pwn:state" | "pwn:calibrate-local"
        | "pwn:run-candidates" | "pwn:auto-solve" => Some(execute_pwn_tool_mapping),
        "threat-intel:discover"
        | "threat-intel:list"
        | "threat-intel:apply"
        | "threat-intel:harvest" => Some(execute_threat_intel_tool_mapping),
        _ => None,
    }
}

fn runtime_executor_for_tool(name: &str) -> Option<ToolExecutor> {
    match name {
        "full-mode:hunt"
        | "classifier-gate:score"
        | "deep-audit:run"
        | "smoke:next-step"
        | "threat-model:build"
        | "threat-model:read"
        | "threat-model:methodologies"
        | "randori:pasta"
        | "randori:threat-model"
        | "x-ray:run"
        | "x-ray:read"
        | "x-ray:x-ray"
        | "threat-leads:build"
        | "threat-leads:read" => Some(execute_runtime_analysis_tool),
        _ => None,
    }
}

fn findings_executor_for_tool(name: &str) -> Option<ToolExecutor> {
    match name {
        "triage:run" | "verify:finding" | "verify:exploit" | "patch:finding" => {
            Some(execute_finding_action_tool)
        }
        "findings:suppress" | "findings:unsuppress" | "findings:verify"
        | "findings:verify-batch" | "findings:patch" => Some(execute_finding_action_tool),
        _ => None,
    }
}

fn adapter_executor_for_tool(name: &str) -> Option<ToolExecutor> {
    match name {
        "recon:nmap"
        | "recon:subdomain"
        | "recon:http-fingerprint"
        | "vendor-assessment:attach"
        | "vendor-assessment:scope"
        | "vendor-assessment:prompts"
        | "vendor-assessment:assess"
        | "chrome-rce:scan"
        | "chrome-rce:review-trigger" => {
            Some(execute_recon_assessment_tool)
        }
        "vuln-scout:audit" | "tob:audit" | "tob:skills" | "shinsa:scan"
        | "shinsa:quick-check" | "shinsa:nist-scan" | "shinsa:nist-quick-check"
        | "shinsa:frameworks" | "prompt-armor:scan" | "prompt-armor:analyze"
        | "prompt-armor:attack" | "prompt-armor:diff" | "prompt-armor:report"
        | "prompt-armor:config" | "pipeline:task-selector"
        | "pipeline:approval-before-verification" => Some(execute_plugin_prompt_tool),
        _ => None,
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
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_native_security_tool(name, input, ctx, runtime), name)
}

fn execute_agentic_security_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_agentic_security_tool(name, input, ctx, runtime), name)
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

fn execute_threat_intel_tool_mapping(
    registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(registry.dispatch_threat_intel_tool(name, input, ctx, runtime), name)
}

fn execute_runtime_analysis_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_runtime_analysis_tool(name, input, ctx, runtime), name)
}

fn execute_finding_action_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_finding_action_tool(name, input, ctx, runtime), name)
}

fn execute_recon_assessment_tool(
    _registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    dispatch_result(dispatch_recon_assessment_tool(name, input, ctx, runtime), name)
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

fn dispatch_result(result: ToolDispatchResult, name: &str) -> Result<Value> {
    result.with_context(|| format!("registered tool {name:?} has no executor mapping"))?
}

fn descriptor_with_runtime_policy(tool: &ToolDescriptor) -> ToolDescriptor {
    let mut descriptor = tool.clone();
    descriptor.runtime_requirement = runtime_requirement_for_tool(&descriptor.name);
    descriptor
}

fn runtime_requirement_for_tool(name: &str) -> RuntimeRequirement {
    if name == "sast:scan" {
        return RuntimeRequirement::InputAware;
    }
    if tool_uses_agent_runtime(name) || name == "pwn:auto-solve" {
        return RuntimeRequirement::Always;
    }
    RuntimeRequirement::Never
}

fn register_workspace_catalog_modules(registry: &mut ModuleRegistry) {
    registry.register(workspace_module());
    registry.register(module_recommender_module());
}

fn register_foundation_modules(registry: &mut ModuleRegistry) {
    registry.register(catalog_module());
    registry.register(config_module());
    registry.register(router_module());
    registry.register(full_mode_module());
    registry.register(classifier_gate_module());
    registry.register(deep_audit_module());
    registry.register(smoke_module());
    context::register_context_modules(registry);
}

fn register_security_modules(registry: &mut ModuleRegistry) {
    registry.register(sast_module());
    native_scanners::register_modules(registry);
    registry.register(agentic_sast_module());
    registry.register(offense_review_module());
    registry.register(carlini_threat_hunt_module().deferred());
    registry.register(taint_iris_module());
    registry.register(taint_iris_next_module());
    registry.register(systems_hunt_module());
    registry.register(uaf_hunt_module().deferred());
    registry.register(pwn_module().deferred());
    registry.register(threat_intel_module());
    registry.register(triage_module());
    registry.register(verify_module());
    registry.register(patch_module());
    registry.register(findings_module());
    registry.register(report_module());
    registry.register(threat_model_module());
    registry.register(x_ray_module());
    registry.register(entry_points_module());
    registry.register(cpg_module());
    registry.register(codeql_db_module());
    registry.register(threat_leads_module());
    registry.register(vendor_assessment::module().deferred());
    registry.register(chrome_rce::module().deferred());
    registry.register(dep_hygiene_module());
    registry.register(secret_scan_module());
    registry.register(pipeline_module());
    registry.register(variant_module());
    registry.register(ndiff_module());
    registry.register(randori_module());
}

fn register_deferred_adapter_modules(registry: &mut ModuleRegistry) {
    registry.register(prompt_armor::module().deferred());
    registry.register(recon_module().deferred());
}
