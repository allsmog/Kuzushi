use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::binary_analysis::{scan_binaries, BinaryAnalysisOptions};
use crate::carlini_threat_hunt::run_carlini_threat_hunt;
use crate::dep_hygiene::check_dependency_hygiene;
use crate::findings::FindingListFilter;
use crate::options::ToolOptionStore;
use crate::patch::run_patch_finding;
use crate::recon::execute_recon_tool;
use crate::runtime::AgentRuntime;
use crate::scan::ScanCancellation;
use crate::secret_scan::{scan_for_secrets, SecretScanOptions};
use crate::systems_hunt::execute_systems_hunt_tool;
use crate::threat_model::execute_threat_model_tool;
use crate::variant_ndiff::{
    run_ndiff_extract_fix_pattern, run_ndiff_fetch_cve, run_ndiff_hunt_variants, run_variant_hunt,
    run_variant_lift_pattern,
};
use crate::x_ray::execute_x_ray_tool;

use super::agentic_sast::run_agentic_sast_report;
use super::options::validate_tool_input_options;
use super::pipeline::{run_pipeline_approval_gate, run_pipeline_task_selector};
use super::sast_pipeline::run_sast_scan;
use super::taint_iris::{run_taint_cwe_select, run_taint_iris_report};
use super::taint_iris_next::run_taint_iris_next_report;
use super::triage::run_triage;
use super::verify::{run_verify_exploit, run_verify_finding};
use super::workspace_tools::{export_workspace_findings_tool, workspace_status_output};
use super::{
    agentic_sast_module, auto_hunt_module, binary_analysis_module, carlini_threat_hunt_module,
    catalog_module, chrome_rce, classifier_gate_module, config_module, context, deep_audit_module,
    dep_hygiene_module, findings_module, full_mode_module, native_scanners, ndiff_module,
    patch_module, pipeline_module, plugin_adapters, prompt_armor, randori_module, recon_module,
    resolve_tool_target, router_module, router_show_tool, run_auto_hunt_tool,
    run_classifier_score_tool, run_deep_audit_tool, run_full_mode_hunt_tool,
    run_smoke_next_step_tool, sast_module, secret_scan_module, smoke_module, systems_hunt_module,
    taint_iris_module, taint_iris_next_module, threat_model_module, triage_module, variant_module,
    vendor_assessment, verify_module, workspace_module, x_ray_module, BuiltinModule,
    ToolDescriptor, ToolExecutionContext,
};

pub(super) type ToolDispatchResult = Option<Result<Value>>;

#[derive(Debug, Default, Clone)]
pub struct ModuleRegistry {
    modules: BTreeMap<String, BuiltinModule>,
    tools: BTreeMap<String, ToolDescriptor>,
}

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
        registry.register(auto_hunt_module());
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
        registry.register(binary_analysis_module());
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

    fn dispatch_prepared_tool_with_runtime(
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
        if let Some(result) = dispatch_agentic_security_tool(self, name, &input, ctx, runtime) {
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

    fn is_registered_dag_node(&self, name: &str) -> bool {
        self.all_modules()
            .flat_map(BuiltinModule::dag_nodes)
            .any(|node| node.id == name)
    }
}

impl ModuleRegistry {
    pub(super) fn dispatch_catalog_tool(&self, name: &str) -> ToolDispatchResult {
        match name {
            "catalog:modules" => Some(Ok(json!(self
                .modules()
                .map(|module| module.metadata())
                .collect::<Vec<_>>()))),
            "catalog:tools" => Some(Ok(json!(self.tools().collect::<Vec<_>>()))),
            _ => None,
        }
    }
}

fn dispatch_context_workspace_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> ToolDispatchResult {
    match name {
        "context:build" | "context-lite:index" => {
            Some(context::build_context_snapshot(input.clone(), ctx))
        }
        "config:show" => Some(Ok(json!(ctx.config))),
        "router:show" => Some(router_show_tool(input.clone(), ctx)),
        "workspace:status" => Some(Ok(workspace_status_json(ctx))),
        "workspace:export-findings" => Some(export_workspace_findings_tool(input.clone(), ctx)),
        "findings:list" => Some(list_findings_tool(input, ctx)),
        _ => None,
    }
}

fn workspace_status_json(ctx: &ToolExecutionContext<'_>) -> Value {
    json!({
        "ok": ctx.workspace.is_some(),
        "output": workspace_status_output(ctx),
        "root": ctx.workspace.map(|workspace| workspace.root().display().to_string()),
        "stateDir": ctx.workspace.map(|workspace| workspace.state_dir().display().to_string()),
        "findingsDb": ctx.workspace.map(|workspace| workspace.findings_db_path().display().to_string()),
        "runtime": ctx.config.runtime.kind,
        "model": ctx.config.model,
    })
}

fn list_findings_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let filter = FindingListFilter::from_tool_input(input)?;
    let store = ctx
        .findings_store
        .context("findings:list requires a findings store")?;
    Ok(store.list_findings_filtered(&filter)?.to_tool_json())
}

fn dispatch_native_security_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "dep-hygiene:check" => Some(run_dep_hygiene_tool(input, ctx)),
        "secret-scan:scan" => Some(run_secret_scan_tool(input, ctx)),
        "binary-analysis:scan" => Some(run_binary_analysis_tool(input, ctx)),
        "semgrep:scan" | "codeql:scan" | "iac-scan:scan" => {
            Some(native_scanners::execute_tool(name, input.clone(), ctx))
        }
        "sast:scan" => Some(run_sast_scan(input.clone(), ctx, runtime)),
        _ => None,
    }
}

fn run_dep_hygiene_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let report = check_dependency_hygiene(&target)?;
    Ok(report.to_tool_json())
}

fn run_secret_scan_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let options = SecretScanOptions::from_tool_input(input)?;
    let report = scan_for_secrets(&target, &options, &ScanCancellation::default())?;
    Ok(report.to_tool_json())
}

fn run_binary_analysis_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let options = BinaryAnalysisOptions::from_tool_input(input)?;
    let report = scan_binaries(&target, &options, &ScanCancellation::default())?;
    Ok(report.to_tool_json())
}

fn dispatch_agentic_security_tool(
    registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "auto-hunt:run" => Some(run_auto_hunt_tool(input.clone(), ctx, runtime, registry)),
        "agentic-sast:scan" => Some(run_agentic_sast_tool(input, ctx, runtime)),
        "variant:lift-pattern" => Some(run_variant_lift_pattern(input.clone(), ctx, runtime)),
        "variant:hunt" => Some(run_variant_hunt(input.clone(), ctx, runtime)),
        "ndiff:fetch-cve" => Some(run_ndiff_fetch_cve(input.clone())),
        "ndiff:extract-fix-pattern" => {
            Some(run_ndiff_extract_fix_pattern(input.clone(), ctx, runtime))
        }
        "ndiff:hunt-variants" => Some(run_ndiff_hunt_variants(input.clone(), ctx, runtime)),
        "carlini-threat-hunt:run" => Some(run_carlini_threat_hunt(input.clone(), ctx, runtime)),
        "pipeline:taint-cwe-select" => Some(run_taint_cwe_select(input.clone(), ctx, runtime)),
        "taint-iris:hunt" => Some(run_taint_iris_tool(input, ctx, runtime)),
        "taint-iris-next:hunt" => Some(run_taint_iris_next_tool(input, ctx, runtime)),
        _ => None,
    }
}

fn run_agentic_sast_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_agentic_sast_report(input, ctx, runtime)?.to_tool_json())
}

fn run_taint_iris_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_taint_iris_report(input, ctx, runtime)?.to_tool_json())
}

fn run_taint_iris_next_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_taint_iris_next_report(input, ctx, runtime)?.to_tool_json())
}

fn dispatch_systems_hunt_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "systems-hunt:systems-context-gatherer"
        | "systems-hunt:systems-invariant-extract"
        | "systems-hunt:systems-trigger-synth"
        | "systems-hunt:systems-hunt"
        | "systems-hunt:deep-semantic-cwe-select"
        | "systems-hunt:deep-semantic-hunt" => {
            Some(execute_systems_hunt_tool(name, input.clone(), ctx, runtime))
        }
        _ => None,
    }
}

fn dispatch_runtime_analysis_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "full-mode:hunt" => Some(run_full_mode_hunt_tool(input.clone(), ctx, runtime)),
        "classifier-gate:score" => Some(run_classifier_score_tool(input.clone(), ctx, runtime)),
        "deep-audit:run" => Some(run_deep_audit_tool(input.clone(), ctx, runtime)),
        "smoke:next-step" => Some(run_smoke_next_step_tool(input.clone(), ctx, runtime)),
        "threat-model:build"
        | "threat-model:read"
        | "threat-model:methodologies"
        | "randori:pasta"
        | "randori:threat-model" => {
            Some(execute_threat_model_tool(name, input.clone(), ctx, runtime))
        }
        "x-ray:run" | "x-ray:read" | "x-ray:x-ray" => {
            Some(execute_x_ray_tool(name, input.clone(), ctx, runtime))
        }
        _ => None,
    }
}

fn dispatch_finding_action_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "triage:run" => Some(run_triage(input.clone(), ctx, runtime)),
        "verify:finding" => Some(run_verify_finding(input.clone(), ctx, runtime)),
        "verify:exploit" => Some(run_verify_exploit(input.clone(), ctx)),
        "patch:finding" => Some(run_patch_finding(input.clone(), ctx, runtime)),
        _ => None,
    }
}

fn dispatch_recon_assessment_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "recon:nmap" | "recon:subdomain" | "recon:http-fingerprint" => {
            Some(execute_recon_tool(name, input.clone(), ctx))
        }
        "vendor-assessment:attach"
        | "vendor-assessment:scope"
        | "vendor-assessment:prompts"
        | "vendor-assessment:assess" => Some(vendor_assessment::execute_tool(
            name,
            input.clone(),
            ctx,
            runtime,
        )),
        "chrome-rce:scan" | "chrome-rce:review-trigger" => {
            Some(chrome_rce::execute_tool(name, input.clone(), ctx))
        }
        _ => None,
    }
}

fn dispatch_plugin_prompt_tool(
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

#[cfg(test)]
mod tests {
    use super::super::OptionType;
    use super::*;
    use crate::config::V2Config;
    use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
    use serde_json::{json, Value};

    #[test]
    fn prepares_tool_input_with_stored_options_before_validation() {
        let registry = ModuleRegistry::with_v2_builtins();
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(false),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Module("sast".to_string()),
            "triage",
            json!(true),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "verify",
            json!("yes"),
        );

        let prepared = registry
            .prepare_tool_input("sast:scan", json!({"triage": false}), Some(&store))
            .unwrap();

        assert_eq!(prepared["taskMode"], json!("auto"));
        assert_eq!(prepared["triage"], json!(false));
        assert_eq!(prepared["verify"], json!(true));
        assert_eq!(prepared.get("model"), None);
    }

    #[test]
    fn stored_required_options_satisfy_tool_validation_without_model_fallback() {
        let registry = ModuleRegistry::with_v2_builtins();
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("recon:nmap".to_string()),
            "target",
            json!("192.0.2.10"),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("recon:nmap".to_string()),
            "ports",
            json!("80,443"),
        );

        let prepared = registry
            .prepare_tool_input("recon:nmap", Value::Null, Some(&store))
            .unwrap();

        assert_eq!(prepared["target"], json!("192.0.2.10"));
        assert_eq!(prepared["ports"], json!("80,443"));
        assert_eq!(prepared.get("model"), None);
    }

    #[test]
    fn exposes_option_specs_for_visible_tool_descriptors() {
        let registry = ModuleRegistry::with_v2_builtins();

        let sast = registry.resolve_tool("sast:scan").unwrap();
        assert!(sast
            .options
            .iter()
            .any(|option| option.name == "tasks" && option.option_type == OptionType::StringList));
        assert!(sast
            .options
            .iter()
            .any(|option| option.name == "disabledTasks"
                && option.option_type == OptionType::StringList));
        assert!(sast.options.iter().any(
            |option| option.name == "severity" && option.option_type == OptionType::StringList
        ));

        let semgrep = registry.resolve_tool("semgrep:scan").unwrap();
        assert!(semgrep.options.iter().any(|option| option.name == "config"
            && option.option_type == OptionType::String
            && option.default == Some(json!("auto"))));

        let codeql = registry.resolve_tool("codeql:scan").unwrap();
        assert!(codeql.options.iter().any(|option| option.name == "language"
            && option.option_type == OptionType::Enum
            && option.choices.contains(&"javascript".to_string())));
        assert!(codeql
            .options
            .iter()
            .any(|option| option.name == "multiLanguage"
                && option.option_type == OptionType::Bool
                && option.default == Some(json!(false))));

        let x_ray = registry.resolve_tool("x-ray:run").unwrap();
        assert!(x_ray.options.iter().any(|option| {
            option.name == "maxBudgetUsd"
                && option.option_type == OptionType::Float
                && option.advanced
        }));

        let recon = registry.resolve_tool("recon:nmap").unwrap();
        assert!(recon.options.iter().any(|option| option.name == "target"
            && option.option_type == OptionType::String
            && option.required));

        let iac = registry.resolve_tool("iac-scan:scan").unwrap();
        assert!(iac.options.iter().any(|option| option.name == "kind"
            && option.option_type == OptionType::Enum
            && option.choices.contains(&"terraform".to_string())));

        let prompt_armor = registry.resolve_tool("prompt-armor:attack").unwrap();
        assert!(prompt_armor
            .options
            .iter()
            .any(|option| option.name == "payload" && option.evasion));
    }

    #[test]
    fn catalog_tool_serialization_keeps_core_descriptor_fields() {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = ToolExecutionContext {
            config: &V2Config::default(),
            workspace: None,
            findings_store: None,
        };

        let tools = registry
            .execute_tool("catalog:tools", Value::Null, &ctx)
            .unwrap();
        let catalog_modules = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "catalog:modules")
            .unwrap();
        assert_eq!(
            catalog_modules["description"],
            json!("List native modules.")
        );
        assert_eq!(catalog_modules["headless"], json!(true));
        assert!(catalog_modules.get("options").is_none());

        let semgrep = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "semgrep:scan")
            .unwrap();
        assert_eq!(semgrep["headless"], json!(true));
        assert!(semgrep["options"]
            .as_array()
            .unwrap()
            .iter()
            .any(|option| option["name"] == "config"));
    }

    #[test]
    fn registers_native_builtin_surface_with_prefixed_tool_names() {
        let registry = ModuleRegistry::with_v2_builtins();

        for expected in [
            "agentic-sast",
            "auto-hunt",
            "binary-analysis",
            "carlini-threat-hunt",
            "chrome-rce",
            "codeql",
            "context",
            "dep-hygiene",
            "findings",
            "iac-scan",
            "ndiff",
            "patch",
            "prompt-armor",
            "randori",
            "recon",
            "sast",
            "secret-scan",
            "semgrep",
            "shinsa",
            "taint-iris",
            "taint-iris-next",
            "threat-model",
            "tob",
            "triage",
            "variant",
            "vendor-assessment",
            "verify",
            "vuln-scout",
            "workspace",
            "x-ray",
        ] {
            assert!(
                registry
                    .modules()
                    .any(|module| module.metadata().id == expected),
                "expected visible module {expected}"
            );
        }

        for expected in ["context-lite", "pipeline", "systems-hunt"] {
            assert!(
                registry
                    .all_modules()
                    .any(|module| module.metadata().id == expected && module.is_hidden()),
                "expected hidden internal module {expected}"
            );
            assert!(
                !registry
                    .modules()
                    .any(|module| module.metadata().id == expected),
                "hidden module {expected} should not be user-visible"
            );
        }

        for tool in registry.tools() {
            let module_id = tool.name.split(':').next().unwrap();
            assert!(
                registry
                    .all_modules()
                    .any(|module| module.metadata().id == module_id),
                "tool {} should use a registered module prefix",
                tool.name
            );
        }

        let recon = registry
            .all_modules()
            .find(|module| module.metadata().id == "recon")
            .unwrap();
        assert!(recon
            .dag_nodes()
            .iter()
            .any(|node| node.id == "recon:http-fingerprint"
                && node.output_kind == "context"
                && node.depends_on == vec!["context:build".to_string()]));

        let auto_hunt = registry
            .all_modules()
            .find(|module| module.metadata().id == "auto-hunt")
            .unwrap();
        assert!(auto_hunt
            .dag_nodes()
            .iter()
            .any(|node| node.id == "auto-hunt:run"
                && node.output_kind == "findings"
                && node.depends_on == vec!["context:build".to_string()]));
    }

    #[test]
    fn resolves_representative_ported_tools() {
        let registry = ModuleRegistry::with_v2_builtins();
        for expected in [
            "context:build",
            "auto-hunt:run",
            "sast:scan",
            "x-ray:run",
            "carlini-threat-hunt:run",
            "threat-model:build",
            "variant:hunt",
            "ndiff:hunt-variants",
            "shinsa:nist-quick-check",
            "prompt-armor:attack",
            "recon:http-fingerprint",
            "iac-scan:scan",
            "dep-hygiene:check",
            "secret-scan:scan",
            "binary-analysis:scan",
            "semgrep:scan",
            "codeql:scan",
            "triage:run",
            "verify:finding",
            "patch:finding",
            "taint-iris-next:hunt",
        ] {
            assert!(
                registry.resolve_tool(expected).is_some(),
                "expected tool {expected}"
            );
        }
    }
}
