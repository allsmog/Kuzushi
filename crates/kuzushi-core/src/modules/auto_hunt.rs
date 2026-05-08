use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::config::V2Config;
use crate::findings::{Finding, FindingStore};
use crate::repository_inventory::{build_repository_inventory, RepositoryInventory};
use crate::runtime::{
    run_tool_loop, AgentLoopOutcome, AgentRuntime, AgentTool, AgentToolLoopRequest,
    LoopHistoryEntry, ToolCall, ToolCallHandler, ToolResult,
};
use crate::spend::{Operation, SpendLimiter};
use crate::workspace::WorkspaceTarget;

use super::generic_findings::normalize_agent_json_findings;
use super::{
    builtin_module, dag, model_option, opt, resolve_tool_model, resolve_tool_target, target_option,
    tool_with_options, BuiltinModule, ModuleKind, ModuleRegistry, OptionType, ToolExecutionContext,
};

const MODULE_ID: &str = "auto-hunt";
const TOOL_NAME: &str = "auto-hunt:run";
const DEFAULT_BUDGET_USD: f64 = 5.0;
const DEFAULT_MAX_STEPS: u32 = 12;
const MAX_READ_FILE_BYTES: u64 = 16 * 1024;
const MAX_EXTRACTED_FINDINGS_PER_TOOL: usize = 500;

const META_TOOLS: &[&str] = &["inspect_target", "list_modules", "read_file"];

const PRODUCER_TOOLS: &[&str] = &[
    "secret-scan:scan",
    "dep-hygiene:check",
    "iac-scan:scan",
    "semgrep:scan",
    "codeql:scan",
    "binary-analysis:scan",
    "agentic-sast:scan",
    "taint-iris-next:hunt",
    "carlini-threat-hunt:run",
    "chrome-rce:scan",
    "systems-hunt:systems-hunt",
];

const CONTEXT_TOOLS: &[&str] = &[
    "context:build",
    "threat-model:build",
    "x-ray:run",
    "recon:http-fingerprint",
];

const SYSTEM_PROMPT: &str = r#"You are Kuzushi auto-hunt.
Pick useful analysis tools for the target, invoke them in any order, and stop when further calls are unlikely to improve coverage.
You may re-invoke tools when new context warrants it.
Use inspect_target and read_file for orientation.
Use list_modules when you need the allowed tool catalog.
Do not call triage, verify, patch, findings:list, classifier-gate, deep-audit, full-mode, hidden tools, or any tool outside the provided toolbox.
Return a concise final summary; findings are collected from tool outputs by the host."#;

pub(crate) fn auto_hunt_module() -> BuiltinModule {
    builtin_module(
        MODULE_ID,
        "Auto Hunt",
        ModuleKind::Defense,
        "Let an LLM choose and run existing analysis modules, then aggregate findings.",
        vec![tool_with_options(
            TOOL_NAME,
            "Run an LLM-guided analysis sweep over a target codebase.",
            vec![
                target_option(),
                model_option(),
                opt(
                    "budgetUsd",
                    OptionType::Float,
                    "Maximum LLM spend for the auto-hunt run.",
                )
                .default(json!(DEFAULT_BUDGET_USD)),
                opt(
                    "maxSteps",
                    OptionType::Int,
                    "Maximum auto-hunt tool-loop steps.",
                )
                .default(json!(DEFAULT_MAX_STEPS)),
            ],
        )],
        vec![dag(TOOL_NAME, "findings", &["context:build"])],
    )
}

pub(crate) fn run_auto_hunt_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    registry: &ModuleRegistry,
) -> Result<Value> {
    Ok(run_auto_hunt_report(&input, ctx, runtime, registry)?.to_tool_json())
}

fn run_auto_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    registry: &ModuleRegistry,
) -> Result<AutoHuntReport> {
    let start = AutoHuntStart::new(input, ctx)?;
    finish_auto_hunt(start, input, ctx, runtime, registry)
}

fn finish_auto_hunt(
    start: AutoHuntStart,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    registry: &ModuleRegistry,
) -> Result<AutoHuntReport> {
    if start.options.budget_usd <= 0.0 {
        return Ok(AutoHuntReport::budget_exhausted(
            start.scan_run_id,
            start.fingerprint,
        ));
    }
    run_positive_budget_hunt(start, input, ctx, runtime, registry)
}

fn run_positive_budget_hunt(
    start: AutoHuntStart,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    registry: &ModuleRegistry,
) -> Result<AutoHuntReport> {
    let plan = AutoHuntRuntimePlan::from_input(input, ctx, runtime)?;
    run_positive_budget_plan(start, ctx, registry, plan)
}

fn run_positive_budget_plan(
    start: AutoHuntStart,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
    plan: AutoHuntRuntimePlan<'_>,
) -> Result<AutoHuntReport> {
    let loop_run = run_budgeted_loop(&start, ctx, plan.runtime, registry, &plan.model)?;
    complete_auto_hunt_report(start, ctx, loop_run)
}

fn require_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.context("auto-hunt:run requires a tool-capable agent runtime; none is configured")
}

fn run_budgeted_loop(
    start: &AutoHuntStart,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    registry: &ModuleRegistry,
    model: &str,
) -> Result<AutoHuntLoopRun> {
    let spend = AutoHuntSpend::reserve(start.options.budget_usd)?;
    let outcome = execute_loop(start, ctx, runtime, registry, model)?;
    settle_loop_spend(spend, outcome)
}

fn settle_loop_spend(spend: AutoHuntSpend, loop_run: AutoHuntLoopRun) -> Result<AutoHuntLoopRun> {
    spend.settle(loop_run.outcome.cost_usd)?;
    Ok(loop_run)
}

fn execute_loop(
    start: &AutoHuntStart,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    registry: &ModuleRegistry,
    model: &str,
) -> Result<AutoHuntLoopRun> {
    let request = build_loop_request(
        &start.options,
        model,
        &start.fingerprint,
        &start.inventory,
        registry,
    );
    let mut toolbox = AutoHuntToolbox::new(
        registry,
        ctx,
        runtime,
        &start.options,
        &start.inventory,
        &start.fingerprint,
        model,
    );
    let outcome = run_tool_loop(runtime, &request, &mut toolbox)?;
    Ok(AutoHuntLoopRun::from_toolbox(outcome, &mut toolbox))
}

fn complete_auto_hunt_report(
    start: AutoHuntStart,
    ctx: &ToolExecutionContext<'_>,
    loop_run: AutoHuntLoopRun,
) -> Result<AutoHuntReport> {
    let persisted = persist_aggregate(
        &start.scan_run_id,
        &start.options.target,
        &loop_run.findings,
        ctx,
    )?;
    let stopped_reason = stopped_reason(&loop_run.outcome, start.options.budget_usd);
    let cost_usd = loop_run.outcome.cost_usd;
    Ok(AutoHuntReport {
        scan_run_id: start.scan_run_id,
        fingerprint: start.fingerprint,
        modules_invoked: loop_run.modules_invoked,
        findings: persisted,
        errors: loop_run.errors,
        transcript: loop_run.outcome.transcript,
        stopped_reason,
        cost_usd,
    })
}

struct AutoHuntStart {
    options: AutoHuntOptions,
    inventory: RepositoryInventory,
    fingerprint: String,
    scan_run_id: String,
}

impl AutoHuntStart {
    fn new(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Self> {
        let options = AutoHuntOptions::from_input(input, ctx)?;
        Self::from_options(options)
    }

    fn from_options(options: AutoHuntOptions) -> Result<Self> {
        let inventory = build_repository_inventory(&options.target)?;
        let fingerprint = target_fingerprint(&inventory);
        Ok(Self {
            options,
            inventory,
            fingerprint,
            scan_run_id: format!("{MODULE_ID}-{}", Uuid::new_v4()),
        })
    }
}

struct AutoHuntRuntimePlan<'a> {
    runtime: &'a dyn AgentRuntime,
    model: String,
}

impl<'a> AutoHuntRuntimePlan<'a> {
    fn from_input(
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&'a dyn AgentRuntime>,
    ) -> Result<Self> {
        Ok(Self {
            runtime: require_runtime(runtime)?,
            model: resolve_tool_model(TOOL_NAME, input, ctx)?,
        })
    }
}

struct AutoHuntLoopRun {
    outcome: AgentLoopOutcome,
    modules_invoked: Vec<String>,
    findings: Vec<Finding>,
    errors: Vec<AutoHuntError>,
}

impl AutoHuntLoopRun {
    fn from_toolbox(outcome: AgentLoopOutcome, toolbox: &mut AutoHuntToolbox<'_, '_>) -> Self {
        Self {
            outcome,
            modules_invoked: std::mem::take(&mut toolbox.modules_invoked),
            findings: std::mem::take(&mut toolbox.findings),
            errors: std::mem::take(&mut toolbox.errors),
        }
    }
}

#[derive(Debug, Clone)]
struct AutoHuntOptions {
    target: PathBuf,
    budget_usd: f64,
    max_steps: u32,
}

impl AutoHuntOptions {
    fn from_input(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Self> {
        let target = resolve_tool_target(input, ctx)?;
        Self::from_target(target, input)
    }

    fn from_target(target: PathBuf, input: &Value) -> Result<Self> {
        Ok(Self {
            target,
            budget_usd: read_f64(input, "budgetUsd", DEFAULT_BUDGET_USD)?,
            max_steps: read_u32(input, "maxSteps", DEFAULT_MAX_STEPS)?.max(1),
        })
    }
}

struct AutoHuntSpend {
    limiter: SpendLimiter,
    ticket: crate::spend::SpendTicket,
}

impl AutoHuntSpend {
    fn reserve(budget_usd: f64) -> Result<Self> {
        let limiter = SpendLimiter::open_in_memory()?;
        Self::reserve_with_limiter(limiter, budget_usd)
    }

    fn reserve_with_limiter(limiter: SpendLimiter, budget_usd: f64) -> Result<Self> {
        limiter.set_cap(Operation::AutoHunt, budget_usd)?;
        let ticket = limiter.deposit(Operation::AutoHunt, budget_usd)?;
        Ok(Self { limiter, ticket })
    }

    fn settle(self, actual_usd: f64) -> Result<()> {
        self.limiter.refund(self.ticket, actual_usd)
    }
}

struct AutoHuntToolbox<'a, 'ctx> {
    registry: &'a ModuleRegistry,
    runtime: &'a dyn AgentRuntime,
    config: &'ctx V2Config,
    workspace: Option<&'ctx WorkspaceTarget>,
    target: &'a Path,
    inventory: &'a RepositoryInventory,
    fingerprint: &'a str,
    model: &'a str,
    modules_invoked: Vec<String>,
    findings: Vec<Finding>,
    errors: Vec<AutoHuntError>,
    seen_findings: BTreeSet<String>,
}

impl<'a, 'ctx> AutoHuntToolbox<'a, 'ctx> {
    fn new(
        registry: &'a ModuleRegistry,
        ctx: &ToolExecutionContext<'ctx>,
        runtime: &'a dyn AgentRuntime,
        options: &'a AutoHuntOptions,
        inventory: &'a RepositoryInventory,
        fingerprint: &'a str,
        model: &'a str,
    ) -> Self {
        Self {
            registry,
            runtime,
            config: ctx.config,
            workspace: ctx.workspace,
            target: &options.target,
            inventory,
            fingerprint,
            model,
            modules_invoked: Vec::new(),
            findings: Vec::new(),
            errors: Vec::new(),
            seen_findings: BTreeSet::new(),
        }
    }
}

impl ToolCallHandler for AutoHuntToolbox<'_, '_> {
    fn run(&mut self, call: &ToolCall) -> Result<ToolResult> {
        match self.run_call(call) {
            Ok(output) => Ok(ToolResult {
                call_id: call.call_id.clone(),
                output,
                is_error: false,
            }),
            Err(error) => Ok(self.error_result(call, error.to_string())),
        }
    }
}

impl AutoHuntToolbox<'_, '_> {
    fn run_call(&mut self, call: &ToolCall) -> Result<Value> {
        if let Some(handler) = meta_tool_handler(&call.name) {
            return handler(self, &call.input);
        }
        if allowed_module_tool(&call.name) {
            return self.invoke_module_tool(&call.name, &call.input);
        }
        anyhow::bail!("auto-hunt toolbox does not expose tool {:?}", call.name)
    }

    fn invoke_module_tool(&mut self, tool_name: &str, input: &Value) -> Result<Value> {
        let input = tool_input(input, self.target, self.model);
        let tool_ctx = ToolExecutionContext {
            config: self.config,
            workspace: self.workspace,
            findings_store: None,
        };
        let output = self.registry.execute_tool_with_runtime(
            tool_name,
            input,
            &tool_ctx,
            Some(self.runtime),
        )?;
        self.modules_invoked.push(tool_name.to_string());
        self.collect_findings(tool_name, &output)?;
        Ok(output)
    }

    fn collect_findings(&mut self, tool_name: &str, output: &Value) -> Result<()> {
        let findings = findings_from_output(tool_name, output, self.target)?;
        self.push_new_findings(findings);
        Ok(())
    }

    fn push_new_findings(&mut self, findings: Vec<Finding>) {
        for finding in findings {
            let key = finding_key(&finding);
            if self.seen_findings.insert(key) {
                self.findings.push(finding);
            }
        }
    }

    fn error_result(&mut self, call: &ToolCall, message: String) -> ToolResult {
        self.record_error(&call.name, message.clone());
        ToolResult {
            call_id: call.call_id.clone(),
            output: json!({ "error": message }),
            is_error: true,
        }
    }

    fn record_error(&mut self, tool: &str, message: String) {
        self.errors.push(AutoHuntError {
            tool: tool.to_string(),
            message,
        });
    }
}

type MetaToolHandler = for<'a, 'ctx> fn(&AutoHuntToolbox<'a, 'ctx>, &Value) -> Result<Value>;

const META_TOOL_HANDLERS: &[(&str, MetaToolHandler)] = &[
    ("inspect_target", inspect_target_tool),
    ("list_modules", list_modules_tool),
    ("read_file", read_file_meta_tool),
];

fn meta_tool_handler(name: &str) -> Option<MetaToolHandler> {
    META_TOOL_HANDLERS
        .iter()
        .find(|(tool_name, _)| *tool_name == name)
        .map(|(_, handler)| *handler)
}

fn inspect_target_tool(toolbox: &AutoHuntToolbox<'_, '_>, _input: &Value) -> Result<Value> {
    Ok(inspect_target(
        toolbox.target,
        toolbox.inventory,
        toolbox.fingerprint,
    ))
}

fn list_modules_tool(toolbox: &AutoHuntToolbox<'_, '_>, _input: &Value) -> Result<Value> {
    list_modules(toolbox.registry)
}

fn read_file_meta_tool(toolbox: &AutoHuntToolbox<'_, '_>, input: &Value) -> Result<Value> {
    read_file_tool(toolbox.target, input)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutoHuntReport {
    scan_run_id: String,
    fingerprint: String,
    modules_invoked: Vec<String>,
    findings: Vec<Finding>,
    errors: Vec<AutoHuntError>,
    transcript: Vec<LoopHistoryEntry>,
    stopped_reason: String,
    cost_usd: f64,
}

impl AutoHuntReport {
    fn budget_exhausted(scan_run_id: String, fingerprint: String) -> Self {
        Self {
            scan_run_id,
            fingerprint,
            modules_invoked: Vec::new(),
            findings: Vec::new(),
            errors: Vec::new(),
            transcript: Vec::new(),
            stopped_reason: "budget_exhausted".to_string(),
            cost_usd: 0.0,
        }
    }

    fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
            "costUsd": self.cost_usd,
        })
    }

    fn output(&self) -> String {
        format!(
            "auto-hunt: {} finding{} from {} module call{} ({})",
            self.findings.len(),
            if self.findings.len() == 1 { "" } else { "s" },
            self.modules_invoked.len(),
            if self.modules_invoked.len() == 1 {
                ""
            } else {
                "s"
            },
            self.stopped_reason
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AutoHuntError {
    tool: String,
    message: String,
}

fn build_loop_request(
    options: &AutoHuntOptions,
    model: &str,
    fingerprint: &str,
    inventory: &RepositoryInventory,
    registry: &ModuleRegistry,
) -> AgentToolLoopRequest {
    AgentToolLoopRequest {
        model: model.to_string(),
        cwd: options.target.clone(),
        system_prompt: SYSTEM_PROMPT.to_string(),
        prompt: build_prompt(options, fingerprint, inventory),
        tools: agent_tools(registry),
        max_steps: options.max_steps,
    }
}

fn build_prompt(
    options: &AutoHuntOptions,
    fingerprint: &str,
    inventory: &RepositoryInventory,
) -> String {
    format!(
        "Target: {}\nFingerprint: {}\nBudget USD: {:.2}\nMax steps: {}\nInventory summary:\n{}",
        options.target.display(),
        fingerprint,
        options.budget_usd,
        options.max_steps,
        serde_json::to_string_pretty(&inventory_summary(inventory)).unwrap_or_default()
    )
}

fn agent_tools(registry: &ModuleRegistry) -> Vec<AgentTool> {
    let mut tools = vec![
        meta_tool(
            "inspect_target",
            "Return target inventory and fingerprint.",
            json!({}),
        ),
        meta_tool("list_modules", "List allowed auto-hunt modules.", json!({})),
        meta_tool(
            "read_file",
            "Read a target-relative text file, capped at 16 KiB.",
            json!({
                "path": { "type": "string" },
                "maxBytes": { "type": "integer", "minimum": 1, "maximum": MAX_READ_FILE_BYTES }
            }),
        ),
    ];
    tools.extend(module_agent_tools(registry));
    tools
}

fn module_agent_tools(registry: &ModuleRegistry) -> Vec<AgentTool> {
    allowed_module_tools()
        .iter()
        .map(|name| {
            let description = registry
                .resolve_tool(name)
                .map(|tool| tool.description.clone())
                .unwrap_or_else(|| format!("Run {name}."));
            AgentTool {
                name: (*name).to_string(),
                description,
                input_schema: json!({ "type": "object", "additionalProperties": true }),
            }
        })
        .collect()
}

fn meta_tool(name: &str, description: &str, properties: Value) -> AgentTool {
    AgentTool {
        name: name.to_string(),
        description: description.to_string(),
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "additionalProperties": false
        }),
    }
}

fn allowed_module_tools() -> Vec<&'static str> {
    PRODUCER_TOOLS
        .iter()
        .chain(CONTEXT_TOOLS.iter())
        .copied()
        .collect()
}

fn allowed_module_tool(name: &str) -> bool {
    PRODUCER_TOOLS.contains(&name) || CONTEXT_TOOLS.contains(&name)
}

fn tool_input(input: &Value, target: &Path, model: &str) -> Value {
    let mut object = input.as_object().cloned().unwrap_or_default();
    object
        .entry("target".to_string())
        .or_insert_with(|| json!(target.display().to_string()));
    if !model.is_empty() {
        object
            .entry("model".to_string())
            .or_insert_with(|| json!(model));
    }
    Value::Object(object)
}

fn inspect_target(target: &Path, inventory: &RepositoryInventory, fingerprint: &str) -> Value {
    json!({
        "target": target.display().to_string(),
        "fingerprint": fingerprint,
        "inventory": inventory_summary(inventory),
    })
}

fn inventory_summary(inventory: &RepositoryInventory) -> Value {
    json!({
        "rootName": inventory.root_name,
        "languages": inventory.languages,
        "frameworks": inventory.frameworks,
        "manifests": inventory.manifests,
        "dependencyManifests": inventory.dependency_manifests,
        "configFiles": inventory.config_files,
        "entrypoints": inventory.entrypoints,
        "routesControllers": inventory.routes_controllers.iter().take(50).collect::<Vec<_>>(),
        "sourceFileCount": inventory.source_files.len(),
        "sourceFiles": inventory.source_files.iter().take(100).collect::<Vec<_>>(),
    })
}

fn list_modules(registry: &ModuleRegistry) -> Result<Value> {
    let catalog = registry
        .dispatch_catalog_tool("catalog:tools")
        .context("catalog:tools dispatcher missing")??;
    let tools = catalog.as_array().cloned().unwrap_or_default();
    Ok(json!({
        "meta": META_TOOLS,
        "producers": catalog_tools(&tools, PRODUCER_TOOLS),
        "context": catalog_tools(&tools, CONTEXT_TOOLS),
    }))
}

fn catalog_tools(catalog: &[Value], allowed: &[&str]) -> Vec<Value> {
    allowed
        .iter()
        .map(|name| {
            catalog
                .iter()
                .find(|tool| tool.get("name").and_then(Value::as_str) == Some(*name))
                .cloned()
                .unwrap_or_else(|| json!({ "name": name }))
        })
        .collect()
}

fn read_file_tool(target: &Path, input: &Value) -> Result<Value> {
    let request = ReadFileRequest::from_input(input)?;
    read_file_request(target, &request)
}

struct ReadFileRequest {
    path: String,
    max_bytes: u64,
}

impl ReadFileRequest {
    fn from_input(input: &Value) -> Result<Self> {
        Ok(Self {
            path: read_file_path(input)?.to_string(),
            max_bytes: read_file_max_bytes(input),
        })
    }
}

fn read_file_path(input: &Value) -> Result<&str> {
    input
        .get("path")
        .and_then(Value::as_str)
        .context("read_file requires path")
}

fn read_file_max_bytes(input: &Value) -> u64 {
    input
        .get("maxBytes")
        .and_then(Value::as_u64)
        .unwrap_or(MAX_READ_FILE_BYTES)
        .min(MAX_READ_FILE_BYTES)
}

fn read_file_request(target: &Path, request: &ReadFileRequest) -> Result<Value> {
    let path = resolve_read_path(target, &request.path)?;
    let bytes = read_file_prefix(&path, request.max_bytes)?;
    Ok(json!({
        "path": request.path,
        "bytes": bytes.len(),
        "maxBytes": request.max_bytes,
        "truncated": fs::metadata(&path).map(|m| m.len() > bytes.len() as u64).unwrap_or(false),
        "content": String::from_utf8_lossy(&bytes),
    }))
}

fn resolve_read_path(target: &Path, requested: &str) -> Result<PathBuf> {
    reject_unsafe_relative_path(requested)?;
    resolve_checked_read_path(target, requested)
}

fn resolve_checked_read_path(target: &Path, requested: &str) -> Result<PathBuf> {
    let root = canonicalize_target(target)?;
    let path = canonicalize_requested_path(&root, requested)?;
    ensure_path_inside_target(&root, path, requested)
}

fn canonicalize_target(target: &Path) -> Result<PathBuf> {
    target
        .canonicalize()
        .with_context(|| format!("could not canonicalize target {}", target.display()))
}

fn canonicalize_requested_path(root: &Path, requested: &str) -> Result<PathBuf> {
    root.join(requested)
        .canonicalize()
        .with_context(|| format!("could not read target-relative file {requested:?}"))
}

fn ensure_path_inside_target(root: &Path, path: PathBuf, requested: &str) -> Result<PathBuf> {
    if !path.starts_with(root) {
        anyhow::bail!("read_file path escapes target: {requested:?}");
    }
    Ok(path)
}

fn reject_unsafe_relative_path(requested: &str) -> Result<()> {
    let path = Path::new(requested);
    anyhow::ensure!(
        !path.is_absolute(),
        "read_file path must be target-relative"
    );
    anyhow::ensure!(
        path.components().all(safe_read_component),
        "read_file path must not escape target"
    );
    Ok(())
}

fn safe_read_component(component: Component<'_>) -> bool {
    matches!(component, Component::Normal(_) | Component::CurDir)
}

fn read_file_prefix(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file =
        fs::File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut reader = file.take(max_bytes);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn findings_from_output(tool_name: &str, output: &Value, target: &Path) -> Result<Vec<Finding>> {
    let Some(raw_findings) = output_findings(output) else {
        return Ok(Vec::new());
    };
    let tool_slug = tool_name.split(':').next().unwrap_or(tool_name);
    normalize_agent_json_findings(
        json!({ "findings": raw_findings }),
        target,
        tool_slug,
        MAX_EXTRACTED_FINDINGS_PER_TOOL,
    )
}

fn output_findings(output: &Value) -> Option<Value> {
    output
        .pointer("/data/findings")
        .or_else(|| output.get("findings"))
        .cloned()
}

fn finding_key(finding: &Finding) -> String {
    format!(
        "{}|{}|{}|{}",
        finding.fingerprint, finding.rule_id, finding.file_path, finding.start_line
    )
}

fn persist_aggregate(
    scan_run_id: &str,
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Vec<Finding>> {
    if let Some(store) = ctx.findings_store {
        return persist_with_store(scan_run_id, target, findings, store);
    }
    persist_workspace_or_memory(scan_run_id, target, findings, ctx)
}

fn persist_workspace_or_memory(
    scan_run_id: &str,
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Vec<Finding>> {
    let Some(workspace) = ctx.workspace else {
        return Ok(findings.to_vec());
    };
    persist_owned_store(scan_run_id, target, findings, workspace)
}

fn persist_owned_store(
    scan_run_id: &str,
    target: &Path,
    findings: &[Finding],
    workspace: &WorkspaceTarget,
) -> Result<Vec<Finding>> {
    workspace.ensure_state_dir()?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    persist_with_store(scan_run_id, target, findings, &store)
}

fn persist_with_store(
    scan_run_id: &str,
    target: &Path,
    findings: &[Finding],
    store: &FindingStore,
) -> Result<Vec<Finding>> {
    start_scan_run(scan_run_id, target, store)?;
    insert_aggregate_findings(scan_run_id, findings, store)?;
    complete_scan_and_list(scan_run_id, findings.len(), store)
}

fn start_scan_run(scan_run_id: &str, target: &Path, store: &FindingStore) -> Result<()> {
    store.insert_scan_run(scan_run_id, target, "running")
}

fn insert_aggregate_findings(
    scan_run_id: &str,
    findings: &[Finding],
    store: &FindingStore,
) -> Result<()> {
    findings
        .iter()
        .try_for_each(|finding| store.insert_finding(scan_run_id, finding).map(|_| ()))
}

fn complete_scan_and_list(
    scan_run_id: &str,
    findings_count: usize,
    store: &FindingStore,
) -> Result<Vec<Finding>> {
    store.complete_scan_run(scan_run_id, "completed", findings_count)?;
    store.list_findings_for_scan_id(scan_run_id)
}

fn target_fingerprint(inventory: &RepositoryInventory) -> String {
    let payload = serde_json::to_string(inventory).unwrap_or_default();
    format!("{:016x}", fnv1a64(payload.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn stopped_reason(outcome: &AgentLoopOutcome, budget_usd: f64) -> String {
    if outcome.cost_usd >= budget_usd {
        "budget_exhausted"
    } else if outcome.truncated {
        "max_steps"
    } else {
        "completed"
    }
    .to_string()
}

fn read_f64(input: &Value, key: &str, default: f64) -> Result<f64> {
    input
        .get(key)
        .map_or(Ok(default), |value| parse_f64_value(key, value))
}

fn parse_f64_value(key: &str, value: &Value) -> Result<f64> {
    if let Some(number) = value.as_f64() {
        return finite_f64(number);
    }
    parse_f64_string_value(key, value)
}

fn finite_f64(value: f64) -> Result<f64> {
    value
        .is_finite()
        .then_some(value)
        .context("must be a finite number")
}

fn parse_f64_string_value(key: &str, value: &Value) -> Result<f64> {
    let Some(value) = value.as_str() else {
        return invalid_number(key, value);
    };
    parse_f64_string(key, value)
}

fn parse_f64_string(key: &str, value: &str) -> Result<f64> {
    value
        .parse::<f64>()
        .with_context(|| format!("{key} must be a number"))
}

fn read_u32(input: &Value, key: &str, default: u32) -> Result<u32> {
    input
        .get(key)
        .map_or(Ok(default), |value| parse_u32_value(key, value))
}

fn parse_u32_value(key: &str, value: &Value) -> Result<u32> {
    if let Some(number) = value.as_u64().and_then(|value| u32::try_from(value).ok()) {
        return Ok(number);
    }
    parse_u32_string_value(key, value)
}

fn parse_u32_string_value(key: &str, value: &Value) -> Result<u32> {
    let Some(value) = value.as_str() else {
        return invalid_number(key, value);
    };
    parse_u32_string(key, value)
}

fn parse_u32_string(key: &str, value: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .with_context(|| format!("{key} must be a non-negative integer"))
}

fn invalid_number<T>(key: &str, _value: &Value) -> Result<T> {
    anyhow::bail!("{key} must be a number")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::TriageOutcome;
    use crate::runtime::{AgentLoopStep, TriageRequest};
    use crate::workspace::WorkspaceTarget;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct ScriptedRuntime {
        steps: Mutex<Vec<AgentLoopStep>>,
        seen_history: Mutex<Vec<usize>>,
    }

    impl ScriptedRuntime {
        fn new(steps: Vec<AgentLoopStep>) -> Self {
            Self {
                steps: Mutex::new(steps),
                seen_history: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> usize {
            self.seen_history.lock().unwrap().len()
        }
    }

    impl AgentRuntime for ScriptedRuntime {
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("auto-hunt tests do not triage findings")
        }

        fn supports_tools(&self) -> bool {
            true
        }

        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            self.seen_history.lock().unwrap().push(history.len());
            let mut steps = self.steps.lock().unwrap();
            anyhow::ensure!(!steps.is_empty(), "scripted runtime exhausted");
            Ok(steps.remove(0))
        }
    }

    fn context_with_model<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
        store: &'a FindingStore,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: Some(store),
        }
    }

    fn config_with_model() -> V2Config {
        V2Config {
            model: Some("test:model".to_string()),
            ..V2Config::default()
        }
    }

    fn write_secret_fixture(root: &Path) {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/config.env"),
            "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n",
        )
        .unwrap();
    }

    fn final_step() -> AgentLoopStep {
        AgentLoopStep::Final {
            text: "done".to_string(),
            structured: None,
            cost_usd: Some(0.01),
        }
    }

    fn tool_call(name: &str, input: Value) -> AgentLoopStep {
        AgentLoopStep::ToolCall {
            call: ToolCall {
                name: name.to_string(),
                input,
                call_id: format!("call-{name}"),
            },
        }
    }

    #[test]
    fn invokes_one_module_and_persists_aggregate_findings() {
        let temp = tempdir().unwrap();
        write_secret_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = config_with_model();
        let ctx = context_with_model(&config, &workspace, &store);
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime =
            ScriptedRuntime::new(vec![tool_call("secret-scan:scan", json!({})), final_step()]);

        let report = run_auto_hunt_report(
            &json!({"target": temp.path().display().to_string()}),
            &ctx,
            Some(&runtime),
            &registry,
        )
        .unwrap();

        assert_eq!(report.modules_invoked, vec!["secret-scan:scan"]);
        assert!(!report.findings.is_empty());
        assert_eq!(report.stopped_reason, "completed");
        let stored = store
            .list_findings_for_scan_id(&report.scan_run_id)
            .unwrap();
        assert_eq!(stored.len(), report.findings.len());
    }

    #[test]
    fn agent_can_choose_no_modules() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = config_with_model();
        let ctx = context_with_model(&config, &workspace, &store);
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime = ScriptedRuntime::new(vec![final_step()]);

        let report = run_auto_hunt_report(
            &json!({"target": temp.path().display().to_string()}),
            &ctx,
            Some(&runtime),
            &registry,
        )
        .unwrap();

        assert!(report.modules_invoked.is_empty());
        assert!(report.findings.is_empty());
        assert_eq!(report.stopped_reason, "completed");
    }

    #[test]
    fn inspect_target_returns_fingerprint() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = config_with_model();
        let ctx = context_with_model(&config, &workspace, &store);
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime =
            ScriptedRuntime::new(vec![tool_call("inspect_target", json!({})), final_step()]);

        let report = run_auto_hunt_report(
            &json!({"target": temp.path().display().to_string()}),
            &ctx,
            Some(&runtime),
            &registry,
        )
        .unwrap();

        let LoopHistoryEntry::ToolResult(result) = &report.transcript[1] else {
            panic!("expected inspect_target tool result");
        };
        assert_eq!(result.output["fingerprint"], json!(report.fingerprint));
        assert!(!report.fingerprint.is_empty());
    }

    #[test]
    fn unknown_module_returns_tool_error_without_panicking() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = config_with_model();
        let ctx = context_with_model(&config, &workspace, &store);
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime =
            ScriptedRuntime::new(vec![tool_call("unknown:scan", json!({})), final_step()]);

        let report = run_auto_hunt_report(
            &json!({"target": temp.path().display().to_string()}),
            &ctx,
            Some(&runtime),
            &registry,
        )
        .unwrap();

        assert_eq!(report.errors.len(), 1);
        let LoopHistoryEntry::ToolResult(result) = &report.transcript[1] else {
            panic!("expected unknown tool result");
        };
        assert!(result.is_error);
    }

    #[test]
    fn zero_budget_short_circuits_before_runtime_call() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = context_with_model(&config, &workspace, &store);
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime = ScriptedRuntime::new(vec![final_step()]);

        let report = run_auto_hunt_report(
            &json!({"target": temp.path().display().to_string(), "budgetUsd": 0.0}),
            &ctx,
            Some(&runtime),
            &registry,
        )
        .unwrap();

        assert_eq!(report.stopped_reason, "budget_exhausted");
        assert_eq!(runtime.calls(), 0);
    }

    #[test]
    fn missing_model_is_an_error() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = context_with_model(&config, &workspace, &store);
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime = ScriptedRuntime::new(vec![final_step()]);

        let error = run_auto_hunt_report(
            &json!({"target": temp.path().display().to_string()}),
            &ctx,
            Some(&runtime),
            &registry,
        )
        .unwrap_err();

        assert!(error.to_string().contains("requires an explicit model"));
    }

    #[test]
    fn read_file_rejects_path_traversal() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("safe.txt"), "safe\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = config_with_model();
        let ctx = context_with_model(&config, &workspace, &store);
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime = ScriptedRuntime::new(vec![
            tool_call("read_file", json!({"path": "../Cargo.toml"})),
            final_step(),
        ]);

        let report = run_auto_hunt_report(
            &json!({"target": temp.path().display().to_string()}),
            &ctx,
            Some(&runtime),
            &registry,
        )
        .unwrap();

        assert_eq!(report.errors.len(), 1);
        let LoopHistoryEntry::ToolResult(result) = &report.transcript[1] else {
            panic!("expected read_file tool result");
        };
        assert!(result.is_error);
    }
}
