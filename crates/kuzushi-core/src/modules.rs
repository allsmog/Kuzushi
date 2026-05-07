use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::artifact_kb::{artifact_knowledge_prompt_context, ArtifactKnowledgePromptContext};
use crate::carlini_threat_hunt::{run_carlini_threat_hunt, run_carlini_threat_hunt_report};
use crate::config::V2Config;
use crate::dep_hygiene::check_dependency_hygiene;
use crate::diff_scope::build_whitebox_diff_scope_report;
use crate::findings::{
    Finding, FindingListFilter, FindingStore, Severity, StaticProofState, TriageOutcome,
    TriageVerdict,
};
use crate::iac_scan::{scan_iac, IacScanOptions};
use crate::options::ToolOptionStore;
use crate::patch::run_patch_finding;
use crate::recon::execute_recon_tool;
use crate::runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, ModelTier, TriageRequest,
};
use crate::scan::{
    index_codeql_sarif_as_static_evidence, run_scan_engines_with_options, scan_engines_for_tasks,
    CodeqlPersistedRun, CodeqlScanReport, CodeqlScanner, ScanCancellation, ScanRunOptions,
    SemgrepPersistedRun, SemgrepScanReport, SemgrepScanner,
};
use crate::secret_scan::{scan_for_secrets, SecretScanOptions};
use crate::semgrep_rule_synthesis::synthesize_candidate_semgrep_rules;
use crate::static_evidence::StaticEvidenceStore;
use crate::static_narrative::build_static_narrative_report;
use crate::static_proof_validator::{
    static_proof_claim_from_whitebox_schema, validate_static_proof_claim, StaticProofValidation,
};
use crate::static_ranking::{rank_static_findings, StaticRankedFinding};
use crate::systems_hunt::{execute_systems_hunt_tool, run_systems_hunt_report};
use crate::threat_model::execute_threat_model_tool;
use crate::variant_ndiff::{
    hunt_whitebox_static_variants, run_ndiff_extract_fix_pattern, run_ndiff_fetch_cve,
    run_ndiff_hunt_variants, run_variant_hunt, run_variant_lift_pattern,
};
use crate::whitebox_static::{
    agent_tool_policy_for_input, apply_whitebox_static_sast_policy, mark_whitebox_static_findings,
    whitebox_static_profile_requested, whitebox_static_proof_state_from_input,
    whitebox_static_triage_prompt_block, whitebox_static_triage_system_prompt,
};
use crate::whitebox_suppressions::{evaluate_whitebox_suppressions, load_whitebox_suppressions};
use crate::workspace::{export_workspace_findings, WorkspaceExportFormat, WorkspaceTarget};
use crate::x_ray::execute_x_ray_tool;
use uuid::Uuid;

mod context;
mod options;

use options::{json_summary, validate_tool_input_options};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleMetadata {
    pub id: String,
    pub name: String,
    pub kind: ModuleKind,
    pub description: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleKind {
    Offense,
    Intel,
    Governance,
    Defense,
    Internal,
    Catalog,
    Config,
    Context,
    Scan,
    Findings,
    Triage,
    Workspace,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    pub headless: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<OptionSpec>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OptionType {
    String,
    Bool,
    Int,
    Float,
    Path,
    Enum,
    StringList,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OptionSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub option_type: OptionType,
    pub description: String,
    pub required: bool,
    pub advanced: bool,
    pub evasion: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
}

impl OptionSpec {
    fn new(name: &str, option_type: OptionType, description: &str) -> Self {
        Self {
            name: name.to_string(),
            option_type,
            description: description.to_string(),
            required: false,
            advanced: false,
            evasion: false,
            default: None,
            choices: Vec::new(),
        }
    }

    fn required(mut self) -> Self {
        self.required = true;
        self
    }

    fn advanced(mut self) -> Self {
        self.advanced = true;
        self
    }

    fn evasion(mut self) -> Self {
        self.evasion = true;
        self
    }

    fn default(mut self, value: Value) -> Self {
        self.default = Some(value);
        self
    }

    fn choices(mut self, choices: &[&str]) -> Self {
        self.choices = choices.iter().map(|choice| (*choice).to_string()).collect();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DagNodeDescriptor {
    pub id: String,
    pub output_kind: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BuiltinModule {
    metadata: ModuleMetadata,
    tools: Vec<ToolDescriptor>,
    dag_nodes: Vec<DagNodeDescriptor>,
    hidden: bool,
}

impl BuiltinModule {
    pub fn metadata(&self) -> &ModuleMetadata {
        &self.metadata
    }

    pub fn tools(&self) -> &[ToolDescriptor] {
        &self.tools
    }

    pub fn dag_nodes(&self) -> &[DagNodeDescriptor] {
        &self.dag_nodes
    }

    pub fn is_hidden(&self) -> bool {
        self.hidden
    }
}

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
        registry.register(semgrep_module());
        registry.register(codeql_module());
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
        registry.register(vendor_assessment_module());
        registry.register(chrome_rce_module());
        registry.register(dep_hygiene_module());
        registry.register(secret_scan_module());
        registry.register(pipeline_module());
        registry.register(variant_module());
        registry.register(ndiff_module());
        registry.register(randori_module());
        registry.register(vuln_scout_module());
        registry.register(tob_module());
        registry.register(shinsa_module());
        registry.register(prompt_armor_module());
        registry.register(recon_module());
        registry.register(iac_scan_module());

        registry
    }

    pub fn register(&mut self, module: BuiltinModule) {
        for tool in module.tools() {
            self.tools.insert(tool.name.clone(), tool.clone());
        }
        self.modules.insert(module.metadata.id.clone(), module);
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
        match name {
            "catalog:modules" => Ok(json!(self
                .modules()
                .map(|module| module.metadata())
                .collect::<Vec<_>>())),
            "catalog:tools" => Ok(json!(self.tools().collect::<Vec<_>>())),
            "context:build" => context::build_context_snapshot(input, ctx),
            "context-lite:index" => context::build_context_snapshot(input, ctx),
            "dep-hygiene:check" => {
                let target = resolve_tool_target(&input, ctx)?;
                let report = check_dependency_hygiene(&target)?;
                Ok(report.to_tool_json())
            }
            "secret-scan:scan" => {
                let target = resolve_tool_target(&input, ctx)?;
                let options = SecretScanOptions::from_tool_input(&input)?;
                let report = scan_for_secrets(&target, &options, &ScanCancellation::default())?;
                Ok(report.to_tool_json())
            }
            "semgrep:scan" => {
                let target = resolve_tool_target(&input, ctx)?;
                let scanner = SemgrepScanner::from_tool_input(&input)?;
                let mut findings =
                    scanner.scan_with_cancel(&target, &ScanCancellation::default())?;
                let index_static_evidence = whitebox_static_profile_requested(&input)?;
                if index_static_evidence {
                    mark_whitebox_static_findings(&mut findings, StaticProofState::SignalOnly)?;
                }
                let persisted =
                    persist_semgrep_findings(&target, &findings, ctx, index_static_evidence)?;
                Ok(
                    SemgrepScanReport::new(target.display().to_string(), findings, persisted)
                        .to_tool_json(),
                )
            }
            "codeql:scan" => {
                let target = resolve_tool_target(&input, ctx)?;
                let scanner = CodeqlScanner::from_tool_input(&input)?;
                let mut output =
                    scanner.scan_with_artifacts(&target, &ScanCancellation::default())?;
                let index_static_evidence = whitebox_static_profile_requested(&input)?;
                if index_static_evidence {
                    mark_whitebox_static_findings(
                        &mut output.findings,
                        StaticProofState::SignalOnly,
                    )?;
                }
                let persisted = persist_codeql_findings(
                    &target,
                    &output.findings,
                    ctx,
                    &output.codeql_sarif_documents,
                    index_static_evidence,
                )?;
                Ok(
                    CodeqlScanReport::new(target.display().to_string(), output.findings, persisted)
                        .to_tool_json(),
                )
            }
            "iac-scan:scan" => {
                let target = resolve_tool_target(&input, ctx)?;
                let options = IacScanOptions::from_tool_input(&input)?;
                let report = scan_iac(&target, &options, &ScanCancellation::default())?;
                let findings = report
                    .findings
                    .iter()
                    .map(|finding| finding.to_core_finding())
                    .collect::<Vec<_>>();
                let persisted = persist_iac_findings(&target, &findings, ctx)?;
                let mut output = report.to_tool_json();
                if let Some(persisted) = persisted {
                    output["data"]["persisted"] = json!(persisted);
                }
                Ok(output)
            }
            "findings:list" => {
                let filter = FindingListFilter::from_tool_input(&input)?;
                let store = ctx
                    .findings_store
                    .context("findings:list requires a findings store")?;
                Ok(store.list_findings_filtered(&filter)?.to_tool_json())
            }
            "agentic-sast:scan" => {
                Ok(run_agentic_sast_report(&input, ctx, runtime)?.to_tool_json())
            }
            "variant:lift-pattern" => run_variant_lift_pattern(input, ctx, runtime),
            "variant:hunt" => run_variant_hunt(input, ctx, runtime),
            "ndiff:fetch-cve" => run_ndiff_fetch_cve(input),
            "ndiff:extract-fix-pattern" => run_ndiff_extract_fix_pattern(input, ctx, runtime),
            "ndiff:hunt-variants" => run_ndiff_hunt_variants(input, ctx, runtime),
            "carlini-threat-hunt:run" => run_carlini_threat_hunt(input, ctx, runtime),
            "pipeline:taint-cwe-select" => run_taint_cwe_select(input, ctx, runtime),
            "taint-iris:hunt" => Ok(run_taint_iris_report(&input, ctx, runtime)?.to_tool_json()),
            "taint-iris-next:hunt" => {
                Ok(run_taint_iris_next_report(&input, ctx, runtime)?.to_tool_json())
            }
            "systems-hunt:systems-context-gatherer"
            | "systems-hunt:systems-invariant-extract"
            | "systems-hunt:systems-trigger-synth"
            | "systems-hunt:systems-hunt"
            | "systems-hunt:deep-semantic-cwe-select"
            | "systems-hunt:deep-semantic-hunt" => {
                execute_systems_hunt_tool(name, input, ctx, runtime)
            }
            "config:show" => Ok(json!(ctx.config)),
            "router:show" => router_show_tool(input, ctx),
            "full-mode:hunt" => run_full_mode_hunt_tool(input, ctx, runtime),
            "classifier-gate:score" => run_classifier_score_tool(input, ctx, runtime),
            "deep-audit:run" => run_deep_audit_tool(input, ctx, runtime),
            "smoke:next-step" => run_smoke_next_step_tool(input, ctx, runtime),
            "workspace:status" => Ok(json!({
                "ok": ctx.workspace.is_some(),
                "output": workspace_status_output(ctx),
                "root": ctx.workspace.map(|workspace| workspace.root().display().to_string()),
                "stateDir": ctx.workspace.map(|workspace| workspace.state_dir().display().to_string()),
                "findingsDb": ctx.workspace.map(|workspace| workspace.findings_db_path().display().to_string()),
                "runtime": ctx.config.runtime.kind,
                "model": ctx.config.model,
            })),
            "workspace:export-findings" => export_workspace_findings_tool(input, ctx),
            "sast:scan" => run_sast_scan(input, ctx, runtime),
            "triage:run" => run_triage(input, ctx, runtime),
            "verify:finding" => run_verify_finding(input, ctx, runtime),
            "verify:exploit" => run_verify_exploit(input, ctx),
            "patch:finding" => run_patch_finding(input, ctx, runtime),
            "threat-model:build"
            | "threat-model:read"
            | "threat-model:methodologies"
            | "randori:pasta"
            | "randori:threat-model" => execute_threat_model_tool(name, input, ctx, runtime),
            "x-ray:run" | "x-ray:read" | "x-ray:x-ray" => {
                execute_x_ray_tool(name, input, ctx, runtime)
            }
            "recon:nmap" | "recon:subdomain" | "recon:http-fingerprint" => {
                execute_recon_tool(name, input, ctx)
            }
            "vendor-assessment:attach"
            | "vendor-assessment:scope"
            | "vendor-assessment:prompts"
            | "vendor-assessment:assess" => {
                execute_vendor_assessment_tool(name, input, ctx, runtime)
            }
            "chrome-rce:scan" => run_chrome_rce_scan(input, ctx),
            "chrome-rce:review-trigger" => run_chrome_rce_review_trigger(input, ctx),
            "vuln-scout:audit" => run_vuln_scout_audit(input, ctx, runtime),
            "tob:audit" => run_tob_audit(input, ctx, runtime),
            "tob:skills" => list_tob_skills(input),
            "shinsa:scan"
            | "shinsa:quick-check"
            | "shinsa:nist-scan"
            | "shinsa:nist-quick-check" => run_shinsa_assessment(name, input, ctx, runtime),
            "shinsa:frameworks" => list_shinsa_frameworks(input),
            "prompt-armor:scan"
            | "prompt-armor:analyze"
            | "prompt-armor:attack"
            | "prompt-armor:diff"
            | "prompt-armor:report"
            | "prompt-armor:config" => execute_prompt_armor_tool(name, input, ctx, runtime),
            "pipeline:task-selector" => run_pipeline_task_selector(input, ctx),
            "pipeline:approval-before-verification" => run_pipeline_approval_gate(input),
            other => {
                anyhow::bail!("registered tool or DAG node {other:?} has no Rust executor mapping")
            }
        }
    }

    fn is_registered_dag_node(&self, name: &str) -> bool {
        self.all_modules()
            .flat_map(BuiltinModule::dag_nodes)
            .any(|node| node.id == name)
    }
}

fn workspace_status_output(ctx: &ToolExecutionContext<'_>) -> String {
    match ctx.workspace {
        Some(workspace) => format!(
            "workspace status\n  Root:      {}\n  State:     {}\n  Findings:  {}",
            workspace.root().display(),
            workspace.state_dir().display(),
            workspace.findings_db_path().display()
        ),
        None => "workspace status unavailable: no active workspace. Next: pass --target <repo> or start the shell with --target .".to_string(),
    }
}

fn export_workspace_findings_tool(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("workspace:export-findings requires an active workspace target")?;
    let output = string_input_any(&input, &["output", "path"])
        .context("workspace:export-findings requires output=<path>. Next: run workspace:export-findings {\"output\":\"findings.json\"}")?;
    let output_path = resolve_input_path(workspace.root(), &output);
    let format = string_input_any(&input, &["format"])
        .map(|value| WorkspaceExportFormat::from_input(&value))
        .transpose()?;
    let report = export_workspace_findings(workspace, &output_path, format)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "workspace:export-findings wrote {} finding(s) to {} ({})",
            report.count,
            report.output_path.display(),
            report.format.as_str()
        ),
        "data": {
            "outputPath": report.output_path.display().to_string(),
            "format": report.format,
            "count": report.count,
        }
    }))
}

fn persist_semgrep_findings(
    target: &Path,
    findings: &[crate::findings::Finding],
    ctx: &ToolExecutionContext<'_>,
    index_static_evidence: bool,
) -> Result<Option<SemgrepPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };

    workspace.ensure_state_dir()?;
    let static_evidence = if index_static_evidence {
        let evidence_store = crate::static_evidence::StaticEvidenceStore::open(workspace)?;
        Some(
            crate::static_evidence::index_semgrep_findings_as_static_evidence(
                &evidence_store,
                workspace.root(),
                findings,
            )?,
        )
    } else {
        None
    };

    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(Some(SemgrepPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        static_evidence,
    }))
}

fn persist_codeql_findings(
    target: &Path,
    findings: &[crate::findings::Finding],
    ctx: &ToolExecutionContext<'_>,
    sarif_documents: &[String],
    index_static_evidence: bool,
) -> Result<Option<CodeqlPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };

    workspace.ensure_state_dir()?;
    let static_evidence = if index_static_evidence {
        let evidence_store = crate::static_evidence::StaticEvidenceStore::open(workspace)?;
        let mut combined = crate::static_evidence::StaticEvidenceIndexReport {
            db_path: evidence_store.db_path().to_string(),
            findings_indexed: 0,
            nodes_indexed: 0,
            edges_indexed: 0,
            node_ids: Vec::new(),
            edge_ids: Vec::new(),
        };
        for sarif in sarif_documents {
            let report =
                index_codeql_sarif_as_static_evidence(&evidence_store, workspace.root(), sarif)?;
            combined.findings_indexed += report.findings_indexed;
            combined.nodes_indexed += report.nodes_indexed;
            combined.edges_indexed += report.edges_indexed;
            combined.node_ids.extend(report.node_ids);
            combined.edge_ids.extend(report.edge_ids);
        }
        Some(combined)
    } else {
        None
    };

    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(Some(CodeqlPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        static_evidence,
    }))
}

fn persist_iac_findings(
    target: &Path,
    findings: &[crate::findings::Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<Value>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };

    workspace.ensure_state_dir()?;
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(Some(json!({
        "runId": run_id,
        "findingsDb": workspace.findings_db_path().display().to_string(),
    })))
}

fn run_sast_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let (input, whitebox_static) = apply_whitebox_static_sast_policy(input)?;
    let workspace = ctx
        .workspace
        .context("sast:scan requires a workspace target; pass --target <repo> or start the shell with --target <repo>")?;
    let store = ctx
        .findings_store
        .context("sast:scan requires a findings store")?;
    let verify_requested = bool_input(&input, &["verify"])?;
    let auto_patch_requested = bool_input(&input, &["autoPatch", "auto_patch"])?;
    let triage_requested = bool_input(&input, &["triage", "aiTriage", "ai_triage"])?
        || verify_requested
        || auto_patch_requested;
    let tasks = parse_sast_tasks(&input)?;
    let (
        native_tasks,
        run_agentic,
        run_carlini,
        run_taint_iris,
        run_taint_iris_next,
        run_systems_hunt,
    ) = split_agentic_sast_tasks(tasks);
    let scanners = if native_tasks.is_empty()
        && (run_agentic || run_carlini || run_taint_iris || run_taint_iris_next || run_systems_hunt)
    {
        Vec::new()
    } else {
        scan_engines_for_tasks(&native_tasks)?
    };
    if scanners.is_empty()
        && !run_agentic
        && !run_carlini
        && !run_taint_iris
        && !run_taint_iris_next
        && !run_systems_hunt
    {
        anyhow::bail!("sast:scan selected no scan engines");
    }
    let mut engine_ids = scanners
        .iter()
        .map(|scanner| scanner.id())
        .collect::<Vec<_>>();
    let options = ScanRunOptions {
        severity: parse_sast_severity_filter(&input)?,
        tasks: None,
        static_proof_state: whitebox_static
            .as_ref()
            .map(|_| StaticProofState::SignalOnly),
        index_static_evidence: whitebox_static.is_some(),
    };

    let native_run = if scanners.is_empty() {
        None
    } else {
        Some(run_scan_engines_with_options(
            workspace, store, &scanners, &options,
        )?)
    };
    let agentic_report = if run_agentic {
        engine_ids.push("agentic");
        Some(run_agentic_sast_report(&input, ctx, runtime)?)
    } else {
        None
    };
    let carlini_report = if run_carlini {
        engine_ids.push("carlini-threat-hunt");
        Some(run_carlini_threat_hunt_report(&input, ctx, runtime)?)
    } else {
        None
    };
    let taint_iris_report = if run_taint_iris {
        engine_ids.push("taint-iris");
        Some(run_taint_iris_report(&input, ctx, runtime)?)
    } else {
        None
    };
    let taint_iris_next_report = if run_taint_iris_next {
        engine_ids.push("taint-iris-next");
        let mut next_input = input.clone();
        if let Value::Object(object) = &mut next_input {
            let should_use_hunt_mode = object
                .get("mode")
                .and_then(Value::as_str)
                .map(str::trim)
                .map(|mode| matches!(mode, "standard" | "whitebox-static"))
                .unwrap_or(true);
            if should_use_hunt_mode {
                object.insert("mode".to_string(), json!("hunt"));
            }
        }
        Some(run_taint_iris_next_report(&next_input, ctx, runtime)?)
    } else {
        None
    };
    let systems_hunt_report = if run_systems_hunt {
        engine_ids.push("systems-hunt");
        Some(run_systems_hunt_report(&input, ctx, runtime)?)
    } else {
        None
    };

    let findings_count = native_run.as_ref().map_or(0, |run| run.findings_count)
        + agentic_report.as_ref().map_or(0, |report| report.count)
        + carlini_report.as_ref().map_or(0, |report| report.count)
        + taint_iris_report.as_ref().map_or(0, |report| report.count)
        + taint_iris_next_report
            .as_ref()
            .map_or(0, |report| report.count)
        + systems_hunt_report
            .as_ref()
            .map_or(0, |report| report.count);
    let primary_run_id = native_run
        .as_ref()
        .map(|run| run.id.clone())
        .or_else(|| {
            agentic_report
                .as_ref()
                .and_then(|report| report.persisted.as_ref())
                .map(|persisted| persisted.run_id.clone())
        })
        .or_else(|| {
            carlini_report
                .as_ref()
                .and_then(|report| report.persisted.as_ref())
                .map(|persisted| persisted.run_id.clone())
        })
        .or_else(|| {
            taint_iris_report
                .as_ref()
                .and_then(|report| report.persisted.as_ref())
                .map(|persisted| persisted.run_id.clone())
        })
        .or_else(|| {
            taint_iris_next_report
                .as_ref()
                .and_then(|report| report.persisted.as_ref())
                .map(|persisted| persisted.run_id.clone())
        })
        .or_else(|| {
            systems_hunt_report
                .as_ref()
                .and_then(|report| report.persisted.as_ref())
                .map(|persisted| persisted.run_id.clone())
        })
        .context("sast:scan completed without a persisted run id")?;
    let run_ids = SastRunIds {
        primary: primary_run_id.clone(),
        native: native_run.as_ref().map(|run| run.id.clone()),
        agentic: agentic_report
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone()),
        carlini: carlini_report
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone()),
        taint_iris: taint_iris_report
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone()),
        taint_iris_next: taint_iris_next_report
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone()),
        systems_hunt: systems_hunt_report
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone()),
    };
    let artifacts = SastRunArtifacts::create(workspace, &primary_run_id)?;
    fs::write(
        artifacts.dir.join("scan-input.json"),
        format!("{}\n", serde_json::to_string_pretty(&input)?),
    )
    .with_context(|| {
        format!(
            "Could not write {}",
            artifacts.dir.join("scan-input.json").display()
        )
    })?;
    let static_ranking = if whitebox_static.is_some() {
        Some(write_static_ranking_json(
            workspace, store, &run_ids, &artifacts,
        )?)
    } else {
        None
    };
    let static_narratives = if whitebox_static.is_some() {
        Some(write_static_narratives_json(
            store,
            &run_ids,
            &artifacts,
            static_ranking.as_ref(),
        )?)
    } else {
        None
    };
    let static_variants = if whitebox_static.is_some() {
        Some(write_static_variants_json(
            workspace, store, &run_ids, &artifacts,
        )?)
    } else {
        None
    };
    let candidate_semgrep_rules = if whitebox_static.is_some() {
        Some(write_candidate_semgrep_rules_json(
            workspace, store, &run_ids, &artifacts,
        )?)
    } else {
        None
    };
    let whitebox_suppressions = if whitebox_static.is_some() {
        Some(write_whitebox_suppressions_json(
            workspace, store, &run_ids, &artifacts,
        )?)
    } else {
        None
    };
    let whitebox_diff = if whitebox_static.is_some() {
        match string_input_any(&input, &["diffBase", "diff_base"]) {
            Some(diff_base) => Some(write_whitebox_diff_scope_json(
                workspace, store, &run_ids, &artifacts, &diff_base,
            )?),
            None => None,
        }
    } else {
        None
    };

    let triage = if triage_requested {
        let fingerprints = fingerprints_for_sast_runs(store, &run_ids)?;
        let triage_input = if fingerprints.is_empty() {
            json!({ "scanId": run_ids.primary.clone() })
        } else {
            json!({ "fingerprints": fingerprints })
        };
        let output = run_triage(triage_input, ctx, runtime)?;
        write_triage_jsonl(&artifacts, &output)?;
        Some(output)
    } else {
        None
    };
    let mut verification_results = Vec::new();
    let mut patch_results = Vec::new();
    if verify_requested || auto_patch_requested {
        for fingerprint in true_positive_fingerprints_for_sast_runs(store, &run_ids)? {
            let fingerprint_for_patch = fingerprint.clone();
            let verification =
                run_verify_finding(json!({ "fingerprint": fingerprint }), ctx, runtime)?;
            write_verify_jsonl(&artifacts, &verification)?;
            let exploitable = verification
                .pointer("/data/exploitable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            verification_results.push(verification);

            if auto_patch_requested && exploitable {
                let patch = run_patch_finding(
                    sast_patch_input(&input, &fingerprint_for_patch),
                    ctx,
                    runtime,
                )?;
                write_patch_jsonl(&artifacts, &fingerprint_for_patch, &patch)?;
                patch_results.push(patch);
            }
        }
    }

    let mut lines = vec![format!(
        "sast:scan {} completed: {} finding(s), db {}",
        primary_run_id,
        findings_count,
        workspace.findings_db_path().display()
    )];
    if whitebox_static.is_some() {
        lines.push(
            "  Mode: whitebox-static (static-only; verify, dynamic analysis, PoC, and patch disabled)"
                .to_string(),
        );
        if let Some(top) = static_ranking
            .as_ref()
            .and_then(|ranking| ranking.pointer("/ranked/0"))
        {
            let score = top
                .pointer("/impact/total")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let title = top
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("top static-impact finding");
            lines.push(format!("  Static ranking: top score {score} · {title}"));
        }
        if let Some(top) = static_narratives
            .as_ref()
            .and_then(|narratives| narratives.pointer("/narratives/0"))
        {
            let location = top
                .get("location")
                .and_then(Value::as_str)
                .unwrap_or("top static finding");
            lines.push(format!(
                "  Static narrative: trigger path summarized for {location}"
            ));
        }
        if let Some(count) = static_variants
            .as_ref()
            .and_then(|variants| variants.get("count"))
            .and_then(Value::as_u64)
            .filter(|count| *count > 0)
        {
            lines.push(format!(
                "  Static variants: {count} code-cited candidate(s), none confirmed by inheritance"
            ));
        }
        if let Some(count) = candidate_semgrep_rules
            .as_ref()
            .and_then(|rules| rules.get("count"))
            .and_then(Value::as_u64)
            .filter(|count| *count > 0)
        {
            let validated = candidate_semgrep_rules
                .as_ref()
                .and_then(|rules| rules.get("validationPassed"))
                .and_then(Value::as_u64)
                .unwrap_or_default();
            lines.push(format!(
                "  Candidate Semgrep rules: {count} disabled candidate(s), {validated} fixture-validated"
            ));
        }
        if let Some(suppression_report) = whitebox_suppressions.as_ref() {
            let suppressed = suppression_report
                .get("suppressedCount")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let stale = suppression_report
                .get("staleCount")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            if suppressed > 0 || stale > 0 {
                lines.push(format!(
                    "  False-positive memory: {suppressed} active suppression match(es), {stale} stale; findings remain visible in audit/report output"
                ));
            }
        }
        if let Some(diff_report) = whitebox_diff.as_ref() {
            let changed_files = diff_report
                .pointer("/summary/changedFiles")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let new_findings = diff_report
                .pointer("/summary/newFindings")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let changed_context = diff_report
                .pointer("/summary/changedContextFindings")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let fixed = diff_report
                .pointer("/summary/fixedFindings")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            lines.push(format!(
                "  Diff scope: {changed_files} changed file(s), {new_findings} new, {changed_context} changed-context, {fixed} fixed"
            ));
        }
    }
    lines.push(format!("  Engines: {}", engine_ids.join(", ")));
    if let Some(triage_output) = triage
        .as_ref()
        .and_then(|value| value.get("output"))
        .and_then(Value::as_str)
    {
        lines.push(triage_output.to_string());
    }
    if verify_requested || auto_patch_requested {
        lines.push(format!(
            "      verified={} patched={}",
            verification_results.len(),
            patch_results.len()
        ));
    }
    let static_narratives_artifact = static_narratives.as_ref().map(|_| {
        artifacts
            .dir
            .join("static-narratives.json")
            .display()
            .to_string()
    });
    let static_variants_artifact = static_variants.as_ref().map(|_| {
        artifacts
            .dir
            .join("static-variants.json")
            .display()
            .to_string()
    });
    let candidate_semgrep_rules_artifact = candidate_semgrep_rules.as_ref().map(|_| {
        artifacts
            .dir
            .join("candidate-semgrep-rules.json")
            .display()
            .to_string()
    });
    let whitebox_suppressions_artifact = whitebox_suppressions.as_ref().map(|_| {
        artifacts
            .dir
            .join("whitebox-suppressions.json")
            .display()
            .to_string()
    });
    let whitebox_diff_artifact = whitebox_diff.as_ref().map(|_| {
        artifacts
            .dir
            .join("whitebox-diff-scope.json")
            .display()
            .to_string()
    });

    let result = json!({
        "ok": true,
        "output": lines.join("\n"),
        "data": {
            "runId": primary_run_id,
            "runIds": {
                "native": run_ids.native,
                "agentic": run_ids.agentic,
                "carlini": run_ids.carlini,
                "taintIris": run_ids.taint_iris,
                "taintIrisNext": run_ids.taint_iris_next,
                "systemsHunt": run_ids.systems_hunt,
            },
            "target": workspace.root().display().to_string(),
            "mode": whitebox_static
                .as_ref()
                .map_or("standard", |policy| policy.mode.as_str()),
            "whiteboxStatic": whitebox_static.as_ref().map(|policy| policy.to_json()),
            "findingsCount": findings_count,
            "db": workspace.findings_db_path().display().to_string(),
            "engines": engine_ids,
            "agentic": agentic_report.as_ref().map(|report| json!(report)),
            "carliniThreatHunt": carlini_report.as_ref().map(|report| json!(report)),
            "taintIris": taint_iris_report.as_ref().map(|report| json!(report)),
            "taintIrisNext": taint_iris_next_report.as_ref().map(|report| json!(report)),
            "systemsHunt": systems_hunt_report.as_ref().map(|report| json!(report)),
            "staticRanking": static_ranking,
            "staticNarratives": static_narratives,
            "staticVariants": static_variants,
            "candidateSemgrepRules": candidate_semgrep_rules,
            "whiteboxSuppressions": whitebox_suppressions,
            "whiteboxDiff": whitebox_diff,
            "triage": triage.as_ref().and_then(|value| value.get("data")).cloned(),
            "verification": {
                "verified": verification_results.len(),
                "results": verification_results
                    .iter()
                    .filter_map(|value| value.get("data").cloned())
                    .collect::<Vec<_>>(),
            },
            "patch": {
                "patched": patch_results.len(),
                "results": patch_results
                    .iter()
                    .filter_map(|value| value.get("data").cloned())
                    .collect::<Vec<_>>(),
            },
            "artifacts": {
                "dir": artifacts.dir.display().to_string(),
                "summary": artifacts.summary.display().to_string(),
                "staticNarratives": static_narratives_artifact,
                "staticVariants": static_variants_artifact,
                "candidateSemgrepRules": candidate_semgrep_rules_artifact,
                "whiteboxSuppressions": whitebox_suppressions_artifact,
                "whiteboxDiff": whitebox_diff_artifact,
                "triageJsonl": artifacts.triage_jsonl.display().to_string(),
                "verifyJsonl": artifacts.verify_jsonl.display().to_string(),
            },
        },
    });
    write_sast_summary(&artifacts, &result)?;

    Ok(result)
}

#[derive(Debug, Clone)]
struct SastRunIds {
    primary: String,
    native: Option<String>,
    agentic: Option<String>,
    carlini: Option<String>,
    taint_iris: Option<String>,
    taint_iris_next: Option<String>,
    systems_hunt: Option<String>,
}

impl SastRunIds {
    fn all(&self) -> Vec<&str> {
        let mut ids = Vec::new();
        if let Some(native) = self.native.as_deref() {
            ids.push(native);
        }
        if let Some(agentic) = self.agentic.as_deref() {
            ids.push(agentic);
        }
        if let Some(carlini) = self.carlini.as_deref() {
            ids.push(carlini);
        }
        if let Some(taint_iris) = self.taint_iris.as_deref() {
            ids.push(taint_iris);
        }
        if let Some(taint_iris_next) = self.taint_iris_next.as_deref() {
            ids.push(taint_iris_next);
        }
        if let Some(systems_hunt) = self.systems_hunt.as_deref() {
            ids.push(systems_hunt);
        }
        if ids.is_empty() {
            ids.push(&self.primary);
        }
        ids
    }
}

#[derive(Debug, Clone)]
struct SastRunArtifacts {
    dir: PathBuf,
    summary: PathBuf,
    triage_jsonl: PathBuf,
    verify_jsonl: PathBuf,
}

impl SastRunArtifacts {
    fn create(workspace: &WorkspaceTarget, run_id: &str) -> Result<Self> {
        let dir = workspace.root().join(".kuzushi").join("runs").join(run_id);
        fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
        let triage_jsonl = dir.join("triage.jsonl");
        let verify_jsonl = dir.join("verify.jsonl");
        fs::write(&triage_jsonl, "")
            .with_context(|| format!("Could not write {}", triage_jsonl.display()))?;
        fs::write(&verify_jsonl, "")
            .with_context(|| format!("Could not write {}", verify_jsonl.display()))?;
        Ok(Self {
            summary: dir.join("summary.json"),
            triage_jsonl,
            verify_jsonl,
            dir,
        })
    }
}

fn fingerprints_for_sast_runs(store: &FindingStore, run_ids: &SastRunIds) -> Result<Vec<String>> {
    let mut fingerprints = Vec::new();
    let mut seen = BTreeSet::new();
    for run_id in run_ids.all() {
        for finding in store.list_findings_for_scan_id(run_id)? {
            if seen.insert(finding.fingerprint.clone()) {
                fingerprints.push(finding.fingerprint);
            }
        }
    }
    Ok(fingerprints)
}

fn findings_for_sast_runs(store: &FindingStore, run_ids: &SastRunIds) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    for run_id in run_ids.all() {
        for finding in store.list_findings_for_scan_id(run_id)? {
            if seen.insert(finding.fingerprint.clone()) {
                findings.push(finding);
            }
        }
    }
    Ok(findings)
}

fn write_static_ranking_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let attack_surface = crate::attack_surface::build_attack_surface_map(workspace.root()).ok();
    let evidence_store = StaticEvidenceStore::open(workspace).ok();
    let ranked = rank_static_findings(&findings, attack_surface.as_ref(), evidence_store.as_ref())?;
    let artifact_path = artifacts.dir.join("static-ranking.json");
    let report = json!({
        "count": ranked.len(),
        "ranked": ranked,
        "attackSurfaceAvailable": attack_surface.is_some(),
        "evidenceDb": evidence_store
            .as_ref()
            .map(|store| store.db_path().to_string()),
        "artifact": artifact_path.display().to_string(),
        "deterministic": true,
        "factors": [
            "attackSurfaceReachability",
            "sourceSinkClass",
            "dataSensitivity",
            "privilegeBoundary",
            "sanitizerAbsence",
            "frameworkContext",
            "codeqlFlowQuality",
            "confidence"
        ],
    });
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

fn write_static_narratives_json(
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
    static_ranking: Option<&Value>,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let ranked = static_ranking
        .and_then(|ranking| ranking.get("ranked").cloned())
        .map(serde_json::from_value::<Vec<StaticRankedFinding>>)
        .transpose()?
        .unwrap_or_default();
    let narrative_report = build_static_narrative_report(&findings, &ranked)?;
    let artifact_path = artifacts.dir.join("static-narratives.json");
    let report = json!({
        "count": narrative_report.count,
        "narratives": narrative_report.narratives,
        "artifact": artifact_path.display().to_string(),
        "deterministic": narrative_report.deterministic,
    });
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

fn write_static_variants_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let evidence_store = StaticEvidenceStore::open(workspace).ok();
    let variant_report =
        hunt_whitebox_static_variants(workspace.root(), &findings, evidence_store.as_ref(), 50)?;
    let artifact_path = artifacts.dir.join("static-variants.json");
    let report = json!({
        "count": variant_report.count,
        "patterns": variant_report.patterns,
        "variants": variant_report.variants,
        "artifact": artifact_path.display().to_string(),
        "deterministic": variant_report.deterministic,
        "policy": "whitebox-static variants are code-cited candidates only; no variant is statically_confirmed by inheritance",
    });
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

fn write_candidate_semgrep_rules_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let evidence_store = StaticEvidenceStore::open(workspace).ok();
    let synthesis_report =
        synthesize_candidate_semgrep_rules(&findings, evidence_store.as_ref(), &[])?;
    let artifact_path = artifacts.dir.join("candidate-semgrep-rules.json");
    let report = json!({
        "count": synthesis_report.count,
        "validationPassed": synthesis_report.validation_passed,
        "candidates": synthesis_report.candidates,
        "artifact": artifact_path.display().to_string(),
        "deterministic": synthesis_report.deterministic,
        "policy": "candidate Semgrep rules are generated only from statically_confirmed findings and remain disabled until fixture validation passes and an operator enables them",
    });
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

fn write_whitebox_suppressions_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let findings = findings_for_sast_runs(store, run_ids)?;
    let suppressions = load_whitebox_suppressions(workspace)?;
    let suppression_report =
        evaluate_whitebox_suppressions(workspace.root(), &findings, &suppressions, now_unix());
    let artifact_path = artifacts.dir.join("whitebox-suppressions.json");
    let report = json!({
        "totalSuppressions": suppression_report.total_suppressions,
        "activeSuppressions": suppression_report.active_suppressions,
        "suppressedCount": suppression_report.suppressed_count,
        "suppressedFindings": suppression_report.suppressed_findings,
        "staleCount": suppression_report.stale_suppressions.len(),
        "staleSuppressions": suppression_report.stale_suppressions,
        "expiredCount": suppression_report.expired_suppressions.len(),
        "expiredSuppressions": suppression_report.expired_suppressions,
        "findingsRemainVisible": suppression_report.findings_remain_visible,
        "auditNote": suppression_report.audit_note,
        "artifact": artifact_path.display().to_string(),
        "deterministic": true,
        "policy": "whitebox-static false-positive memory annotates suppressions only; suppressed findings remain in audit/report output",
    });
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

fn write_whitebox_diff_scope_json(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
    diff_base: &str,
) -> Result<Value> {
    let current_findings = findings_for_sast_runs(store, run_ids)?;
    let previous_findings = store.list_findings(FindingListFilter::MAX_LIMIT)?;
    let artifact_path = artifacts.dir.join("whitebox-diff-scope.json");
    let mut report = serde_json::to_value(build_whitebox_diff_scope_report(
        workspace.root(),
        diff_base,
        &current_findings,
        &previous_findings,
    )?)?;
    if let Value::Object(object) = &mut report {
        object.insert(
            "artifact".to_string(),
            json!(artifact_path.display().to_string()),
        );
        object.insert(
            "policy".to_string(),
            json!("whitebox-static PR mode uses only local git diff data; no remote git provider is required"),
        );
    }
    fs::write(
        &artifact_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("Could not write {}", artifact_path.display()))?;
    Ok(report)
}

fn true_positive_fingerprints_for_sast_runs(
    store: &FindingStore,
    run_ids: &SastRunIds,
) -> Result<Vec<String>> {
    let mut fingerprints = Vec::new();
    let mut seen = BTreeSet::new();
    for run_id in run_ids.all() {
        for finding in store.list_findings_for_scan_id(run_id)? {
            if finding
                .triage
                .as_ref()
                .is_some_and(|triage| triage.verdict == TriageVerdict::TruePositive)
                && seen.insert(finding.fingerprint.clone())
            {
                fingerprints.push(finding.fingerprint);
            }
        }
    }
    Ok(fingerprints)
}

fn sast_patch_input(sast_input: &Value, fingerprint: &str) -> Value {
    let mut patch_input = Map::new();
    patch_input.insert("fingerprint".to_string(), json!(fingerprint));
    for key in ["maxIterations", "buildCmd", "testCmd"] {
        if let Some(value) = sast_input.get(key) {
            patch_input.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(patch_input)
}

fn write_sast_summary(artifacts: &SastRunArtifacts, result: &Value) -> Result<()> {
    fs::write(
        &artifacts.summary,
        format!("{}\n", serde_json::to_string_pretty(result)?),
    )
    .with_context(|| format!("Could not write {}", artifacts.summary.display()))
}

fn write_triage_jsonl(artifacts: &SastRunArtifacts, triage_output: &Value) -> Result<()> {
    let results = triage_output
        .pointer("/data/results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if results.is_empty() {
        append_jsonl(
            &artifacts.triage_jsonl,
            json!({
                "type": "triage:complete",
                "data": triage_output.get("data").cloned().unwrap_or(Value::Null),
            }),
        )?;
        return Ok(());
    }

    for result in results {
        append_jsonl(
            &artifacts.triage_jsonl,
            json!({
                "type": "triage:complete",
                "fingerprint": result.get("fingerprint").cloned().unwrap_or(Value::Null),
                "data": result,
            }),
        )?;
    }
    Ok(())
}

fn write_verify_jsonl(artifacts: &SastRunArtifacts, verify_output: &Value) -> Result<()> {
    append_jsonl(
        &artifacts.verify_jsonl,
        json!({
            "type": "verification:complete",
            "fingerprint": verify_output.pointer("/data/fingerprint").cloned().unwrap_or(Value::Null),
            "data": verify_output.get("data").cloned().unwrap_or(Value::Null),
        }),
    )
}

fn write_patch_jsonl(
    artifacts: &SastRunArtifacts,
    fingerprint: &str,
    patch_output: &Value,
) -> Result<()> {
    append_jsonl(
        &artifacts.verify_jsonl,
        json!({
            "type": "patch:complete",
            "fingerprint": fingerprint,
            "data": patch_output.get("data").cloned().unwrap_or(Value::Null),
        }),
    )
}

fn append_jsonl(path: &Path, value: Value) -> Result<()> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(&value)?)
        .with_context(|| format!("Could not write {}", path.display()))
}

fn split_agentic_sast_tasks(tasks: Vec<String>) -> (Vec<String>, bool, bool, bool, bool, bool) {
    let mut native = Vec::new();
    let mut agentic = false;
    let mut carlini = false;
    let mut taint_iris = false;
    let mut taint_iris_next = false;
    let mut systems_hunt = false;
    for task in tasks {
        match task.trim() {
            "agentic" | "agentic-sast" | "agentic-sast:scan" => agentic = true,
            "carlini" | "threat-hunt" | "carlini-threat-hunt" | "carlini-threat-hunt:run" => {
                carlini = true
            }
            "taint" | "iris" | "taint-iris" | "taint-iris:hunt" => taint_iris = true,
            "taint-iris-next" | "iris-next" | "taint-next" | "taint-iris-next:hunt" => {
                taint_iris_next = true
            }
            "systems"
            | "systems-hunt"
            | "systems-hunt:systems-hunt"
            | "systems-hunt:systems-context-gatherer"
            | "systems-hunt:systems-invariant-extract"
            | "systems-hunt:systems-trigger-synth"
            | "deep-semantic"
            | "deep-semantic-hunt"
            | "systems-hunt:deep-semantic-hunt" => systems_hunt = true,
            _ => native.push(task),
        }
    }
    (
        native,
        agentic,
        carlini,
        taint_iris,
        taint_iris_next,
        systems_hunt,
    )
}

#[derive(Debug, Clone)]
struct AgenticSastInput {
    max_findings: usize,
    passes: usize,
    severity: Vec<String>,
    exclude_patterns: Vec<String>,
}

impl AgenticSastInput {
    fn from_tool_input(input: &Value) -> Result<Self> {
        let max_findings = match input
            .get("maxFindings")
            .or_else(|| input.get("max_findings"))
        {
            Some(Value::Number(number)) => number
                .as_u64()
                .filter(|value| *value > 0)
                .context("agentic-sast:scan maxFindings must be a positive integer")?
                .min(200) as usize,
            Some(Value::String(value)) => value
                .parse::<usize>()
                .ok()
                .filter(|value| *value > 0)
                .context("agentic-sast:scan maxFindings must be a positive integer")?
                .min(200),
            Some(_) => anyhow::bail!("agentic-sast:scan maxFindings must be a positive integer"),
            None => 40,
        };
        let passes = match input.get("passes") {
            Some(Value::Number(number)) => number
                .as_u64()
                .filter(|value| matches!(*value, 1 | 2))
                .context("agentic-sast:scan passes must be 1 or 2")?
                as usize,
            Some(Value::String(value)) => value
                .parse::<usize>()
                .ok()
                .filter(|value| matches!(*value, 1 | 2))
                .context("agentic-sast:scan passes must be 1 or 2")?,
            Some(_) => anyhow::bail!("agentic-sast:scan passes must be 1 or 2"),
            None => 1,
        };
        let severity = string_list_input(input, &["severity"])?.unwrap_or_else(|| {
            vec![
                "ERROR".to_string(),
                "WARNING".to_string(),
                "INFO".to_string(),
            ]
        });
        let exclude_patterns =
            string_list_input(input, &["excludePatterns", "exclude_patterns"])?.unwrap_or_default();

        Ok(Self {
            max_findings,
            passes,
            severity,
            exclude_patterns,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgenticSastReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<AgenticSastPersistedRun>,
    pub cost_usd: f64,
}

impl AgenticSastReport {
    fn output(&self) -> String {
        let mut lines = vec![format!(
            "agentic-sast: {} finding{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.target
        )];
        if let Some(persisted) = &self.persisted {
            lines.push(format!(
                "  Persisted run: {} ({})",
                persisted.run_id, persisted.findings_db
            ));
        }
        if !self.findings.is_empty() {
            lines.push(String::new());
            lines.push("Top findings:".to_string());
            for finding in self.findings.iter().take(10) {
                lines.push(format!(
                    "  - {} - {} - {}:{}",
                    finding.severity.as_str(),
                    finding.rule_id,
                    finding.file_path,
                    finding.start_line
                ));
            }
            if self.findings.len() > 10 {
                lines.push(format!("  ... and {} more", self.findings.len() - 10));
            }
        }
        lines.join("\n")
    }

    fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
            "costUsd": self.cost_usd,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgenticSastPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}

const AGENTIC_SAST_SYSTEM_PROMPT: &str = r#"You are Kuzushi's agentic SAST scanner.
Return only JSON matching:
{"findings":[{"ruleId":"short-rule-id","filePath":"relative/path","startLine":1,"endLine":1,"severity":"ERROR|WARNING|INFO","message":"short finding summary","confidence":"HIGH|MEDIUM|LOW","subcategory":["vuln"],"likelihood":"HIGH|MEDIUM|LOW","impact":"HIGH|MEDIUM|LOW","cwe":["CWE-..."],"evidence":"source-to-sink proof"}]}.
Only report concrete vulnerabilities you can justify from the provided repository inventory and snippets."#;

fn run_agentic_sast_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<AgenticSastReport> {
    let target = resolve_tool_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "agentic-sast: target is not a directory: {}",
            target.display()
        );
    }
    let options = AgenticSastInput::from_tool_input(input)?;
    let runtime = runtime.context(
        "agentic-sast:scan requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = optional_nonempty_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context(
            "agentic-sast:scan requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
        )?;
    let whitebox_static = whitebox_static_profile_requested(input)?;
    let system_prompt = if whitebox_static {
        whitebox_static_triage_system_prompt().to_string()
    } else {
        AGENTIC_SAST_SYSTEM_PROMPT.to_string()
    };
    let agent_tool_policy = agent_tool_policy_for_input(input)?;

    let inventory = collect_agentic_repo_inventory(&target, 80, 2048)?;
    let response = runtime.query_blocking(
        AgentQueryRequest::new(
            model.clone(),
            target.clone(),
            system_prompt.clone(),
            build_agentic_sast_prompt(&target, &options, &inventory, None, whitebox_static),
        )
        .with_tool_policy(agent_tool_policy.clone()),
    )?;
    let first_raw = parse_agentic_sast_response(response)?;
    let mut findings =
        normalize_agentic_sast_findings(first_raw, &target, options.max_findings, whitebox_static)?;

    if options.passes == 2 && !findings.is_empty() {
        let review_context = summarize_agentic_findings_for_review(&findings);
        let review_response = runtime.query_blocking(
            AgentQueryRequest::new(
                model.clone(),
                target.clone(),
                system_prompt,
                build_agentic_sast_prompt(
                    &target,
                    &options,
                    &inventory,
                    Some(&review_context),
                    whitebox_static,
                ),
            )
            .with_tool_policy(agent_tool_policy.clone()),
        )?;
        let review_raw = parse_agentic_sast_response(review_response)?;
        let review_findings = normalize_agentic_sast_findings(
            review_raw,
            &target,
            options.max_findings,
            whitebox_static,
        )?;
        let mut merged = BTreeMap::new();
        for finding in findings.into_iter().chain(review_findings) {
            merged.entry(finding.fingerprint.clone()).or_insert(finding);
        }
        findings = merged.into_values().take(options.max_findings).collect();
    }
    if whitebox_static {
        mark_whitebox_static_findings(&mut findings, StaticProofState::CodeCited)?;
    }

    let persisted = persist_agentic_sast_findings(&target, &findings, ctx)?;
    Ok(AgenticSastReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        cost_usd: 0.0,
    })
}

fn parse_agentic_sast_response(response: AgentQueryResponse) -> Result<Value> {
    match response.structured {
        Some(value) => Ok(value),
        None => parse_json_object_from_agent_text(&response.text).with_context(|| {
            "agentic-sast:scan expected pi-agent-core to return JSON with a findings array"
        }),
    }
}

fn collect_agentic_repo_inventory(
    root: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    collect_agentic_repo_inventory_inner(root, root, max_files, max_bytes_per_file, &mut files)?;
    Ok(files)
}

fn collect_agentic_repo_inventory_inner(
    root: &Path,
    dir: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
    files: &mut Vec<(String, String)>,
) -> Result<()> {
    if files.len() >= max_files {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if files.len() >= max_files {
            break;
        }
        let path = entry.path();
        let file_name = entry.file_name();
        if should_skip_path(&file_name.to_string_lossy()) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_agentic_repo_inventory_inner(
                root,
                &path,
                max_files,
                max_bytes_per_file,
                files,
            )?;
        } else if file_type.is_file() && is_agentic_context_file(&path) {
            let raw = fs::read(&path).unwrap_or_default();
            if raw.iter().take(4096).any(|byte| *byte == 0) {
                continue;
            }
            let snippet =
                String::from_utf8_lossy(&raw[..raw.len().min(max_bytes_per_file)]).to_string();
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            files.push((relative, snippet));
        }
    }
    Ok(())
}

fn is_agentic_context_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if matches!(
        name,
        "package.json" | "Cargo.toml" | "pyproject.toml" | "go.mod" | "pom.xml"
    ) {
        return true;
    }
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or(""),
        "c" | "cc"
            | "cpp"
            | "cs"
            | "go"
            | "java"
            | "js"
            | "jsx"
            | "kt"
            | "php"
            | "py"
            | "rb"
            | "rs"
            | "sol"
            | "ts"
            | "tsx"
    )
}

fn build_agentic_sast_prompt(
    target: &Path,
    options: &AgenticSastInput,
    inventory: &[(String, String)],
    review_context: Option<&str>,
    whitebox_static: bool,
) -> String {
    let mut prompt = vec![
        "Scan this repository for concrete application-security vulnerabilities.".to_string(),
        format!("Target: {}", target.display()),
        format!("Severity filter: {}", options.severity.join(", ")),
        format!("Max findings: {}", options.max_findings),
        format!(
            "Exclude paths/globs: {}",
            if options.exclude_patterns.is_empty() {
                "(none)".to_string()
            } else {
                options.exclude_patterns.join(", ")
            }
        ),
        String::new(),
        "Evidence requirements: name the attacker-controlled source, sink, missing guard, and exact file:line. Omit uncertain or hypothetical findings.".to_string(),
    ];
    if whitebox_static {
        prompt.push(String::new());
        prompt.push(whitebox_static_triage_prompt_block().to_string());
    }
    if let Some(review_context) = review_context {
        prompt.push(String::new());
        prompt.push(review_context.to_string());
    }
    prompt.push(String::new());
    prompt.push("Repository inventory and snippets:".to_string());
    if inventory.is_empty() {
        prompt.push("(no readable source snippets found)".to_string());
    }
    for (path, snippet) in inventory {
        prompt.push(format!("\n--- {path} ---\n{snippet}"));
    }
    prompt.join("\n")
}

fn summarize_agentic_findings_for_review(findings: &[Finding]) -> String {
    let mut lines = vec![
        "Second pass context: validate these first-pass findings and report only new or corrected findings.".to_string(),
    ];
    for finding in findings.iter().take(20) {
        lines.push(format!(
            "- [{}] {} at {}:{}: {}",
            finding.severity.as_str(),
            finding.rule_id,
            finding.file_path,
            finding.start_line,
            finding.title
        ));
    }
    lines.join("\n")
}

fn normalize_agentic_sast_findings(
    raw: Value,
    target: &Path,
    max_findings: usize,
    whitebox_static: bool,
) -> Result<Vec<Finding>> {
    let findings_value = match raw {
        Value::Object(object) => object
            .get("findings")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        Value::Array(items) => Value::Array(items),
        _ => {
            anyhow::bail!("agentic-sast output parse failed: expected an object or findings array")
        }
    };
    let Value::Array(items) = findings_value else {
        anyhow::bail!("agentic-sast output parse failed: findings must be an array");
    };

    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        let raw_item = Value::Object(object.clone());
        let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
            .unwrap_or_else(|| "agentic-sast/finding".to_string());
        let file_path =
            normalize_agentic_file_path(resolve_agentic_schema_file_path(&object), target);
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .or_else(|| read_nested_object_u64(&object, "source", &["startLine", "start_line"]))
            .or_else(|| first_citation_u64(&object, &["startLine", "start_line"]))
            .filter(|value| *value > 0)
            .unwrap_or(1) as u32;
        let end_line = read_object_u64(&object, &["endLine", "end_line"])
            .or_else(|| read_nested_object_u64(&object, "source", &["endLine", "end_line"]))
            .or_else(|| first_citation_u64(&object, &["endLine", "end_line"]))
            .filter(|value| *value > 0)
            .map(|value| value as u32);
        let severity = agentic_severity(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or("WARNING"),
        );
        let mut message = read_object_string(&object, &["message"])
            .or_else(|| read_object_string(&object, &["title"]))
            .unwrap_or_else(|| rule_id.clone());
        if let Some(evidence) = read_object_string(&object, &["evidence"]) {
            if !evidence.trim().is_empty() {
                message.push_str("\n\nEvidence: ");
                message.push_str(evidence.trim());
            }
        }
        append_agentic_schema_field(&mut message, &object, "verdict", "Verdict");
        append_agentic_schema_field(
            &mut message,
            &object,
            "staticProofState",
            "Static proof state",
        );
        append_agentic_schema_object_summary(&mut message, &object, "source", "Source");
        append_agentic_schema_object_summary(&mut message, &object, "sink", "Sink");
        append_agentic_schema_object_summary(&mut message, &object, "path", "Path");
        append_agentic_schema_object_summary(
            &mut message,
            &object,
            "sanitizerAssessment",
            "Sanitizer assessment",
        );
        append_agentic_schema_object_summary(
            &mut message,
            &object,
            "guardAssessment",
            "Guard assessment",
        );
        append_agentic_schema_field(
            &mut message,
            &object,
            "triggerNarrative",
            "Trigger narrative",
        );
        append_agentic_schema_field(&mut message, &object, "impactNarrative", "Impact narrative");
        append_agentic_schema_field(&mut message, &object, "recommendedFix", "Recommended fix");
        if let Some(confidence) = read_object_string(&object, &["confidence"]) {
            message.push_str("\nConfidence: ");
            message.push_str(confidence.trim());
        }
        let mut finding = Finding::new_tool(
            "agentic", rule_id, file_path, start_line, end_line, severity, message,
        );
        if whitebox_static {
            let validation = validate_agentic_whitebox_static_claim(target, &raw_item)?;
            apply_agentic_static_validation(&mut finding, &validation);
        } else if let Some(state) = whitebox_static_proof_state_from_input(&raw_item)? {
            finding.set_static_proof_state(state);
        }
        findings.push(finding);
    }
    Ok(findings)
}

fn validate_agentic_whitebox_static_claim(
    target: &Path,
    raw_item: &Value,
) -> Result<StaticProofValidation> {
    let claim = static_proof_claim_from_whitebox_schema(raw_item)?;
    Ok(validate_static_proof_claim(target, &claim))
}

fn apply_agentic_static_validation(finding: &mut Finding, validation: &StaticProofValidation) {
    finding.set_static_proof_state(validation.final_state);
    if validation.accepted {
        if !validation.verified_citations.is_empty() {
            finding.message.push_str("\nVerified citations: ");
            finding
                .message
                .push_str(&validation.verified_citations.len().to_string());
        }
        return;
    }
    finding
        .message
        .push_str("\nWhitebox citation validation: downgraded to needs_runtime_evidence.");
    for issue in validation.issues.iter().take(6) {
        finding.message.push_str("\n- ");
        finding.message.push_str(issue);
    }
}

fn resolve_agentic_schema_file_path(object: &Map<String, Value>) -> String {
    read_object_string(object, &["filePath", "file_path"])
        .or_else(|| read_nested_object_string(object, "source", &["filePath", "file_path"]))
        .or_else(|| read_nested_object_string(object, "sink", &["filePath", "file_path"]))
        .or_else(|| first_citation_string(object, &["filePath", "file_path"]))
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_nested_object_string(
    object: &Map<String, Value>,
    nested_key: &str,
    keys: &[&str],
) -> Option<String> {
    object
        .get(nested_key)
        .and_then(Value::as_object)
        .and_then(|nested| read_object_string(nested, keys))
}

fn read_nested_object_u64(
    object: &Map<String, Value>,
    nested_key: &str,
    keys: &[&str],
) -> Option<u64> {
    object
        .get(nested_key)
        .and_then(Value::as_object)
        .and_then(|nested| read_object_u64(nested, keys))
}

fn first_citation_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    object
        .get("citations")
        .and_then(Value::as_array)
        .and_then(|citations| citations.first())
        .and_then(Value::as_object)
        .and_then(|citation| read_object_string(citation, keys))
}

fn first_citation_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    object
        .get("citations")
        .and_then(Value::as_array)
        .and_then(|citations| citations.first())
        .and_then(Value::as_object)
        .and_then(|citation| read_object_u64(citation, keys))
}

fn append_agentic_schema_field(
    message: &mut String,
    object: &Map<String, Value>,
    key: &str,
    label: &str,
) {
    if let Some(value) = read_object_string(object, &[key]) {
        if !value.trim().is_empty() {
            message.push('\n');
            message.push_str(label);
            message.push_str(": ");
            message.push_str(value.trim());
        }
    }
}

fn append_agentic_schema_object_summary(
    message: &mut String,
    object: &Map<String, Value>,
    key: &str,
    label: &str,
) {
    let Some(value) = object.get(key).and_then(Value::as_object) else {
        return;
    };
    let summary = read_object_string(value, &["description", "explanation", "status", "kind"])
        .filter(|text| !text.trim().is_empty());
    let Some(summary) = summary else {
        return;
    };
    message.push('\n');
    message.push_str(label);
    message.push_str(": ");
    message.push_str(summary.trim());
}

fn normalize_agentic_file_path(path: String, target: &Path) -> String {
    let candidate = PathBuf::from(path.trim());
    if candidate.is_absolute() {
        return candidate
            .strip_prefix(target)
            .unwrap_or(&candidate)
            .display()
            .to_string();
    }
    path.trim().to_string()
}

fn agentic_severity(value: &str) -> Severity {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "ERROR" | "HIGH" => Severity::High,
        "WARNING" | "MEDIUM" => Severity::Medium,
        "INFO" | "LOW" => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn persist_agentic_sast_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<AgenticSastPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(Some(AgenticSastPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct TaintCweSelection {
    id: String,
    name: String,
    reason: String,
}

#[derive(Debug, Clone)]
struct TaintIrisInput {
    max_cwes: Option<usize>,
    max_findings: usize,
    prompt_override: Option<String>,
    max_budget_usd: Option<f64>,
}

impl TaintIrisInput {
    fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        let prompt_override = optional_nonempty_string(input, "TAINT_IRIS_PROMPT")?
            .map(|value| resolve_prompt_override_for_key(&value, cwd, "TAINT_IRIS_PROMPT"))
            .transpose()?;
        Ok(Self {
            max_cwes: positive_usize_input(
                input,
                &["maxCwes", "max_cwes"],
                "taint-iris:hunt maxCwes",
            )?,
            max_findings: positive_usize_input(
                input,
                &["maxFindings", "max_findings"],
                "taint-iris:hunt maxFindings",
            )?
            .unwrap_or(50)
            .min(250),
            prompt_override,
            max_budget_usd: positive_f64_input(
                input,
                &["maxBudgetUsd", "max_budget_usd"],
                "taint-iris:hunt maxBudgetUsd",
            )?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisReport {
    target: String,
    count: usize,
    cwes: Vec<TaintCweSelection>,
    findings: Vec<Finding>,
    persisted: Option<TaintIrisPersistedRun>,
    cost_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    degradation: Option<Value>,
}

impl TaintIrisReport {
    fn output(&self) -> String {
        let mut lines = vec![format!(
            "taint-iris: {} finding{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.target
        )];
        if self.cwes.is_empty() {
            lines.push("  CWE classes: none selected".to_string());
        } else {
            lines.push(format!(
                "  CWE classes: {}",
                self.cwes
                    .iter()
                    .map(|cwe| cwe.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if let Some(persisted) = &self.persisted {
            lines.push(format!(
                "  Persisted run: {} ({})",
                persisted.run_id, persisted.findings_db
            ));
        }
        if !self.findings.is_empty() {
            lines.push(String::new());
            lines.push("Top findings:".to_string());
            for finding in self.findings.iter().take(10) {
                lines.push(format!(
                    "  - {} - {} - {}:{}",
                    finding.severity.as_str(),
                    finding.rule_id,
                    finding.file_path,
                    finding.start_line
                ));
            }
            if self.findings.len() > 10 {
                lines.push(format!("  ... and {} more", self.findings.len() - 10));
            }
        }
        lines.join("\n")
    }

    fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
            "costUsd": self.cost_usd,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct TaintIrisPersistedRun {
    run_id: String,
    findings_db: String,
}

const TAINT_CWE_SELECT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Taint CWE selector.
Return only JSON matching:
{"cwes":[{"id":"CWE-89","name":"SQL Injection","reason":"why this project should be checked"}]}.
Select only vulnerability classes that are plausible for the provided repository context."#;

const TAINT_IRIS_SYSTEM_PROMPT: &str = r#"You are Kuzushi's IRIS-style taint analysis agent.
Return only JSON matching:
{"findings":[{"title":"short title","cwe":"CWE-89","severity":"critical|high|medium|low","filePath":"relative/path","startLine":1,"message":"finding detail","sourceSinkTrace":"source -> sink proof","taintPath":[{"filePath":"relative/path","line":1,"message":"source|step|sink","snippet":"code"}],"confidence":"high|medium|low","exploitPreconditions":"required conditions"}]}.
Only report concrete source-to-sink vulnerabilities with code evidence. Omit uncertain or hypothetical findings."#;

fn run_taint_cwe_select(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let model = optional_nonempty_string(&input, "model")?.or_else(|| ctx.config.model.clone());
    let cwes = run_taint_cwe_select_value(&input, &target, runtime, model.as_deref())?;
    Ok(json!({
        "ok": true,
        "output": format!("pipeline:taint-cwe-select selected {} CWE class{}", cwes.len(), if cwes.len() == 1 { "" } else { "es" }),
        "data": {
            "target": target.display().to_string(),
            "cwes": cwes,
        },
    }))
}

fn run_taint_iris_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<TaintIrisReport> {
    let target = resolve_tool_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "taint-iris:hunt target is not a directory: {}",
            target.display()
        );
    }
    let options = TaintIrisInput::from_tool_input(input, &target)?;
    let runtime = runtime.context(
        "taint-iris:hunt requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = optional_nonempty_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context(
            "taint-iris:hunt requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
        )?;

    let mut cwes = run_taint_cwe_select_value(input, &target, Some(runtime), Some(&model))?;
    if let Some(max_cwes) = options.max_cwes {
        cwes.truncate(max_cwes);
    }

    if cwes.is_empty() {
        let findings = Vec::new();
        let persisted = persist_taint_iris_findings(&target, &findings, ctx)?;
        return Ok(TaintIrisReport {
            target: target.display().to_string(),
            count: 0,
            cwes,
            findings,
            persisted,
            cost_usd: 0.0,
            degradation: Some(json!({
                "type": "legacy-inconclusive",
                "reason": "no-cwes-selected",
                "message": "No CWE classes were selected, so the IRIS taint agent did not run; treat as inconclusive, not clean.",
            })),
        });
    }

    let inventory = collect_agentic_repo_inventory(&target, 80, 2048)?;
    let codeql_db = resolve_taint_codeql_db_path(&target, ctx.workspace.map(WorkspaceTarget::root));
    let response = runtime.query_blocking(
        AgentQueryRequest::new(
            model.clone(),
            target.clone(),
            TAINT_IRIS_SYSTEM_PROMPT.to_string(),
            build_taint_iris_prompt(&target, &cwes, &inventory, codeql_db.as_deref(), &options),
        )
        .with_tool_policy(agent_tool_policy_for_input(input)?),
    )?;
    let raw = parse_taint_iris_response(response)?;
    let mut findings = normalize_taint_iris_findings(raw, &target, options.max_findings)?;
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SourceSinkLinked)?;
    }
    let persisted = persist_taint_iris_findings(&target, &findings, ctx)?;

    Ok(TaintIrisReport {
        target: target.display().to_string(),
        count: findings.len(),
        cwes,
        findings,
        persisted,
        cost_usd: 0.0,
        degradation: None,
    })
}

fn run_taint_cwe_select_value(
    input: &Value,
    target: &Path,
    runtime: Option<&dyn AgentRuntime>,
    model: Option<&str>,
) -> Result<Vec<TaintCweSelection>> {
    if let Some(cwes) = parse_taint_cwes_from_input(input)? {
        return Ok(cwes);
    }

    let runtime = runtime.context(
        "pipeline:taint-cwe-select requires the pi-agent-core runtime unless cwes are supplied explicitly",
    )?;
    let model = model.context(
        "pipeline:taint-cwe-select requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
    )?;
    let inventory = collect_agentic_repo_inventory(target, 60, 1024)?;
    let response = runtime.query_blocking(
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            TAINT_CWE_SELECT_SYSTEM_PROMPT.to_string(),
            build_taint_cwe_select_prompt(target, &inventory),
        )
        .with_tool_policy(agent_tool_policy_for_input(input)?),
    )?;
    parse_taint_cwe_select_response(response)
}

fn parse_taint_cwes_from_input(input: &Value) -> Result<Option<Vec<TaintCweSelection>>> {
    if let Some(value) = input.get("cwe").or_else(|| input.get("cwes")) {
        return parse_taint_cwes_value(value).map(Some);
    }
    Ok(None)
}

fn parse_taint_cwes_value(value: &Value) -> Result<Vec<TaintCweSelection>> {
    match value {
        Value::String(text) => Ok(text
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|id| TaintCweSelection {
                id: id.to_string(),
                name: id.to_string(),
                reason: "operator-supplied".to_string(),
            })
            .collect()),
        Value::Array(items) => {
            let mut cwes = Vec::new();
            for item in items {
                match item {
                    Value::String(id) => {
                        let id = id.trim();
                        if !id.is_empty() {
                            cwes.push(TaintCweSelection {
                                id: id.to_string(),
                                name: id.to_string(),
                                reason: "operator-supplied".to_string(),
                            });
                        }
                    }
                    Value::Object(object) => {
                        let id = read_object_string(object, &["id", "cwe"])
                            .context("taint-iris cwes entries require id or cwe")?;
                        let name =
                            read_object_string(object, &["name"]).unwrap_or_else(|| id.clone());
                        let reason = read_object_string(object, &["reason"])
                            .unwrap_or_else(|| "operator-supplied".to_string());
                        cwes.push(TaintCweSelection { id, name, reason });
                    }
                    _ => anyhow::bail!(
                        "taint-iris cwes must be a string, string array, or object array"
                    ),
                }
            }
            Ok(cwes)
        }
        _ => anyhow::bail!("taint-iris cwes must be a string or array"),
    }
}

fn parse_taint_cwe_select_response(response: AgentQueryResponse) -> Result<Vec<TaintCweSelection>> {
    let raw = match response.structured {
        Some(value) => value,
        None => parse_json_object_from_agent_text(&response.text).with_context(|| {
            "pipeline:taint-cwe-select expected pi-agent-core to return JSON with a cwes array"
        })?,
    };
    let Value::Object(object) = raw else {
        anyhow::bail!("pipeline:taint-cwe-select output parse failed: expected a JSON object");
    };
    let Some(value) = object.get("cwes") else {
        return Ok(Vec::new());
    };
    parse_taint_cwes_value(value)
}

fn parse_taint_iris_response(response: AgentQueryResponse) -> Result<Value> {
    match response.structured {
        Some(value) => Ok(value),
        None => parse_json_object_from_agent_text(&response.text).with_context(|| {
            "taint-iris:hunt expected pi-agent-core to return JSON with a findings array"
        }),
    }
}

fn build_taint_cwe_select_prompt(target: &Path, inventory: &[(String, String)]) -> String {
    let mut prompt = vec![
        "Select the CWE classes that deserve IRIS-style taint analysis for this repository."
            .to_string(),
        format!("Target: {}", target.display()),
        "Prefer source-to-sink classes such as injection, traversal, SSRF, deserialization, and unsafe code execution when the snippets support them.".to_string(),
        String::new(),
        "Repository inventory and snippets:".to_string(),
    ];
    if inventory.is_empty() {
        prompt.push("(no readable source snippets found)".to_string());
    }
    for (path, snippet) in inventory {
        prompt.push(format!("\n--- {path} ---\n{snippet}"));
    }
    prompt.join("\n")
}

fn build_taint_iris_prompt(
    target: &Path,
    cwes: &[TaintCweSelection],
    inventory: &[(String, String)],
    codeql_db: Option<&Path>,
    options: &TaintIrisInput,
) -> String {
    let mut prompt = vec![
        "Run bounded IRIS-style taint analysis over this repository.".to_string(),
        format!("Target: {}", target.display()),
        "Trace attacker-controlled sources to dangerous sinks. Use CodeQL reasoning where possible, but only report vulnerabilities supported by source evidence.".to_string(),
        String::new(),
        "CWE classes to analyze:".to_string(),
    ];
    for cwe in cwes {
        prompt.push(format!("- {}: {} ({})", cwe.id, cwe.name, cwe.reason));
    }
    prompt.push(String::new());
    match codeql_db {
        Some(path) => prompt.push(format!(
            "A CodeQL database appears to be available at {}. Generated query artifacts, if any, should stay under .kuzushi/runs/<run-id>/taint-iris.",
            path.display()
        )),
        None => prompt.push(
            "No CodeQL database was found under .kuzushi/codeql-db or .codeql/db; use grep/manual source tracing inside the target only."
                .to_string(),
        ),
    }
    if let Some(max_budget_usd) = options.max_budget_usd {
        prompt.push(format!(
            "Operator budget cap: ${max_budget_usd:.2}. Keep the analysis focused."
        ));
    }
    if let Some(prompt_override) = options.prompt_override.as_deref() {
        prompt.push(String::new());
        prompt.push("Operator prompt override:".to_string());
        prompt.push(prompt_override.to_string());
    }
    prompt.push(String::new());
    prompt.push("Repository inventory and snippets:".to_string());
    if inventory.is_empty() {
        prompt.push("(no readable source snippets found)".to_string());
    }
    for (path, snippet) in inventory {
        prompt.push(format!("\n--- {path} ---\n{snippet}"));
    }
    prompt.join("\n")
}

fn resolve_taint_codeql_db_path(target: &Path, workspace_root: Option<&Path>) -> Option<PathBuf> {
    let mut roots = vec![target.to_path_buf()];
    if let Some(workspace_root) = workspace_root {
        roots.push(workspace_root.to_path_buf());
    }
    roots.sort();
    roots.dedup();
    for root in roots {
        for candidate in [
            root.join(".kuzushi").join("codeql-db"),
            root.join(".codeql").join("db"),
        ] {
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn normalize_taint_iris_findings(
    raw: Value,
    target: &Path,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let findings_value = match raw {
        Value::Object(object) => object
            .get("findings")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        Value::Array(items) => Value::Array(items),
        _ => anyhow::bail!("taint-iris output parse failed: expected an object or findings array"),
    };
    let Value::Array(items) = findings_value else {
        anyhow::bail!("taint-iris output parse failed: findings must be an array");
    };

    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        let cwe = read_object_string(&object, &["cwe", "CWE"]).unwrap_or_else(|| "CWE".to_string());
        let rule_id = read_object_string(&object, &["ruleId", "rule_id"])
            .unwrap_or_else(|| format!("taint-iris/{}", sanitize_rule_segment(&cwe)));
        let file_path = normalize_agentic_file_path(
            read_object_string(&object, &["filePath", "file_path"])
                .unwrap_or_else(|| "unknown".to_string()),
            target,
        );
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .filter(|value| *value > 0)
            .unwrap_or(1) as u32;
        let severity = agentic_severity(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or("medium"),
        );
        let title = read_object_string(&object, &["title"]).unwrap_or_else(|| rule_id.clone());
        let detail = read_object_string(&object, &["message"]).unwrap_or_else(|| title.clone());
        let mut message = format!("{title}\n\n{detail}\nCWE: {cwe}");
        if let Some(trace) = read_object_string(&object, &["sourceSinkTrace", "source_sink_trace"])
        {
            message.push_str("\nSource-to-sink trace: ");
            message.push_str(trace.trim());
        }
        if let Some(confidence) = read_object_string(&object, &["confidence"]) {
            message.push_str("\nConfidence: ");
            message.push_str(confidence.trim());
        }
        if let Some(preconditions) =
            read_object_string(&object, &["exploitPreconditions", "exploit_preconditions"])
        {
            message.push_str("\nExploit preconditions: ");
            message.push_str(preconditions.trim());
        }
        if let Some(path_summary) = summarize_taint_path(&object) {
            message.push_str("\nTaint path:\n");
            message.push_str(&path_summary);
        }
        findings.push(Finding::new_tool(
            "taint-iris",
            rule_id,
            file_path,
            start_line,
            None,
            severity,
            message,
        ));
    }
    Ok(findings)
}

fn summarize_taint_path(object: &Map<String, Value>) -> Option<String> {
    let path = read_object_value(object, &["taintPath", "taint_path"])?.as_array()?;
    let mut lines = Vec::new();
    for item in path.iter().take(20) {
        let Value::Object(step) = item else {
            continue;
        };
        let file_path = read_object_string(step, &["filePath", "file_path"])
            .unwrap_or_else(|| "unknown".to_string());
        let line = read_object_u64(step, &["line", "startLine", "start_line"]).unwrap_or(1);
        let message = read_object_string(step, &["message"]).unwrap_or_default();
        let snippet = read_object_string(step, &["snippet"]).unwrap_or_default();
        let mut rendered = format!("- {file_path}:{line}");
        if !message.is_empty() {
            rendered.push_str(": ");
            rendered.push_str(&message);
        }
        if !snippet.is_empty() {
            rendered.push_str(" | ");
            rendered.push_str(&snippet);
        }
        lines.push(rendered);
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

fn sanitize_rule_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').to_string()
}

fn persist_taint_iris_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<TaintIrisPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(Some(TaintIrisPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TaintIrisNextMode {
    Plan,
    Hunt,
}

impl TaintIrisNextMode {
    fn from_input(input: &Value) -> Result<Self> {
        match input.get("mode").and_then(Value::as_str).unwrap_or("plan") {
            "plan" => Ok(Self::Plan),
            "hunt" => Ok(Self::Hunt),
            other => anyhow::bail!(
                "taint-iris-next:hunt mode must be \"plan\" or \"hunt\", got {other:?}"
            ),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Hunt => "hunt",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextCaps {
    max_catalog_entries: usize,
    max_candidates_per_cwe: usize,
    max_evidence_per_cwe: usize,
    max_files_per_query: usize,
    max_specs_per_cwe: usize,
    max_agent_findings: usize,
    codeql_analyze_timeout_ms: usize,
    min_evidence_level: String,
}

#[derive(Debug, Clone)]
struct TaintIrisNextInput {
    mode: TaintIrisNextMode,
    backend: String,
    languages: Vec<String>,
    caps: TaintIrisNextCaps,
    max_budget_usd: Option<f64>,
}

impl TaintIrisNextInput {
    fn from_tool_input(input: &Value) -> Result<Self> {
        let mode = TaintIrisNextMode::from_input(input)?;
        let backend =
            optional_taint_next_string(input, &["backend"])?.unwrap_or_else(|| "auto".to_string());
        if !matches!(
            backend.as_str(),
            "auto" | "structural" | "semgrep" | "codeql" | "joern" | "language"
        ) {
            anyhow::bail!(
                "taint-iris-next:hunt backend must be auto, structural, semgrep, codeql, joern, or language"
            );
        }
        let languages = string_list_input(input, &["languages"])?
            .unwrap_or_default()
            .into_iter()
            .map(|language| normalize_taint_next_language(&language))
            .filter(|language| !language.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let min_evidence_level =
            optional_taint_next_string(input, &["minEvidenceLevel", "min_evidence_level"])?
                .unwrap_or_else(|| "linked".to_string());
        if !matches!(min_evidence_level.as_str(), "path" | "linked" | "candidate") {
            anyhow::bail!(
                "taint-iris-next:hunt minEvidenceLevel must be \"path\", \"linked\", or \"candidate\""
            );
        }
        let caps = TaintIrisNextCaps {
            max_catalog_entries: positive_usize_input(
                input,
                &[
                    "maxCatalogEntries",
                    "maxCwes",
                    "max_catalog_entries",
                    "max_cwes",
                ],
                "taint-iris-next:hunt maxCatalogEntries",
            )?
            .unwrap_or(24)
            .min(100),
            max_candidates_per_cwe: positive_usize_input(
                input,
                &["maxCandidatesPerCwe", "max_candidates_per_cwe"],
                "taint-iris-next:hunt maxCandidatesPerCwe",
            )?
            .unwrap_or(24)
            .min(200),
            max_evidence_per_cwe: positive_usize_input(
                input,
                &["maxEvidencePerCwe", "max_evidence_per_cwe"],
                "taint-iris-next:hunt maxEvidencePerCwe",
            )?
            .unwrap_or(12)
            .min(200),
            max_files_per_query: positive_usize_input(
                input,
                &["maxFilesPerQuery", "max_files_per_query"],
                "taint-iris-next:hunt maxFilesPerQuery",
            )?
            .unwrap_or(25)
            .min(500),
            max_specs_per_cwe: positive_usize_input(
                input,
                &["maxSpecsPerCwe", "max_specs_per_cwe"],
                "taint-iris-next:hunt maxSpecsPerCwe",
            )?
            .unwrap_or(16)
            .min(200),
            max_agent_findings: positive_usize_input(
                input,
                &[
                    "maxAgentFindings",
                    "max_agent_findings",
                    "maxFindings",
                    "max_findings",
                ],
                "taint-iris-next:hunt maxAgentFindings",
            )?
            .unwrap_or(20)
            .min(250),
            codeql_analyze_timeout_ms: positive_usize_input(
                input,
                &["codeqlAnalyzeTimeoutMs", "codeql_analyze_timeout_ms"],
                "taint-iris-next:hunt codeqlAnalyzeTimeoutMs",
            )?
            .unwrap_or(180_000)
            .clamp(30_000, 900_000),
            min_evidence_level,
        };
        Ok(Self {
            mode,
            backend,
            languages,
            caps,
            max_budget_usd: positive_f64_input(
                input,
                &["maxBudgetUsd", "max_budget_usd"],
                "taint-iris-next:hunt maxBudgetUsd",
            )?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct TaintIrisNextCatalogEntry {
    cwe: &'static str,
    name: &'static str,
    taint_class: &'static str,
    languages: &'static [&'static str],
    source_signals: &'static [&'static str],
    sink_signals: &'static [&'static str],
    sanitizer_signals: &'static [&'static str],
    structural_queries: &'static [&'static str],
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextRankedCatalogEntry {
    cwe: String,
    name: String,
    taint_class: String,
    languages: Vec<String>,
    source_signals: Vec<String>,
    sink_signals: Vec<String>,
    sanitizer_signals: Vec<String>,
    structural_queries: Vec<String>,
    score: i32,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextStructuralQuery {
    id: String,
    cwe: String,
    taint_class: String,
    role: String,
    pattern: String,
    languages: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextArtifactStatus {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextBackendChoice {
    requested: String,
    selected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    codeql_db_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    corroborate_with_codeql: Option<bool>,
    structural_tool: String,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct TaintIrisNextPlan {
    target: PathBuf,
    scan_root: PathBuf,
    repo_root: PathBuf,
    mode: TaintIrisNextMode,
    caps: TaintIrisNextCaps,
    languages: Vec<String>,
    context_status: TaintIrisNextArtifactStatus,
    threat_model_status: TaintIrisNextArtifactStatus,
    repo_context: Option<Value>,
    threat_model: Option<Value>,
    catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    structural_queries: Vec<TaintIrisNextStructuralQuery>,
    prompt_catalog: String,
    backend: TaintIrisNextBackendChoice,
    max_budget_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextCandidate {
    id: String,
    cwe: String,
    taint_class: String,
    track: String,
    role: String,
    kind: String,
    pattern: String,
    file_path: String,
    line: u32,
    snippet: String,
    language: String,
    confidence: String,
    catalog_signal: String,
    source: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextEvidence {
    cwe: String,
    taint_class: String,
    track: String,
    role: String,
    pattern: String,
    file_path: String,
    line: u32,
    snippet: String,
    language: String,
    confidence: String,
    catalog_signal: String,
    evidence_level: String,
    source: String,
    candidate_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    linked_story_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextLabeledSpec {
    id: String,
    cwe: String,
    taint_class: String,
    track: String,
    role: String,
    kind: String,
    api_name: String,
    pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    confidence: String,
    rationale: String,
    catalog_signal: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextLinkedStory {
    id: String,
    cwe: String,
    taint_class: String,
    track: String,
    evidence_level: String,
    file_path: String,
    language: String,
    source_candidate_id: String,
    sink_candidate_id: String,
    source_line: u32,
    sink_line: u32,
    shared_tokens: Vec<String>,
    rationale: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextEvidenceResult {
    backend: String,
    tool: String,
    evidence: Vec<TaintIrisNextEvidence>,
    candidates: Vec<TaintIrisNextCandidate>,
    linked_stories: Vec<TaintIrisNextLinkedStory>,
    labeled_specs: Vec<TaintIrisNextLabeledSpec>,
    query_count: usize,
    candidate_counts: BTreeMap<String, usize>,
    labeled_spec_counts: BTreeMap<String, usize>,
    linked_story_count: usize,
    backend_path_count: usize,
    structural_engine: String,
    triage_summary: Value,
    outcome: String,
    warnings: Vec<String>,
    artifacts: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextPersistedRun {
    run_id: String,
    findings_db: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaintIrisNextReport {
    target: String,
    status: String,
    mode: String,
    count: usize,
    findings: Vec<Finding>,
    review_candidates: Vec<Finding>,
    selected_cwes: Vec<Value>,
    persisted: Option<TaintIrisNextPersistedRun>,
    cost_usd: f64,
    #[serde(skip)]
    ok: bool,
    #[serde(skip)]
    output: String,
    #[serde(skip)]
    data: Value,
}

impl TaintIrisNextReport {
    fn to_tool_json(&self) -> Value {
        let mut data = self.data.clone();
        if let Value::Object(object) = &mut data {
            object.insert("persisted".to_string(), json!(self.persisted));
        }
        json!({
            "ok": self.ok,
            "output": self.output,
            "data": data,
            "costUsd": self.cost_usd,
        })
    }
}

#[derive(Debug, Clone)]
struct TaintIrisNextAgentResult {
    agent_status: String,
    selected_cwes: Vec<Value>,
    findings: Vec<Finding>,
    review_candidates: Vec<Finding>,
    triage: Vec<Value>,
    triage_summary: Value,
    outcome: String,
    raw_output: Value,
    structured_output_valid: bool,
    structured_output_retry_count: usize,
    parse_error: Option<String>,
    result_text_excerpt: Option<String>,
    warnings: Vec<String>,
    cost_usd: f64,
}

const TAINT_IRIS_NEXT_ANY: &[&str] = &["any"];
const TAINT_IRIS_NEXT_WEB: &[&str] = &[
    "javascript",
    "typescript",
    "python",
    "ruby",
    "php",
    "java",
    "go",
    "csharp",
];
const TAINT_IRIS_NEXT_NATIVE: &[&str] = &["c", "cpp", "go", "rust"];

const TAINT_IRIS_NEXT_CATALOG: &[TaintIrisNextCatalogEntry] = &[
    TaintIrisNextCatalogEntry {
        cwe: "CWE-22",
        name: "Path Traversal",
        taint_class: "path-traversal",
        languages: TAINT_IRIS_NEXT_ANY,
        source_signals: &["req.query", "request path", "filename", "archive entry"],
        sink_signals: &["readFile", "writeFile", "open(", "File.open", "send_file"],
        sanitizer_signals: &["basename", "realpath", "canonicalize", "safe_join"],
        structural_queries: &["../", "path.join", "readFile", "PathBuf", "send_file"],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-78",
        name: "OS Command Injection",
        taint_class: "os-command-injection",
        languages: TAINT_IRIS_NEXT_ANY,
        source_signals: &[
            "req.query",
            "request.",
            "process.argv",
            "os.environ",
            "env::args",
        ],
        sink_signals: &[
            "child_process.exec",
            "subprocess",
            "Popen",
            "Command::new",
            "shell=True",
        ],
        sanitizer_signals: &["execFile", "argument vector", "allowlist", "shellwords"],
        structural_queries: &[
            "child_process",
            "Runtime.exec",
            "subprocess",
            "Popen",
            "shell=True",
        ],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-79",
        name: "Cross-Site Scripting",
        taint_class: "xss",
        languages: TAINT_IRIS_NEXT_WEB,
        source_signals: &[
            "req.query",
            "request.body",
            "query parameter",
            "profile field",
        ],
        sink_signals: &[
            "innerHTML",
            "dangerouslySetInnerHTML",
            "res.send",
            "html_safe",
            "render(",
        ],
        sanitizer_signals: &["escapeHtml", "sanitize", "DOMPurify"],
        structural_queries: &[
            "innerHTML",
            "dangerouslySetInnerHTML",
            "res.send",
            "html_safe",
        ],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-89",
        name: "SQL Injection",
        taint_class: "sql-injection",
        languages: TAINT_IRIS_NEXT_ANY,
        source_signals: &[
            "req.query",
            "request.args",
            "request.query",
            "route parameter",
            "params[",
        ],
        sink_signals: &[
            "query(",
            "execute(",
            "find_by_sql",
            "Sequelize.literal",
            "raw(",
        ],
        sanitizer_signals: &[
            "prepared statement",
            "bind parameter",
            "parameterized query",
        ],
        structural_queries: &["SELECT", "WHERE", "db.query", "execute(", "raw("],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-94",
        name: "Code Injection",
        taint_class: "code-injection",
        languages: &["javascript", "typescript", "python", "ruby", "php", "java"],
        source_signals: &[
            "req.query",
            "request.",
            "template expression",
            "workflow expression",
        ],
        sink_signals: &["eval(", "Function(", "exec(", "compile(", "class_eval"],
        sanitizer_signals: &["allowlist expression", "sandbox", "parser restriction"],
        structural_queries: &["eval(", "new Function", "compile(", "class_eval"],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-117",
        name: "Log Injection",
        taint_class: "log-injection",
        languages: TAINT_IRIS_NEXT_ANY,
        source_signals: &["req.query", "username", "header", "job payload"],
        sink_signals: &[
            "logger.",
            "log.info",
            "println",
            "tracing::",
            "Rails.logger",
        ],
        sanitizer_signals: &["strip CRLF", "structured logging", "JSON encoding"],
        structural_queries: &["logger.", "log.info", "println", "tracing::"],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-190",
        name: "Integer Overflow",
        taint_class: "integer-overflow",
        languages: TAINT_IRIS_NEXT_NATIVE,
        source_signals: &["length", "size", "count", "offset"],
        sink_signals: &["malloc", "resize", "capacity", "copy", "slice"],
        sanitizer_signals: &["checked_add", "saturating", "bounds check"],
        structural_queries: &["checked_add", "saturating_", "malloc", "resize", "capacity"],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-502",
        name: "Deserialization of Untrusted Data",
        taint_class: "deserialization",
        languages: TAINT_IRIS_NEXT_ANY,
        source_signals: &["req.body", "request body", "message payload", "cookie"],
        sink_signals: &[
            "deserialize",
            "pickle.loads",
            "yaml.load",
            "Marshal.load",
            "readObject",
        ],
        sanitizer_signals: &["safe_load", "allowed classes", "schema validation"],
        structural_queries: &["pickle.loads", "yaml.load", "deserialize", "readObject"],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-611",
        name: "XML External Entity",
        taint_class: "xxe",
        languages: TAINT_IRIS_NEXT_WEB,
        source_signals: &["request body", "xml upload", "SOAP payload"],
        sink_signals: &[
            "DocumentBuilderFactory",
            "SAXParserFactory",
            "lxml",
            "xml2js",
        ],
        sanitizer_signals: &["disable doctype", "external entity disabled"],
        structural_queries: &[
            "DocumentBuilderFactory",
            "SAXParserFactory",
            "lxml",
            "xml2js",
        ],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-862",
        name: "Missing Authorization",
        taint_class: "missing-authorization",
        languages: TAINT_IRIS_NEXT_WEB,
        source_signals: &["route", "handler", "controller", "mutation"],
        sink_signals: &["delete", "update", "admin", "owner", "tenant"],
        sanitizer_signals: &["authorize", "policy", "permission", "current_user"],
        structural_queries: &["router.", "delete", "update", "authorize", "current_user"],
    },
    TaintIrisNextCatalogEntry {
        cwe: "CWE-918",
        name: "Server-Side Request Forgery",
        taint_class: "ssrf",
        languages: TAINT_IRIS_NEXT_WEB,
        source_signals: &[
            "req.query.url",
            "request url",
            "webhook URL",
            "callback URL",
        ],
        sink_signals: &["fetch(", "axios.", "http.get", "requests.get", "Net::HTTP"],
        sanitizer_signals: &["URL allowlist", "block private IP", "hostname allowlist"],
        structural_queries: &["fetch(", "axios.", "http.get", "requests.get", "Net::HTTP"],
    },
];

const TAINT_IRIS_NEXT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Taint IRIS Next agent.
Return only strict JSON matching:
{"selectedCwes":[{"cwe":"CWE-89","reason":"why","catalogSignals":["sink: query"],"sourceSpec":"source","sinkSpec":"sink","sanitizerSpec":"","customCweRationale":""}],"findings":[{"title":"short title","cwe":"CWE-89","severity":"critical|high|medium|low|info","confidence":"high|medium|low","evidenceLevel":"path|linked|candidate","filePath":"relative/path","startLine":1,"message":"detail","sourceSinkTrace":"source -> sink","catalogSignals":["source: req.query","sink: query"],"customCweRationale":"","taintPath":[{"filePath":"relative/path","line":1,"message":"source|step|sink","snippet":"code"}]}],"triage":[{"status":"finding|candidate|rejected","cwe":"CWE-89","evidenceLevel":"path|linked|candidate","rationale":"why","filePath":"relative/path","line":1,"catalogSignals":["sink: query"]}],"notes":[]}.
Select CWE themes from the bounded catalog unless customCweRationale is present. Report only concrete evidence-backed findings."#;

fn run_taint_iris_next_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<TaintIrisNextReport> {
    let target = resolve_tool_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "taint-iris-next:hunt target is not a directory: {}",
            target.display()
        );
    }
    let options = TaintIrisNextInput::from_tool_input(input)?;
    let plan = build_taint_iris_next_plan(&target, options)?;

    if !taint_iris_next_has_required_context(&plan) {
        let output = render_taint_iris_next_missing_context(&plan);
        return Ok(TaintIrisNextReport {
            target: plan.target.display().to_string(),
            status: "missing-context".to_string(),
            mode: plan.mode.as_str().to_string(),
            count: 0,
            findings: Vec::new(),
            review_candidates: Vec::new(),
            selected_cwes: Vec::new(),
            persisted: None,
            cost_usd: 0.0,
            ok: false,
            output: output.clone(),
            data: json!({
                "status": "missing-context",
                "target": plan.target.display().to_string(),
                "contextStatus": plan.context_status,
                "threatModelStatus": plan.threat_model_status,
                "missing": {
                    "context": !plan.context_status.ok,
                    "threatModel": !plan.threat_model_status.ok,
                },
            }),
        });
    }

    let evidence = extract_taint_iris_next_evidence(&plan)?;
    let agent_prompt = build_taint_iris_next_agent_prompt(&plan, &evidence);

    if plan.mode == TaintIrisNextMode::Plan {
        let output = render_taint_iris_next_output(&plan, &evidence, None);
        let data = taint_iris_next_base_data(&plan, &evidence, "planned", &agent_prompt);
        return Ok(TaintIrisNextReport {
            target: plan.target.display().to_string(),
            status: "planned".to_string(),
            mode: "plan".to_string(),
            count: 0,
            findings: Vec::new(),
            review_candidates: Vec::new(),
            selected_cwes: Vec::new(),
            persisted: None,
            cost_usd: 0.0,
            ok: true,
            output,
            data,
        });
    }

    let runtime = runtime.context(
        "taint-iris-next:hunt requires the pi-agent-core runtime in hunt mode. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = optional_nonempty_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context(
            "taint-iris-next:hunt requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
        )?;
    let mut agent = run_taint_iris_next_agent(
        &plan,
        &evidence,
        &agent_prompt,
        runtime,
        &model,
        agent_tool_policy_for_input(input)?,
    )?;
    let mut findings = agent.findings.clone();
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SourceSinkLinked)?;
        agent.findings = findings;
    }
    let persisted = persist_taint_iris_next_findings(&target, &agent.findings, ctx)?;
    let output = render_taint_iris_next_output(&plan, &evidence, Some(&agent));
    let status = if agent.outcome == "agent-output-invalid" {
        if agent.findings.is_empty() {
            "agent-output-invalid"
        } else {
            "hunted-with-agent-output-invalid"
        }
    } else {
        "hunted"
    };
    let mut data = taint_iris_next_base_data(&plan, &evidence, status, &agent_prompt);
    if let Value::Object(object) = &mut data {
        object.insert("outcome".to_string(), json!(agent.outcome));
        object.insert("agentStatus".to_string(), json!(agent.agent_status));
        object.insert("selectedCwes".to_string(), json!(agent.selected_cwes));
        object.insert("findings".to_string(), json!(agent.findings));
        object.insert(
            "reviewCandidates".to_string(),
            json!(agent.review_candidates),
        );
        object.insert("triage".to_string(), json!(agent.triage));
        object.insert("triageSummary".to_string(), agent.triage_summary.clone());
        object.insert("warnings".to_string(), json!(agent.warnings));
        object.insert("rawAgentOutput".to_string(), agent.raw_output.clone());
        object.insert(
            "structuredOutputValid".to_string(),
            json!(agent.structured_output_valid),
        );
        object.insert(
            "structuredOutputRetryCount".to_string(),
            json!(agent.structured_output_retry_count),
        );
        if let Some(parse_error) = &agent.parse_error {
            object.insert("parseError".to_string(), json!(parse_error));
        }
        if let Some(excerpt) = &agent.result_text_excerpt {
            object.insert("resultTextExcerpt".to_string(), json!(excerpt));
        }
        object.insert(
            "stats".to_string(),
            json!({
                "totalFindings": agent.findings.len().saturating_sub(agent.review_candidates.len()),
                "totalReviewCandidates": agent.review_candidates.len(),
                "totalCandidates": evidence.candidates.len(),
                "totalLinkedStories": evidence.linked_story_count,
                "backendPathCount": evidence.backend_path_count,
                "totalCostUsd": agent.cost_usd,
            }),
        );
    }

    Ok(TaintIrisNextReport {
        target: plan.target.display().to_string(),
        status: status.to_string(),
        mode: "hunt".to_string(),
        count: agent
            .findings
            .len()
            .saturating_sub(agent.review_candidates.len()),
        findings: agent.findings.clone(),
        review_candidates: agent.review_candidates.clone(),
        selected_cwes: agent.selected_cwes.clone(),
        persisted,
        cost_usd: agent.cost_usd,
        ok: status != "agent-output-invalid",
        output,
        data,
    })
}

fn build_taint_iris_next_plan(
    target: &Path,
    options: TaintIrisNextInput,
) -> Result<TaintIrisNextPlan> {
    let repo_root = target.to_path_buf();
    let context = load_taint_iris_next_context(&repo_root);
    let threat_model = load_taint_iris_next_threat_model(&repo_root);
    let mut languages = options.languages.clone();
    languages.extend(taint_iris_next_context_languages(context.value.as_ref()));
    languages.extend(detect_taint_iris_next_languages(target)?);
    languages = languages
        .into_iter()
        .map(|language| normalize_taint_next_language(&language))
        .filter(|language| !language.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let threat_cwes = collect_taint_iris_next_cwes(threat_model.value.as_ref());
    let context_keywords = taint_iris_next_context_keywords(context.value.as_ref(), target)?;
    let catalog = rank_taint_iris_next_catalog(&languages, &threat_cwes, &context_keywords)
        .into_iter()
        .take(options.caps.max_catalog_entries)
        .collect::<Vec<_>>();
    let structural_queries = build_taint_iris_next_structural_queries(&catalog);
    let prompt_catalog = render_taint_iris_next_catalog(&catalog);
    let backend = choose_taint_iris_next_backend(&options.backend, &repo_root);

    Ok(TaintIrisNextPlan {
        target: target.to_path_buf(),
        scan_root: target.to_path_buf(),
        repo_root,
        mode: options.mode,
        caps: options.caps,
        languages,
        context_status: context.status,
        threat_model_status: threat_model.status,
        repo_context: context.value,
        threat_model: threat_model.value,
        catalog,
        structural_queries,
        prompt_catalog,
        backend,
        max_budget_usd: options.max_budget_usd,
    })
}

struct TaintIrisNextArtifactLoad {
    status: TaintIrisNextArtifactStatus,
    value: Option<Value>,
}

fn load_taint_iris_next_context(repo_root: &Path) -> TaintIrisNextArtifactLoad {
    let path = repo_root.join(".kuzushi").join("context-snapshot.json");
    match fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(value) => TaintIrisNextArtifactLoad {
                status: TaintIrisNextArtifactStatus {
                    ok: true,
                    path: Some(path.display().to_string()),
                    reason: "loaded".to_string(),
                },
                value: Some(value),
            },
            Err(error) => TaintIrisNextArtifactLoad {
                status: TaintIrisNextArtifactStatus {
                    ok: false,
                    path: Some(path.display().to_string()),
                    reason: format!("invalid JSON: {error}"),
                },
                value: None,
            },
        },
        Err(_) => TaintIrisNextArtifactLoad {
            status: TaintIrisNextArtifactStatus {
                ok: false,
                path: Some(path.display().to_string()),
                reason: "not found".to_string(),
            },
            value: None,
        },
    }
}

fn load_taint_iris_next_threat_model(repo_root: &Path) -> TaintIrisNextArtifactLoad {
    let path = repo_root.join(".kuzushi").join("threat-model.json");
    match fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(value) => TaintIrisNextArtifactLoad {
                status: TaintIrisNextArtifactStatus {
                    ok: true,
                    path: Some(path.display().to_string()),
                    reason: "loaded".to_string(),
                },
                value: Some(value),
            },
            Err(error) => TaintIrisNextArtifactLoad {
                status: TaintIrisNextArtifactStatus {
                    ok: false,
                    path: Some(path.display().to_string()),
                    reason: format!("invalid JSON: {error}"),
                },
                value: None,
            },
        },
        Err(_) => TaintIrisNextArtifactLoad {
            status: TaintIrisNextArtifactStatus {
                ok: false,
                path: Some(path.display().to_string()),
                reason: "not found".to_string(),
            },
            value: None,
        },
    }
}

fn taint_iris_next_context_languages(context: Option<&Value>) -> Vec<String> {
    context
        .and_then(|value| value.pointer("/repoContext/languages"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(normalize_taint_next_language)
                .filter(|language| !language.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn taint_iris_next_context_keywords(context: Option<&Value>, target: &Path) -> Result<String> {
    let mut parts = Vec::new();
    if let Some(context) = context {
        if let Some(repo_context) = context.get("repoContext") {
            parts.push(repo_context.to_string());
        }
    }
    for file in [
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "go.mod",
        "pom.xml",
    ] {
        let path = target.join(file);
        if let Ok(raw) = fs::read_to_string(path) {
            parts.push(raw);
        }
    }
    Ok(parts.join("\n").to_ascii_lowercase())
}

fn collect_taint_iris_next_cwes(value: Option<&Value>) -> BTreeSet<String> {
    let mut cwes = BTreeSet::new();
    if let Some(value) = value {
        collect_taint_iris_next_cwes_inner(value, &mut cwes);
    }
    cwes
}

fn collect_taint_iris_next_cwes_inner(value: &Value, cwes: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            for token in text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-') {
                let normalized = normalize_taint_next_cwe(token);
                if normalized.starts_with("CWE-") {
                    cwes.insert(normalized);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_taint_iris_next_cwes_inner(item, cwes);
            }
        }
        Value::Object(object) => {
            for value in object.values() {
                collect_taint_iris_next_cwes_inner(value, cwes);
            }
        }
        _ => {}
    }
}

fn rank_taint_iris_next_catalog(
    languages: &[String],
    threat_cwes: &BTreeSet<String>,
    context_keywords: &str,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    let language_set = languages.iter().cloned().collect::<BTreeSet<_>>();
    let has_web = context_keywords.contains("express")
        || context_keywords.contains("fastapi")
        || context_keywords.contains("django")
        || context_keywords.contains("route")
        || context_keywords.contains("handler");
    let has_db = context_keywords.contains("sql")
        || context_keywords.contains("postgres")
        || context_keywords.contains("mysql")
        || context_keywords.contains("sqlite")
        || context_keywords.contains("prisma")
        || context_keywords.contains("sqlalchemy");

    let mut entries = TAINT_IRIS_NEXT_CATALOG
        .iter()
        .map(|entry| {
            let mut score = 0;
            let mut reasons = Vec::new();
            if threat_cwes.contains(entry.cwe) {
                score += 100;
                reasons.push("threat-model CWE".to_string());
            }
            if entry.languages.contains(&"any")
                || entry
                    .languages
                    .iter()
                    .any(|language| language_set.contains(*language))
            {
                score += 25;
                reasons.push("language match".to_string());
            }
            if entry.languages.contains(&"any") {
                score += 5;
                reasons.push("language agnostic".to_string());
            }
            if has_db && entry.taint_class.contains("sql") {
                score += 35;
                reasons.push("database/ORM context".to_string());
            }
            if has_web
                && matches!(
                    entry.taint_class,
                    "xss" | "ssrf" | "missing-authorization" | "sql-injection" | "path-traversal"
                )
            {
                score += 20;
                reasons.push("web entrypoint context".to_string());
            }
            let hits = entry
                .source_signals
                .iter()
                .chain(entry.sink_signals.iter())
                .chain(entry.structural_queries.iter())
                .filter(|signal| context_keywords.contains(&signal.to_ascii_lowercase()))
                .count() as i32;
            if hits > 0 {
                score += (hits * 5).min(30);
                reasons.push("context keyword overlap".to_string());
            }
            TaintIrisNextRankedCatalogEntry {
                cwe: entry.cwe.to_string(),
                name: entry.name.to_string(),
                taint_class: entry.taint_class.to_string(),
                languages: entry
                    .languages
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                source_signals: entry
                    .source_signals
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                sink_signals: entry
                    .sink_signals
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                sanitizer_signals: entry
                    .sanitizer_signals
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                structural_queries: entry
                    .structural_queries
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                score,
                reasons,
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| cwe_number(&left.cwe).cmp(&cwe_number(&right.cwe)))
    });
    entries
}

fn build_taint_iris_next_structural_queries(
    entries: &[TaintIrisNextRankedCatalogEntry],
) -> Vec<TaintIrisNextStructuralQuery> {
    let mut seen = BTreeSet::new();
    let mut queries = Vec::new();
    for entry in entries {
        for (role, patterns) in [
            ("source", &entry.source_signals),
            ("sink", &entry.sink_signals),
            ("sanitizer", &entry.sanitizer_signals),
            ("structural", &entry.structural_queries),
        ] {
            for pattern in patterns {
                let trimmed = pattern.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let key = format!("{}:{}:{}", entry.cwe, role, trimmed.to_ascii_lowercase());
                if !seen.insert(key) {
                    continue;
                }
                queries.push(TaintIrisNextStructuralQuery {
                    id: format!(
                        "{}-{}-{}",
                        entry.cwe.to_ascii_lowercase(),
                        role,
                        queries.len() + 1
                    ),
                    cwe: entry.cwe.clone(),
                    taint_class: entry.taint_class.clone(),
                    role: role.to_string(),
                    pattern: trimmed.to_string(),
                    languages: entry.languages.clone(),
                });
            }
        }
    }
    queries
}

fn render_taint_iris_next_catalog(entries: &[TaintIrisNextRankedCatalogEntry]) -> String {
    let mut lines = vec![
        "## CWE Candidate Catalog".to_string(),
        "The agent must choose CWE themes from this catalog unless it provides customCweRationale."
            .to_string(),
        "For every selected catalog CWE, cite at least one source/sink/sanitizer/query signal."
            .to_string(),
        String::new(),
    ];
    for entry in entries {
        lines.push(format!(
            "- {}: {} [{}] score={}",
            entry.cwe, entry.name, entry.taint_class, entry.score
        ));
        lines.push(format!("  languages: {}", entry.languages.join(", ")));
        lines.push(format!(
            "  sources: {}",
            entry
                .source_signals
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
        lines.push(format!(
            "  sinks: {}",
            entry
                .sink_signals
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
        if !entry.sanitizer_signals.is_empty() {
            lines.push(format!(
                "  sanitizers: {}",
                entry
                    .sanitizer_signals
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        lines.push(format!(
            "  structural queries: {}",
            entry
                .structural_queries
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    lines.join("\n")
}

fn choose_taint_iris_next_backend(requested: &str, repo_root: &Path) -> TaintIrisNextBackendChoice {
    let codeql_db = [
        repo_root.join(".kuzushi").join("codeql-db"),
        repo_root.join(".codeql").join("db"),
    ]
    .into_iter()
    .find(|path| path.exists());
    let mut warnings = Vec::new();
    let selected = match requested {
        "codeql" if codeql_db.is_some() => "codeql",
        "codeql" => {
            warnings.push(
                "backend=codeql requested, but no existing CodeQL DB was found; using structural evidence"
                    .to_string(),
            );
            "structural"
        }
        "semgrep" | "joern" | "language" => {
            warnings.push(format!(
                "backend={requested} is not a Rust execution backend in this cutover; using structural evidence"
            ));
            "structural"
        }
        _ => "structural",
    };
    TaintIrisNextBackendChoice {
        requested: requested.to_string(),
        selected: selected.to_string(),
        codeql_db_path: codeql_db.as_ref().map(|path| path.display().to_string()),
        corroborate_with_codeql: codeql_db.as_ref().map(|_| true),
        structural_tool: "rg".to_string(),
        warnings,
    }
}

fn taint_iris_next_has_required_context(plan: &TaintIrisNextPlan) -> bool {
    plan.context_status.ok || !plan.languages.is_empty()
}

fn render_taint_iris_next_missing_context(plan: &TaintIrisNextPlan) -> String {
    [
        "Taint IRIS Next needs usable Kuzushi context or a source-file inventory before it hunts."
            .to_string(),
        format!(
            "context: {} ({})",
            if plan.context_status.ok { "loaded" } else { "missing" },
            plan.context_status.reason
        ),
        format!(
            "file inventory languages: {}",
            if plan.languages.is_empty() {
                "none detected".to_string()
            } else {
                plan.languages.join(", ")
            }
        ),
        format!(
            "threat model: {} ({}) (warning only)",
            if plan.threat_model_status.ok {
                "loaded"
            } else {
                "warning"
            },
            plan.threat_model_status.reason
        ),
        String::new(),
        "Run context:build, then rerun taint-iris-next. A threat model improves ranking but is not a hard blocker.".to_string(),
    ]
    .join("\n")
}

fn extract_taint_iris_next_evidence(
    plan: &TaintIrisNextPlan,
) -> Result<TaintIrisNextEvidenceResult> {
    let files = collect_taint_iris_next_source_files(&plan.scan_root, 500, 128 * 1024)?;
    let mut candidates = Vec::new();
    let mut seen_candidate = BTreeSet::new();
    let mut per_query_files: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut per_cwe_candidates: BTreeMap<String, usize> = BTreeMap::new();

    for source_file in files {
        for (line_index, line) in source_file.lines.iter().enumerate() {
            let line_number = (line_index + 1) as u32;
            let lower = line.to_ascii_lowercase();
            for query in &plan.structural_queries {
                let query_key = format!("{}:{}:{}", query.cwe, query.role, query.pattern);
                let files_for_query = per_query_files.entry(query_key).or_default();
                if files_for_query.len() >= plan.caps.max_files_per_query
                    && !files_for_query.contains(&source_file.relative_path)
                {
                    continue;
                }
                if !taint_iris_next_line_matches(&lower, &query.pattern) {
                    continue;
                }
                let cwe_count = per_cwe_candidates.entry(query.cwe.clone()).or_default();
                if *cwe_count >= plan.caps.max_candidates_per_cwe {
                    continue;
                }
                let id = format!(
                    "{}:{}:{}:{}",
                    query.cwe, query.role, source_file.relative_path, line_number
                );
                if !seen_candidate.insert(id.clone()) {
                    continue;
                }
                files_for_query.insert(source_file.relative_path.clone());
                *cwe_count += 1;
                candidates.push(TaintIrisNextCandidate {
                    id,
                    cwe: query.cwe.clone(),
                    taint_class: query.taint_class.clone(),
                    track: if query.taint_class.contains("authorization") {
                        "control".to_string()
                    } else {
                        "taint".to_string()
                    },
                    role: query.role.clone(),
                    kind: taint_iris_next_kind_for_role(&query.role).to_string(),
                    pattern: query.pattern.clone(),
                    file_path: source_file.relative_path.clone(),
                    line: line_number,
                    snippet: line.trim().to_string(),
                    language: source_file.language.clone(),
                    confidence: if matches!(query.role.as_str(), "source" | "sink") {
                        "medium".to_string()
                    } else {
                        "low".to_string()
                    },
                    catalog_signal: format!("{}: {}", query.role, query.pattern),
                    source: "structural".to_string(),
                });
            }
        }
    }

    let linked_stories = build_taint_iris_next_linked_stories(&candidates);
    let linked_by_candidate = linked_stories
        .iter()
        .flat_map(|story| {
            [
                (story.source_candidate_id.clone(), story.id.clone()),
                (story.sink_candidate_id.clone(), story.id.clone()),
            ]
        })
        .collect::<BTreeMap<_, _>>();
    let mut evidence = candidates
        .iter()
        .map(|candidate| TaintIrisNextEvidence {
            cwe: candidate.cwe.clone(),
            taint_class: candidate.taint_class.clone(),
            track: candidate.track.clone(),
            role: candidate.role.clone(),
            pattern: candidate.pattern.clone(),
            file_path: candidate.file_path.clone(),
            line: candidate.line,
            snippet: candidate.snippet.clone(),
            language: candidate.language.clone(),
            confidence: candidate.confidence.clone(),
            catalog_signal: candidate.catalog_signal.clone(),
            evidence_level: linked_by_candidate
                .get(&candidate.id)
                .map(|_| "linked")
                .unwrap_or("candidate")
                .to_string(),
            source: candidate.source.clone(),
            candidate_id: candidate.id.clone(),
            linked_story_id: linked_by_candidate.get(&candidate.id).cloned(),
        })
        .collect::<Vec<_>>();
    cap_taint_iris_next_evidence(&mut evidence, plan.caps.max_evidence_per_cwe);

    let labeled_specs = candidates
        .iter()
        .filter(|candidate| matches!(candidate.role.as_str(), "source" | "sink" | "sanitizer"))
        .take(plan.caps.max_specs_per_cwe * plan.catalog.len().max(1))
        .map(|candidate| TaintIrisNextLabeledSpec {
            id: format!("spec-{}", candidate.id),
            cwe: candidate.cwe.clone(),
            taint_class: candidate.taint_class.clone(),
            track: candidate.track.clone(),
            role: candidate.role.clone(),
            kind: candidate.kind.clone(),
            api_name: candidate.pattern.clone(),
            pattern: candidate.pattern.clone(),
            file_path: Some(candidate.file_path.clone()),
            line: Some(candidate.line),
            confidence: candidate.confidence.clone(),
            rationale: format!("Matched catalog {} signal", candidate.role),
            catalog_signal: candidate.catalog_signal.clone(),
        })
        .collect::<Vec<_>>();

    let candidate_counts = count_taint_iris_next_candidates(&candidates);
    let labeled_spec_counts = labeled_specs
        .iter()
        .fold(BTreeMap::new(), |mut counts, spec| {
            *counts.entry(spec.cwe.clone()).or_insert(0) += 1;
            counts
        });
    let linked_story_count = linked_stories.len();
    let outcome = if linked_story_count > 0 {
        "linked-evidence"
    } else if !evidence.is_empty() {
        "candidate-only"
    } else {
        "structural-only"
    };
    let finding_count = linked_story_count;
    let candidate_count = evidence.len().saturating_sub(finding_count);
    Ok(TaintIrisNextEvidenceResult {
        backend: plan.backend.selected.clone(),
        tool: if plan.backend.selected == "codeql" {
            "codeql".to_string()
        } else {
            plan.backend.structural_tool.clone()
        },
        evidence,
        candidates,
        linked_stories,
        labeled_specs,
        query_count: plan.structural_queries.len(),
        candidate_counts,
        labeled_spec_counts,
        linked_story_count,
        backend_path_count: 0,
        structural_engine: plan.backend.structural_tool.clone(),
        triage_summary: json!({
            "finding": finding_count,
            "candidate": candidate_count,
            "rejected": 0,
        }),
        outcome: outcome.to_string(),
        warnings: plan.backend.warnings.clone(),
        artifacts: json!({
            "codeqlLanguage": Value::Null,
            "codeqlQueryPath": Value::Null,
            "codeqlCompileStatus": "not-run",
        }),
    })
}

#[derive(Debug, Clone)]
struct TaintIrisNextSourceFile {
    relative_path: String,
    language: String,
    lines: Vec<String>,
}

fn collect_taint_iris_next_source_files(
    root: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
) -> Result<Vec<TaintIrisNextSourceFile>> {
    let mut files = Vec::new();
    collect_taint_iris_next_source_files_inner(
        root,
        root,
        max_files,
        max_bytes_per_file,
        &mut files,
    )?;
    Ok(files)
}

fn collect_taint_iris_next_source_files_inner(
    root: &Path,
    dir: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
    files: &mut Vec<TaintIrisNextSourceFile>,
) -> Result<()> {
    if files.len() >= max_files {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if files.len() >= max_files {
            break;
        }
        let path = entry.path();
        let file_name = entry.file_name();
        if should_skip_path(&file_name.to_string_lossy()) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_taint_iris_next_source_files_inner(
                root,
                &path,
                max_files,
                max_bytes_per_file,
                files,
            )?;
            continue;
        }
        if !file_type.is_file() || !is_agentic_context_file(&path) {
            continue;
        }
        let raw = fs::read(&path).unwrap_or_default();
        if raw.iter().take(4096).any(|byte| *byte == 0) {
            continue;
        }
        let text = String::from_utf8_lossy(&raw[..raw.len().min(max_bytes_per_file)]).to_string();
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let language = language_for_path(&path);
        files.push(TaintIrisNextSourceFile {
            relative_path,
            language,
            lines: text.lines().map(ToString::to_string).collect(),
        });
    }
    Ok(())
}

fn detect_taint_iris_next_languages(root: &Path) -> Result<Vec<String>> {
    Ok(collect_taint_iris_next_source_files(root, 600, 1024)?
        .into_iter()
        .map(|file| file.language)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn language_for_path(path: &Path) -> String {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or("") {
        "js" | "jsx" => "javascript",
        "ts" | "tsx" => "typescript",
        "py" => "python",
        "rb" => "ruby",
        "php" => "php",
        "java" => "java",
        "go" => "go",
        "rs" => "rust",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "cs" => "csharp",
        _ => "unknown",
    }
    .to_string()
}

fn taint_iris_next_line_matches(line_lower: &str, pattern: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    if line_lower.contains(&pattern_lower) {
        return true;
    }
    match pattern_lower.as_str() {
        "query parameter" | "route parameter" => {
            line_lower.contains("req.query")
                || line_lower.contains("request.args")
                || line_lower.contains("params")
        }
        "request body" => line_lower.contains("req.body") || line_lower.contains("request.body"),
        "request path" => line_lower.contains("req.path") || line_lower.contains("request.path"),
        "webhook url" | "callback url" | "request url" => {
            line_lower.contains("req.query.url")
                || line_lower.contains("request.url")
                || line_lower.contains("url")
        }
        "prepared statement" | "parameterized query" | "bind parameter" => {
            line_lower.contains("$1") || line_lower.contains("?") || line_lower.contains("bind")
        }
        _ => false,
    }
}

fn taint_iris_next_kind_for_role(role: &str) -> &'static str {
    match role {
        "source" => "external-return-source",
        "sink" => "external-arg-sink",
        "sanitizer" => "sanitizer",
        _ => "control-context",
    }
}

fn build_taint_iris_next_linked_stories(
    candidates: &[TaintIrisNextCandidate],
) -> Vec<TaintIrisNextLinkedStory> {
    let mut stories = Vec::new();
    for source in candidates
        .iter()
        .filter(|candidate| candidate.role == "source")
    {
        for sink in candidates
            .iter()
            .filter(|candidate| candidate.role == "sink" && candidate.cwe == source.cwe)
        {
            if sink.file_path != source.file_path {
                continue;
            }
            let distance = sink.line.abs_diff(source.line);
            if distance > 80 {
                continue;
            }
            let shared_tokens = shared_taint_iris_next_tokens(&source.snippet, &sink.snippet);
            stories.push(TaintIrisNextLinkedStory {
                id: format!("linked-{}-{}", source.id, sink.id),
                cwe: source.cwe.clone(),
                taint_class: source.taint_class.clone(),
                track: source.track.clone(),
                evidence_level: "linked".to_string(),
                file_path: source.file_path.clone(),
                language: source.language.clone(),
                source_candidate_id: source.id.clone(),
                sink_candidate_id: sink.id.clone(),
                source_line: source.line,
                sink_line: sink.line,
                shared_tokens: shared_tokens.clone(),
                rationale: format!(
                    "{} source at line {} is near {} sink at line {}{}",
                    source.catalog_signal,
                    source.line,
                    sink.catalog_signal,
                    sink.line,
                    if shared_tokens.is_empty() {
                        String::new()
                    } else {
                        format!(" with shared tokens {}", shared_tokens.join(", "))
                    }
                ),
            });
        }
    }
    stories.sort_by(|left, right| {
        cwe_priority(&right.cwe)
            .cmp(&cwe_priority(&left.cwe))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.sink_line.cmp(&right.sink_line))
    });
    stories
}

fn shared_taint_iris_next_tokens(left: &str, right: &str) -> Vec<String> {
    let left_tokens = identifier_tokens(left);
    let right_tokens = identifier_tokens(right);
    left_tokens
        .intersection(&right_tokens)
        .filter(|token| token.len() > 2)
        .take(8)
        .cloned()
        .collect()
}

fn identifier_tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .map(str::trim)
        .filter(|token| token.len() > 2)
        .map(|token| token.to_ascii_lowercase())
        .filter(|token| {
            !matches!(
                token.as_str(),
                "const"
                    | "let"
                    | "var"
                    | "def"
                    | "function"
                    | "return"
                    | "query"
                    | "request"
                    | "params"
            )
        })
        .collect()
}

fn cap_taint_iris_next_evidence(evidence: &mut Vec<TaintIrisNextEvidence>, max_per_cwe: usize) {
    let mut counts = BTreeMap::new();
    evidence.retain(|item| {
        let count = counts.entry(item.cwe.clone()).or_insert(0usize);
        if *count >= max_per_cwe {
            return false;
        }
        *count += 1;
        true
    });
}

fn count_taint_iris_next_candidates(
    candidates: &[TaintIrisNextCandidate],
) -> BTreeMap<String, usize> {
    candidates
        .iter()
        .fold(BTreeMap::new(), |mut counts, candidate| {
            *counts.entry(candidate.cwe.clone()).or_insert(0) += 1;
            counts
        })
}

fn build_taint_iris_next_agent_prompt(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> String {
    let mut lines = vec![
        "Taint IRIS Next".to_string(),
        "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities".to_string(),
        String::new(),
        "You are Kuzushi's Taint IRIS Next agent. This is an agent-forward adaptation inspired by the IRIS paper, not the original implementation.".to_string(),
        String::new(),
        "## Objective".to_string(),
        "Use the deterministic context, threat model, CWE catalog, candidates, typed specs, and evidence bundles below to select relevant CWE themes and report only defensible findings.".to_string(),
        format!("minimum finding evidence level: {}", plan.caps.min_evidence_level),
        String::new(),
        "## Backend".to_string(),
        format!("requested: {}", plan.backend.requested),
        format!("selected: {}", plan.backend.selected),
        format!("structural engine: {}", evidence.structural_engine),
        format!("evidence tool: {}", evidence.tool),
        format!(
            "CodeQL corroboration: {}",
            if plan.backend.corroborate_with_codeql.unwrap_or(false) {
                "enabled"
            } else {
                "disabled"
            }
        ),
        plan.backend
            .codeql_db_path
            .as_ref()
            .map(|path| format!("existing CodeQL DB: {path}"))
            .unwrap_or_else(|| "existing CodeQL DB: none".to_string()),
        String::new(),
        "## Context Summary".to_string(),
        format!("languages: {}", plan.languages.join(", ")),
        format!("context artifact: {}", plan.context_status.reason),
        String::new(),
        "## Threat Model Summary".to_string(),
        format!("threat model artifact: {}", plan.threat_model_status.reason),
        String::new(),
        plan.prompt_catalog.clone(),
        String::new(),
        "## Candidate And Spec Counts".to_string(),
        format!("candidateCounts: {}", json!(evidence.candidate_counts)),
        format!("labeledSpecCounts: {}", json!(evidence.labeled_spec_counts)),
        String::new(),
        "## Evidence Bundles".to_string(),
    ];
    for item in evidence.evidence.iter().take(40) {
        lines.push(format!(
            "- {} {} {}:{} [{}] {}",
            item.cwe, item.role, item.file_path, item.line, item.evidence_level, item.snippet
        ));
    }
    lines.push(String::new());
    lines.push("## Linked Stories".to_string());
    for story in evidence.linked_stories.iter().take(20) {
        lines.push(format!(
            "- {} {}:{} -> {} ({})",
            story.cwe, story.file_path, story.source_line, story.sink_line, story.rationale
        ));
    }
    lines.push(String::new());
    lines.push("## Contract".to_string());
    lines.push(
        "- Return strict JSON matching { selectedCwes, findings, triage, notes }.".to_string(),
    );
    lines.push(format!(
        "- Return at most {} findings.",
        plan.caps.max_agent_findings
    ));
    lines.push("- Cite catalogSignals for every selected CWE and every finding.".to_string());
    lines.join("\n")
}

fn run_taint_iris_next_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
    runtime: &dyn AgentRuntime,
    model: &str,
    agent_tool_policy: crate::runtime::AgentToolPolicy,
) -> Result<TaintIrisNextAgentResult> {
    let response = runtime.query_blocking(
        AgentQueryRequest::new(
            model.to_string(),
            plan.repo_root.clone(),
            TAINT_IRIS_NEXT_SYSTEM_PROMPT.to_string(),
            agent_prompt.to_string(),
        )
        .with_tool_policy(agent_tool_policy.clone()),
    )?;
    let mut retry_count = 0usize;
    let mut parsed = parse_taint_iris_next_agent_response(response);
    if parsed.is_err() {
        retry_count = 1;
        let repair = runtime.query_blocking(
            AgentQueryRequest::new(
                model.to_string(),
                plan.repo_root.clone(),
                TAINT_IRIS_NEXT_SYSTEM_PROMPT.to_string(),
                build_taint_iris_next_repair_prompt(plan, evidence),
            )
            .with_tool_policy(agent_tool_policy),
        )?;
        parsed = parse_taint_iris_next_agent_response(repair);
    }

    let raw = match parsed {
        Ok(raw) => raw,
        Err(error) => {
            let (findings, selections, triage) =
                deterministic_taint_iris_next_fallback(plan, evidence);
            let warnings = vec![
                "agent returned no structured JSON output".to_string(),
                format!("parse error: {error}"),
                format!(
                    "agent output invalid; returning {} deterministic linked finding candidate(s) for review",
                    findings.len()
                ),
            ];
            return Ok(TaintIrisNextAgentResult {
                agent_status: "invalid-json".to_string(),
                selected_cwes: selections,
                findings: findings.clone(),
                review_candidates: findings,
                triage,
                triage_summary: summarize_taint_iris_next_triage(&[]),
                outcome: "agent-output-invalid".to_string(),
                raw_output: Value::Null,
                structured_output_valid: false,
                structured_output_retry_count: retry_count,
                parse_error: Some(error.to_string()),
                result_text_excerpt: None,
                warnings,
                cost_usd: 0.0,
            });
        }
    };

    let Value::Object(object) = raw.clone() else {
        anyhow::bail!("taint-iris-next:hunt expected agent output to be a JSON object");
    };
    let selections = normalize_taint_iris_next_selections(
        read_object_value(&object, &["selectedCwes", "selected_cwes"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        &plan.catalog,
    )?;
    let (mut findings, mut warnings) = normalize_taint_iris_next_findings(
        read_object_value(&object, &["findings"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        plan,
        evidence,
    )?;
    let triage = normalize_taint_iris_next_triage(
        read_object_value(&object, &["triage"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
    let mut review_candidates = Vec::new();
    let mut outcome = evidence.outcome.clone();
    let mut agent_status = if selections.is_empty() {
        "no-selection".to_string()
    } else {
        "valid-json".to_string()
    };
    if selections.is_empty() && findings.is_empty() && !evidence.linked_stories.is_empty() {
        let (fallback_findings, fallback_selections, fallback_triage) =
            deterministic_taint_iris_next_fallback(plan, evidence);
        if !fallback_findings.is_empty() {
            warnings.push(format!(
                "agent selected no CWEs; returning {} deterministic linked finding candidate(s) for review",
                fallback_findings.len()
            ));
            findings = fallback_findings.clone();
            review_candidates = fallback_findings;
            outcome = "agent-no-selection".to_string();
            agent_status = "no-selection-fallback".to_string();
            return Ok(TaintIrisNextAgentResult {
                agent_status,
                selected_cwes: fallback_selections,
                findings,
                review_candidates,
                triage: fallback_triage.clone(),
                triage_summary: summarize_taint_iris_next_triage(&fallback_triage),
                outcome,
                raw_output: raw,
                structured_output_valid: true,
                structured_output_retry_count: retry_count,
                parse_error: None,
                result_text_excerpt: None,
                warnings,
                cost_usd: 0.0,
            });
        }
    }
    if selections.is_empty() && !evidence.evidence.is_empty() {
        warnings.push(format!(
            "agent selected no CWEs from {} evidence row(s)",
            evidence.evidence.len()
        ));
        outcome = "agent-no-selection".to_string();
    }
    findings.truncate(plan.caps.max_agent_findings);
    Ok(TaintIrisNextAgentResult {
        agent_status,
        selected_cwes: selections,
        findings,
        review_candidates,
        triage_summary: summarize_taint_iris_next_triage(&triage),
        triage,
        outcome,
        raw_output: raw,
        structured_output_valid: true,
        structured_output_retry_count: retry_count,
        parse_error: None,
        result_text_excerpt: None,
        warnings,
        cost_usd: 0.0,
    })
}

fn parse_taint_iris_next_agent_response(response: AgentQueryResponse) -> Result<Value> {
    match response.structured {
        Some(value @ Value::Object(_)) => Ok(value),
        Some(_) => anyhow::bail!(
            "taint-iris-next:hunt expected structured output to be a JSON object"
        ),
        None => parse_json_object_from_agent_text(&response.text).with_context(|| {
            "taint-iris-next:hunt expected pi-agent-core to return JSON with selectedCwes, findings, triage, and notes"
        }),
    }
}

fn build_taint_iris_next_repair_prompt(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> String {
    [
        "Return only strict JSON matching this shape: {\"selectedCwes\":[],\"findings\":[],\"triage\":[],\"notes\":[]}.".to_string(),
        "No markdown, no prose outside JSON.".to_string(),
        format!("Minimum finding evidence level: {}", plan.caps.min_evidence_level),
        format!(
            "Backend: {}; evidence rows: {}; linked stories: {}",
            plan.backend.selected,
            evidence.evidence.len(),
            evidence.linked_story_count
        ),
        format!(
            "Catalog CWEs: {}",
            plan.catalog
                .iter()
                .map(|entry| entry.cwe.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ]
    .join("\n")
}

fn normalize_taint_iris_next_selections(
    items: Vec<Value>,
    catalog: &[TaintIrisNextRankedCatalogEntry],
) -> Result<Vec<Value>> {
    let catalog_ids = catalog
        .iter()
        .map(|entry| entry.cwe.clone())
        .collect::<BTreeSet<_>>();
    let mut selections = Vec::new();
    let mut rejected = Vec::new();
    for item in items {
        let Value::Object(object) = item else {
            continue;
        };
        let Some(cwe) = read_object_string(&object, &["cwe"]) else {
            continue;
        };
        let cwe = normalize_taint_next_cwe(&cwe);
        let catalog_signals =
            read_object_string_array(&object, &["catalogSignals", "catalog_signals"]);
        let custom = read_object_string(&object, &["customCweRationale", "custom_cwe_rationale"]);
        if !catalog_ids.contains(&cwe) && custom.is_none() {
            rejected.push(format!(
                "{cwe}: not present in CWE catalog and missing customCweRationale"
            ));
            continue;
        }
        if catalog_ids.contains(&cwe) && catalog_signals.is_empty() {
            rejected.push(format!(
                "{cwe}: catalog CWE selection must cite at least one catalog signal"
            ));
            continue;
        }
        selections.push(json!({
            "cwe": cwe,
            "reason": read_object_string(&object, &["reason"]).unwrap_or_default(),
            "catalogSignals": catalog_signals,
            "sourceSpec": read_object_string(&object, &["sourceSpec", "source_spec"]).unwrap_or_default(),
            "sinkSpec": read_object_string(&object, &["sinkSpec", "sink_spec"]).unwrap_or_default(),
            "sanitizerSpec": read_object_string(&object, &["sanitizerSpec", "sanitizer_spec"]).unwrap_or_default(),
            "customCweRationale": custom.unwrap_or_default(),
            "knownCatalogCwe": catalog_ids.contains(&cwe),
        }));
    }
    if !rejected.is_empty() {
        anyhow::bail!(
            "[taint-iris-next] Agent selected invalid CWEs: {}",
            rejected.join("; ")
        );
    }
    Ok(selections)
}

fn normalize_taint_iris_next_findings(
    items: Vec<Value>,
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let catalog_ids = plan
        .catalog
        .iter()
        .map(|entry| entry.cwe.clone())
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for item in items {
        let Value::Object(object) = item else {
            continue;
        };
        let cwe = normalize_taint_next_cwe(
            &read_object_string(&object, &["cwe"]).unwrap_or_else(|| "CWE".to_string()),
        );
        if !catalog_ids.contains(&cwe)
            && read_object_string(&object, &["customCweRationale", "custom_cwe_rationale"])
                .is_none()
        {
            warnings.push(format!(
                "dropped finding with non-catalog CWE {cwe} and no customCweRationale"
            ));
            continue;
        }
        let title = read_object_string(&object, &["title"])
            .unwrap_or_else(|| format!("{} taint finding", cwe));
        let file_path = normalize_agentic_file_path(
            read_object_string(&object, &["filePath", "file_path"])
                .unwrap_or_else(|| "unknown".to_string()),
            &plan.repo_root,
        );
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .filter(|value| *value > 0)
            .unwrap_or(1) as u32;
        let evidence_level = read_object_string(&object, &["evidenceLevel", "evidence_level"])
            .unwrap_or_else(|| strongest_taint_iris_next_evidence_level(&cwe, evidence));
        if !taint_iris_next_evidence_meets_minimum(&evidence_level, &plan.caps.min_evidence_level) {
            warnings.push(format!(
                "dropped {cwe} finding below minEvidenceLevel={}; strongest evidence was {evidence_level}",
                plan.caps.min_evidence_level
            ));
            continue;
        }
        let detail = read_object_string(&object, &["message"]).unwrap_or_else(|| title.clone());
        let mut message = format!("[{cwe}] {title}: {detail}");
        if let Some(trace) = read_object_string(&object, &["sourceSinkTrace", "source_sink_trace"])
        {
            message.push_str("\nSource-to-sink trace: ");
            message.push_str(trace.trim());
        }
        let catalog_signals =
            read_object_string_array(&object, &["catalogSignals", "catalog_signals"]);
        if !catalog_signals.is_empty() {
            message.push_str("\nCatalog signals: ");
            message.push_str(&catalog_signals.join("; "));
        }
        if let Some(confidence) = read_object_string(&object, &["confidence"]) {
            message.push_str("\nConfidence: ");
            message.push_str(&confidence);
        }
        if let Some(path_summary) = summarize_taint_path(&object) {
            message.push_str("\nTaint path:\n");
            message.push_str(&path_summary);
        }
        findings.push(Finding::new_tool(
            "taint-iris-next",
            format!("taint-iris-next/{}", sanitize_rule_segment(&cwe)),
            file_path,
            start_line,
            None,
            agentic_severity(
                read_object_string(&object, &["severity"])
                    .as_deref()
                    .unwrap_or("medium"),
            ),
            message,
        ));
    }
    Ok((findings, warnings))
}

fn normalize_taint_iris_next_triage(items: Vec<Value>) -> Vec<Value> {
    items
        .into_iter()
        .filter_map(|item| {
            let Value::Object(object) = item else {
                return None;
            };
            let cwe = read_object_string(&object, &["cwe"])?;
            Some(json!({
                "status": read_object_string(&object, &["status"]).unwrap_or_else(|| "candidate".to_string()),
                "cwe": normalize_taint_next_cwe(&cwe),
                "evidenceLevel": read_object_string(&object, &["evidenceLevel", "evidence_level"]).unwrap_or_else(|| "candidate".to_string()),
                "rationale": read_object_string(&object, &["rationale"]).unwrap_or_default(),
                "filePath": read_object_string(&object, &["filePath", "file_path"]),
                "line": read_object_u64(&object, &["line", "startLine", "start_line"]).unwrap_or(1),
                "catalogSignals": read_object_string_array(&object, &["catalogSignals", "catalog_signals"]),
            }))
        })
        .collect()
}

fn deterministic_taint_iris_next_fallback(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> (Vec<Finding>, Vec<Value>, Vec<Value>) {
    if !taint_iris_next_evidence_meets_minimum("linked", &plan.caps.min_evidence_level) {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    let candidates = evidence
        .candidates
        .iter()
        .map(|candidate| (candidate.id.clone(), candidate))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    let mut selections_by_cwe = BTreeMap::new();
    let mut triage = Vec::new();
    for story in evidence
        .linked_stories
        .iter()
        .take(plan.caps.max_agent_findings)
    {
        let Some(source) = candidates.get(&story.source_candidate_id) else {
            continue;
        };
        let Some(sink) = candidates.get(&story.sink_candidate_id) else {
            continue;
        };
        selections_by_cwe.entry(story.cwe.clone()).or_insert_with(|| {
            json!({
                "cwe": story.cwe,
                "reason": "Deterministic structural linker produced linked evidence before agent selection completed.",
                "catalogSignals": [source.catalog_signal.clone(), sink.catalog_signal.clone()],
                "sourceSpec": source.catalog_signal,
                "sinkSpec": sink.catalog_signal,
                "sanitizerSpec": "",
                "customCweRationale": "",
                "knownCatalogCwe": true,
            })
        });
        triage.push(json!({
            "status": "finding",
            "cwe": story.cwe,
            "evidenceLevel": "linked",
            "rationale": format!("Deterministic fallback: {}", story.rationale),
            "filePath": story.file_path,
            "line": story.sink_line,
            "catalogSignals": [source.catalog_signal.clone(), sink.catalog_signal.clone()],
        }));
        let message = format!(
            "[{}] Linked {} candidate: {}. Agent triage output was unavailable or invalid, so review before treating as confirmed.\nTaint path:\n- {}:{}: source: {} | {}\n- {}:{}: sink: {} | {}",
            story.cwe,
            story.taint_class,
            story.rationale,
            source.file_path,
            source.line,
            source.catalog_signal,
            source.snippet,
            sink.file_path,
            sink.line,
            sink.catalog_signal,
            sink.snippet
        );
        findings.push(Finding::new_tool(
            "taint-iris-next",
            format!("taint-iris-next/{}", sanitize_rule_segment(&story.cwe)),
            story.file_path.clone(),
            story.sink_line,
            None,
            deterministic_taint_iris_next_severity(&story.cwe),
            message,
        ));
    }
    (findings, selections_by_cwe.into_values().collect(), triage)
}

fn summarize_taint_iris_next_triage(triage: &[Value]) -> Value {
    let mut finding = 0usize;
    let mut candidate = 0usize;
    let mut rejected = 0usize;
    for item in triage {
        match item
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("candidate")
        {
            "finding" => finding += 1,
            "rejected" => rejected += 1,
            _ => candidate += 1,
        }
    }
    json!({
        "finding": finding,
        "candidate": candidate,
        "rejected": rejected,
    })
}

fn strongest_taint_iris_next_evidence_level(
    cwe: &str,
    evidence: &TaintIrisNextEvidenceResult,
) -> String {
    let mut strongest = "candidate";
    for item in &evidence.evidence {
        if item.cwe != cwe {
            continue;
        }
        if item.evidence_level == "path" {
            return "path".to_string();
        }
        if item.evidence_level == "linked" {
            strongest = "linked";
        }
    }
    strongest.to_string()
}

fn taint_iris_next_evidence_meets_minimum(level: &str, minimum: &str) -> bool {
    fn rank(value: &str) -> u8 {
        match value {
            "path" => 3,
            "linked" => 2,
            "candidate" => 1,
            _ => 0,
        }
    }
    rank(level) >= rank(minimum)
}

fn deterministic_taint_iris_next_severity(cwe: &str) -> Severity {
    match cwe {
        "CWE-78" | "CWE-89" | "CWE-94" => Severity::High,
        "CWE-22" | "CWE-79" | "CWE-502" | "CWE-611" | "CWE-918" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn cwe_priority(cwe: &str) -> i32 {
    match cwe {
        "CWE-78" | "CWE-89" | "CWE-94" => 3,
        "CWE-22" | "CWE-79" | "CWE-502" | "CWE-611" | "CWE-918" => 2,
        _ => 1,
    }
}

fn taint_iris_next_base_data(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    status: &str,
    agent_prompt: &str,
) -> Value {
    json!({
        "status": status,
        "attribution": "IRIS-inspired adaptation; not the original IRIS implementation.",
        "references": ["IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities"],
        "target": plan.target.display().to_string(),
        "mode": plan.mode.as_str(),
        "backend": plan.backend,
        "caps": plan.caps,
        "maxBudgetUsd": plan.max_budget_usd,
        "languages": plan.languages,
        "contextStatus": plan.context_status,
        "threatModelStatus": plan.threat_model_status,
        "repoContext": plan.repo_context.clone(),
        "threatModel": plan.threat_model.clone(),
        "cweCatalog": plan.catalog,
        "promptCatalog": plan.prompt_catalog,
        "structuralQueries": plan.structural_queries,
        "evidence": evidence.evidence,
        "candidates": evidence.candidates,
        "linkedStories": evidence.linked_stories,
        "labeledSpecs": evidence.labeled_specs,
        "outcome": evidence.outcome,
        "candidateCounts": evidence.candidate_counts,
        "labeledSpecCounts": evidence.labeled_spec_counts,
        "linkedStoryCount": evidence.linked_story_count,
        "backendPathCount": evidence.backend_path_count,
        "structuralEngine": evidence.structural_engine,
        "triageSummary": evidence.triage_summary,
        "evidenceResult": evidence,
        "agentPrompt": agent_prompt,
    })
}

fn render_taint_iris_next_output(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent: Option<&TaintIrisNextAgentResult>,
) -> String {
    let warnings = plan
        .backend
        .warnings
        .iter()
        .chain(evidence.warnings.iter())
        .chain(agent.into_iter().flat_map(|agent| agent.warnings.iter()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let selected = agent
        .map(|agent| {
            agent
                .selected_cwes
                .iter()
                .filter_map(|value| value.get("cwe").and_then(Value::as_str))
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut lines = vec![
        "Taint IRIS Next".to_string(),
        "IRIS-inspired bounded taint hunting".to_string(),
        String::new(),
        "IRIS-inspired adaptation; not the original IRIS implementation.".to_string(),
        String::new(),
        format!("target: {}", plan.target.display()),
        format!("mode: {}", plan.mode.as_str()),
        format!(
            "outcome: {}",
            agent
                .map(|agent| agent.outcome.as_str())
                .unwrap_or(evidence.outcome.as_str())
        ),
        format!(
            "backend: {} -> {}",
            plan.backend.requested, plan.backend.selected
        ),
        format!("structural engine: {}", evidence.structural_engine),
        format!(
            "CodeQL corroboration: {}",
            if plan.backend.corroborate_with_codeql.unwrap_or(false) {
                "enabled"
            } else {
                "disabled"
            }
        ),
        plan.backend
            .codeql_db_path
            .as_ref()
            .map(|path| format!("existing CodeQL DB: {path}"))
            .unwrap_or_else(|| "existing CodeQL DB: none".to_string()),
        format!("scan root: {}", plan.scan_root.display()),
        format!("repo root: {}", plan.repo_root.display()),
        format!(
            "context: {} ({})",
            if plan.context_status.ok {
                "loaded"
            } else {
                "missing/incomplete"
            },
            plan.context_status.reason
        ),
        format!(
            "threat model: {} ({})",
            if plan.threat_model_status.ok {
                "loaded"
            } else {
                "warning"
            },
            plan.threat_model_status.reason
        ),
        format!("languages: {}", plan.languages.join(", ")),
        format!("min evidence level: {}", plan.caps.min_evidence_level),
        format!(
            "CWE catalog: {}/{} ranked candidates",
            plan.catalog.len(),
            TAINT_IRIS_NEXT_CATALOG.len()
        ),
        format!("structural query seeds: {}", plan.structural_queries.len()),
        format!("candidates: {}", evidence.candidates.len()),
        format!("labeled specs: {}", evidence.labeled_specs.len()),
        format!("linked stories: {}", evidence.linked_story_count),
        format!("backend paths: {}", evidence.backend_path_count),
        format!(
            "evidence: {} rows via {}",
            evidence.evidence.len(),
            evidence.tool
        ),
    ];
    if let Some(agent) = agent {
        lines.push(format!("agent status: {}", agent.agent_status));
        lines.push(format!(
            "agent selected CWEs: {}",
            if selected.is_empty() {
                "none".to_string()
            } else {
                selected.join(", ")
            }
        ));
        lines.push(format!(
            "triage: findings={} candidates={} rejected={}",
            agent
                .triage_summary
                .get("finding")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            agent
                .triage_summary
                .get("candidate")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            agent
                .triage_summary
                .get("rejected")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        ));
        lines.push(format!(
            "findings: {}",
            agent
                .findings
                .len()
                .saturating_sub(agent.review_candidates.len())
        ));
        if !agent.review_candidates.is_empty() {
            lines.push(format!(
                "review candidates: {}",
                agent.review_candidates.len()
            ));
        }
        lines.push(if agent.structured_output_valid {
            format!(
                "agent output: valid strict JSON{}",
                if agent.structured_output_retry_count > 0 {
                    " after repair retry"
                } else {
                    ""
                }
            )
        } else {
            format!(
                "agent output: invalid strict JSON after {} repair retry",
                agent.structured_output_retry_count
            )
        });
    } else {
        lines.push(format!(
            "triage: findings={} candidates={} rejected={}",
            evidence
                .triage_summary
                .get("finding")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            evidence
                .triage_summary
                .get("candidate")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            evidence
                .triage_summary
                .get("rejected")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        ));
    }
    if !warnings.is_empty() {
        lines.push(format!("warnings: {}", warnings.join("; ")));
    }
    lines.push(String::new());
    lines.push(if plan.mode == TaintIrisNextMode::Plan {
        "Status: deterministic plan complete. Hunt mode will feed this bounded catalog and evidence bundle into one scoped agent session.".to_string()
    } else {
        "Status: hunt complete.".to_string()
    });
    lines.push(String::new());
    lines.push(plan.prompt_catalog.clone());
    lines.join("\n")
}

fn persist_taint_iris_next_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<TaintIrisNextPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;
    Ok(Some(TaintIrisNextPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

fn optional_taint_next_string(input: &Value, keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::String(text) => Ok(Some(text.trim().to_string()).filter(|s| !s.is_empty())),
                _ => anyhow::bail!("taint-iris-next:hunt {key} must be a string"),
            };
        }
    }
    Ok(None)
}

fn normalize_taint_next_language(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "js" | "javascript" => "javascript",
        "ts" | "typescript" => "typescript",
        "py" | "python" => "python",
        "rb" | "ruby" => "ruby",
        "rs" | "rust" => "rust",
        "golang" | "go" => "go",
        "c++" | "cpp" | "cxx" => "cpp",
        "c#" | "csharp" => "csharp",
        "java" => "java",
        "php" => "php",
        "c" => "c",
        "any" => "any",
        other => other,
    }
    .to_string()
}

fn normalize_taint_next_cwe(value: &str) -> String {
    let trimmed = value.trim().to_ascii_uppercase();
    let digits = trimmed
        .strip_prefix("CWE-")
        .or_else(|| trimmed.strip_prefix("CWE_"))
        .or_else(|| trimmed.strip_prefix("CWE "))
        .unwrap_or(&trimmed);
    if let Ok(number) = digits.parse::<u32>() {
        return format!("CWE-{number}");
    }
    trimmed
}

fn cwe_number(value: &str) -> u32 {
    normalize_taint_next_cwe(value)
        .strip_prefix("CWE-")
        .and_then(|digits| digits.parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

fn positive_usize_input(input: &Value, keys: &[&str], label: &str) -> Result<Option<usize>> {
    let Some(value) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    match value {
        Value::Number(number) => {
            let value = number
                .as_u64()
                .with_context(|| format!("{label} must be a positive integer"))?;
            if value == 0 {
                anyhow::bail!("{label} must be a positive integer");
            }
            Ok(Some(value as usize))
        }
        Value::String(value) => {
            let parsed = value
                .trim()
                .parse::<usize>()
                .with_context(|| format!("{label} must be a positive integer"))?;
            if parsed == 0 {
                anyhow::bail!("{label} must be a positive integer");
            }
            Ok(Some(parsed))
        }
        _ => anyhow::bail!("{label} must be a positive integer"),
    }
}

fn positive_f64_input(input: &Value, keys: &[&str], label: &str) -> Result<Option<f64>> {
    let Some(value) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    let parsed = match value {
        Value::Number(number) => number
            .as_f64()
            .with_context(|| format!("{label} must be a positive number"))?,
        Value::String(value) => value
            .trim()
            .parse::<f64>()
            .with_context(|| format!("{label} must be a positive number"))?,
        _ => anyhow::bail!("{label} must be a positive number"),
    };
    if !parsed.is_finite() || parsed <= 0.0 {
        anyhow::bail!("{label} must be a positive number");
    }
    Ok(Some(parsed))
}

fn parse_sast_tasks(input: &Value) -> Result<Vec<String>> {
    let requested = string_list_input(input, &["tasks", "taskIds", "task_ids"])?;
    let disabled =
        string_list_input(input, &["disabledTasks", "disabled_tasks"])?.unwrap_or_default();
    let task_mode = input
        .get("taskMode")
        .or_else(|| input.get("task_mode"))
        .and_then(Value::as_str)
        .unwrap_or("auto");
    if !matches!(task_mode, "auto" | "manual") {
        anyhow::bail!("sast:scan taskMode must be \"auto\" or \"manual\"");
    }
    if task_mode == "manual" && requested.as_ref().map_or(true, Vec::is_empty) {
        anyhow::bail!("sast:scan taskMode=manual requires a non-empty tasks array");
    }

    let mut tasks = requested.unwrap_or_else(|| {
        if disabled.is_empty() {
            Vec::new()
        } else {
            vec![
                "semgrep".to_string(),
                "dep-hygiene".to_string(),
                "secret-scan".to_string(),
                "iac-scan".to_string(),
            ]
        }
    });

    if !disabled.is_empty() {
        tasks.retain(|task| {
            !disabled
                .iter()
                .any(|disabled| same_scan_task(task, disabled))
        });
    }
    Ok(tasks)
}

fn parse_sast_severity_filter(input: &Value) -> Result<Option<Vec<Severity>>> {
    let Some(values) = string_list_input(input, &["severity"])? else {
        return Ok(None);
    };
    if values.is_empty() {
        return Ok(None);
    }
    values
        .iter()
        .map(|value| parse_sast_severity(value))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn parse_sast_severity(value: &str) -> Result<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" | "error" => Ok(Severity::High),
        "medium" | "warning" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        "unknown" => Ok(Severity::Unknown),
        other => anyhow::bail!("sast:scan unknown severity filter {other:?}"),
    }
}

fn string_list_input(input: &Value, keys: &[&str]) -> Result<Option<Vec<String>>> {
    let Some(raw) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    let values = match raw {
        Value::String(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .context("sast:scan list inputs must contain only non-empty strings")
            })
            .collect::<Result<Vec<_>>>()?,
        _ => anyhow::bail!("sast:scan list inputs must be a string or string array"),
    };
    Ok(Some(values))
}

fn bool_input(input: &Value, keys: &[&str]) -> Result<bool> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return value
                .as_bool()
                .with_context(|| format!("sast:scan {key} must be a boolean"));
        }
    }
    Ok(false)
}

fn same_scan_task(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    left == right || left.split(':').next() == right.split(':').next()
}

#[derive(Debug, Clone)]
struct TriageRunInput {
    fingerprints: Option<Vec<String>>,
    batch_size: usize,
    prompt_template: Option<String>,
    scan_id: Option<String>,
    /// Maximum number of concurrent LLM calls in Stage 2. Default 8.
    /// 1 disables concurrency (sequential); higher values trade
    /// wallclock for token-rate-limit risk.
    concurrency: usize,
    /// Hard cost cap in USD for the whole triage call. The cascade
    /// aborts mid-stage when accumulated cost exceeds this; remaining
    /// findings stay in `pending` state. `None` means uncapped (legacy
    /// behaviour). Falls back to `KUZUSHI_COST_CAP_USD` env var.
    cost_cap_usd: Option<f64>,
    /// Stage 1 prefilter threshold. Findings whose deterministic
    /// `prefilter_score` is strictly below this value are dropped
    /// before any LLM call. Default 0 (no prefiltering).
    prefilter_threshold: i64,
    /// Force the runtime to use a specific model tier for Stage 2.
    /// Defaults to `Cheap` so multi-stage triage routes through the
    /// fastest model when available.
    stage2_tier: ModelTier,
}

impl TriageRunInput {
    fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        let mut fingerprints = Vec::new();
        if let Some(fingerprint) = optional_nonempty_string(input, "fingerprint")? {
            fingerprints.push(fingerprint);
        }
        if let Some(values) = input.get("fingerprints") {
            let Value::Array(items) = values else {
                anyhow::bail!("triage:run fingerprints must be an array of strings");
            };
            for item in items {
                let Some(value) = item
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    anyhow::bail!("triage:run fingerprints entries must be non-empty strings");
                };
                fingerprints.push(value.to_string());
            }
        }

        let batch_size = match input.get("batchSize").or_else(|| input.get("batch_size")) {
            Some(Value::Number(number)) => {
                let value = number
                    .as_u64()
                    .context("triage:run batchSize must be a positive integer")?;
                if value == 0 {
                    anyhow::bail!("triage:run batchSize must be a positive integer");
                }
                value.min(500) as usize
            }
            Some(Value::String(value)) => {
                let parsed = value
                    .parse::<usize>()
                    .context("triage:run batchSize must be a positive integer")?;
                if parsed == 0 {
                    anyhow::bail!("triage:run batchSize must be a positive integer");
                }
                parsed.min(500)
            }
            Some(_) => anyhow::bail!("triage:run batchSize must be a positive integer"),
            None => 5,
        };

        let prompt_template = optional_nonempty_string(input, "TRIAGE_PROMPT")?
            .map(|value| resolve_prompt_override(&value, cwd))
            .transpose()?;
        let scan_id = optional_nonempty_string(input, "scanId")?
            .or(optional_nonempty_string(input, "scan_id")?);

        let concurrency = match input.get("concurrency") {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(8).clamp(1, 64) as usize,
            None => 8,
            Some(_) => anyhow::bail!("triage:run concurrency must be a positive integer"),
        };

        let cost_cap_usd = match input
            .get("costCapUsd")
            .or_else(|| input.get("cost_cap_usd"))
        {
            Some(Value::Number(n)) => n.as_f64(),
            None => std::env::var("KUZUSHI_COST_CAP_USD")
                .ok()
                .and_then(|s| s.trim().parse::<f64>().ok()),
            Some(_) => anyhow::bail!("triage:run costCapUsd must be a number"),
        };

        let prefilter_threshold = input
            .get("prefilterThreshold")
            .or_else(|| input.get("prefilter_threshold"))
            .and_then(Value::as_i64)
            .unwrap_or(0);

        let stage2_tier = match input
            .get("stage2Tier")
            .or_else(|| input.get("stage2_tier"))
            .and_then(Value::as_str)
        {
            Some("cheap") | None => ModelTier::Cheap,
            Some("mid") => ModelTier::Mid,
            Some("deep") => ModelTier::Deep,
            Some(other) => {
                anyhow::bail!("triage:run stage2Tier must be one of cheap|mid|deep (got {other:?})")
            }
        };

        Ok(Self {
            fingerprints: if fingerprints.is_empty() {
                None
            } else {
                Some(fingerprints)
            },
            batch_size,
            prompt_template,
            scan_id,
            concurrency,
            cost_cap_usd,
            prefilter_threshold,
            stage2_tier,
        })
    }
}

/// Deterministic prefilter score for a finding. Combines severity,
/// number of attacker-controlled fields named in the message, and a
/// bonus for finding tools that are already curated (cargo-audit,
/// codeql) over wide-net SAST.
fn prefilter_score(finding: &Finding) -> i64 {
    let mut score: i64 = match finding.severity {
        Severity::Critical => 8,
        Severity::High => 5,
        Severity::Medium => 3,
        Severity::Low | Severity::Info | Severity::Unknown => 1,
    };
    let msg = finding.message.to_ascii_lowercase();
    for keyword in [
        "attacker",
        "untrusted",
        "user-controlled",
        "user controlled",
        "out-of-bounds",
        "use-after-free",
        "race condition",
        "buffer overflow",
        "integer overflow",
        "memory corruption",
        "command injection",
        "sql injection",
    ] {
        if msg.contains(keyword) {
            score += 2;
        }
    }
    // Tool quality nudge: curated scanners over wide-net SAST.
    match finding.tool.as_str() {
        "codeql" | "cargo-audit" | "iac-scan" | "secret-scan" => score += 2,
        "semgrep" => score += 1,
        _ => {}
    }
    score
}

fn run_triage(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "triage:run needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("triage:run requires a findings store for the active workspace")?;

    let input = TriageRunInput::from_tool_input(&input, workspace.root())?;
    let (findings, missing_fingerprints) = select_triage_findings(store, &input)?;
    if findings.is_empty() {
        return Ok(json!({
            "ok": false,
            "output": "[-] No findings match. Run a scanner first (`kuzushi scan <repo>`) or pass explicit fingerprints.",
            "data": {
                "triaged": 0,
                "total": 0,
                "tp": 0,
                "fp": 0,
                "needsReview": 0,
                "byDesign": 0,
                "costUsd": 0.0,
                "missingFingerprints": missing_fingerprints,
                "batchSize": input.batch_size,
            },
            "costUsd": 0.0,
        }));
    }

    let runtime = runtime.context(
        "triage:run requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model_configured = ctx.config.model.clone().context(
        "triage:run requires an explicit model in config.toml or KUZUSHI_MODEL; Kuzushi will not choose a fallback model",
    )?;
    let stage2_model = runtime.model_for_tier(input.stage2_tier, &model_configured);

    let total = findings.len();

    // ----- Stage 1: deterministic prefilter --------------------------
    let (kept, dropped_prefilter): (Vec<Finding>, Vec<Finding>) = findings
        .into_iter()
        .partition(|f| prefilter_score(f) >= input.prefilter_threshold);
    let stage1_kept = kept.len();
    let stage1_dropped = dropped_prefilter.len();

    // ----- Stage 2: concurrent LLM triage ----------------------------
    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut needs_review = 0usize;
    let mut by_design = 0usize;
    // Cost accumulator: every TriageOutcome now carries `cost_usd`
    // which providers populate when they surface usage (the
    // AnthropicOAuthRuntime path does so today). The cap test below
    // fires for real once the first call returns non-zero cost.
    let mut total_cost: f64 = 0.0;
    let mut cost_cap_hit = false;
    let mut results: Vec<Value> = Vec::with_capacity(stage1_kept);
    let mut pending_after_cap = 0usize;

    let cwd = workspace.root().to_path_buf();
    let prompt_template = input.prompt_template.clone();

    // Sequential dispatch (the trait's `&dyn AgentRuntime` borrow does
    // not satisfy `'static` for `tokio::spawn`). True concurrency is
    // a follow-up requiring an `Arc<dyn AgentRuntime>` signature
    // change. The `concurrency` knob is reported in the output for
    // forward compatibility.
    for finding in kept {
        if let Some(cap) = input.cost_cap_usd {
            if total_cost >= cap {
                cost_cap_hit = true;
                pending_after_cap += 1;
                continue;
            }
        }

        let req = TriageRequest {
            model: stage2_model.clone(),
            cwd: cwd.clone(),
            finding: finding.clone(),
            prompt_template: prompt_template.clone(),
        };
        let outcome = match runtime.triage_finding_blocking(req) {
            Ok(o) => o,
            Err(err) => {
                results.push(json!({
                    "fingerprint": finding.fingerprint,
                    "stage": "haiku",
                    "verdict": "needs_review",
                    "confidence": 0.0,
                    "rationale": format!("triage call failed: {err}"),
                }));
                needs_review += 1;
                continue;
            }
        };
        let finding_id = match finding.id {
            Some(id) => id,
            None => {
                results.push(json!({
                    "fingerprint": finding.fingerprint,
                    "stage": "haiku",
                    "verdict": outcome.verdict.as_str(),
                    "confidence": outcome.confidence,
                    "rationale": "finding lacked SQLite id; verdict not persisted",
                }));
                continue;
            }
        };
        total_cost += outcome.cost_usd;
        match outcome.verdict {
            TriageVerdict::TruePositive => tp += 1,
            TriageVerdict::FalsePositive => fp += 1,
            TriageVerdict::NeedsReview => needs_review += 1,
            TriageVerdict::ByDesign => by_design += 1,
        }
        if let Err(err) = store.save_triage(finding_id, &outcome) {
            eprintln!(
                "[triage:run] could not persist triage for finding {}: {err}",
                finding.fingerprint
            );
        }
        results.push(json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": outcome.rationale,
            "costUsd": outcome.cost_usd,
        }));
    }

    let triaged = results.len();
    let dropped_high_conf_fp = results
        .iter()
        .filter(|r| {
            r.get("verdict").and_then(Value::as_str) == Some("false_positive")
                && r.get("confidence").and_then(Value::as_f64).unwrap_or(0.0) >= 0.7
        })
        .count();

    let stages = json!([
        {
            "stage": "prefilter",
            "kept": stage1_kept,
            "dropped": stage1_dropped,
            "rule": format!("prefilter_score >= {}", input.prefilter_threshold),
        },
        {
            "stage": "haiku",
            "model": stage2_model,
            "concurrency": input.concurrency,
            "triaged": triaged,
            "tp": tp,
            "fp": fp,
            "needsReview": needs_review,
            "byDesign": by_design,
            "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
            "costUsd": total_cost,
            "costCapHit": cost_cap_hit,
            "pendingAfterCap": pending_after_cap,
        }
    ]);

    let mut summary = format!(
        "[+] Triaged {triaged} of {total} findings (stage1 dropped {stage1_dropped})\n      tp={tp}  fp={fp}  needs_review={needs_review}"
    );
    if by_design > 0 {
        summary.push_str(&format!("  by_design={by_design}"));
    }
    summary.push_str(&format!("\n      cost=${total_cost:.4}"));
    if cost_cap_hit {
        summary.push_str(&format!(
            "\n[!] cost cap hit; {pending_after_cap} finding(s) remain unevaluated"
        ));
    }
    if !missing_fingerprints.is_empty() {
        summary.push_str(&format!(
            "\n[!] {} requested finding(s) were not found",
            missing_fingerprints.len()
        ));
    }

    Ok(json!({
        "ok": true,
        "output": summary,
        "data": {
            "triaged": triaged,
            "total": total,
            "tp": tp,
            "fp": fp,
            "needsReview": needs_review,
            "byDesign": by_design,
            "costUsd": total_cost,
            "missingFingerprints": missing_fingerprints,
            "batchSize": input.batch_size,
            "concurrency": input.concurrency,
            "stage2Tier": match input.stage2_tier {
                ModelTier::Cheap => "cheap",
                ModelTier::Mid => "mid",
                ModelTier::Deep => "deep",
            },
            "costCapUsd": input.cost_cap_usd,
            "costCapHit": cost_cap_hit,
            "pendingAfterCap": pending_after_cap,
            "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
            "stages": stages,
            "results": results,
        },
        "costUsd": total_cost,
    }))
}

fn select_triage_findings(
    store: &FindingStore,
    input: &TriageRunInput,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut missing = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(fingerprints) = &input.fingerprints {
        for reference in fingerprints {
            match store.get_finding_by_reference(reference)? {
                Some(finding)
                    if input
                        .scan_id
                        .as_ref()
                        .is_none_or(|scan_id| finding.scan_id.as_deref() == Some(scan_id)) =>
                {
                    if seen.insert(finding.fingerprint.clone()) {
                        findings.push(finding);
                    }
                }
                _ => missing.push(reference.clone()),
            }
        }
    } else {
        for finding in store.list_findings(FindingListFilter::MAX_LIMIT)? {
            if input
                .scan_id
                .as_ref()
                .is_some_and(|scan_id| finding.scan_id.as_deref() != Some(scan_id))
            {
                continue;
            }
            findings.push(finding);
        }
    }

    Ok((findings, missing))
}

#[derive(Debug, Clone)]
struct VerifyFindingInput {
    fingerprint: String,
    prompt_template: Option<String>,
}

impl VerifyFindingInput {
    fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        let fingerprint = match input.get("fingerprint") {
            Some(Value::String(value)) if !value.trim().is_empty() => value.trim().to_string(),
            Some(_) => anyhow::bail!("verify:finding fingerprint must be a non-empty string"),
            None => anyhow::bail!("verify:finding requires a fingerprint"),
        };
        let prompt_template = match input.get("VERIFY_PROMPT") {
            Some(Value::String(value)) if !value.trim().is_empty() => {
                Some(resolve_prompt_override(value.trim(), cwd)?)
            }
            Some(Value::String(_)) | None => None,
            Some(_) => anyhow::bail!("verify:finding VERIFY_PROMPT must be a string"),
        };

        Ok(Self {
            fingerprint,
            prompt_template,
        })
    }
}

const VERIFY_SYSTEM_PROMPT: &str = r#"You are Kuzushi's exploitability verification agent.
Return only JSON with these fields:
{"fingerprint":"...","exploitable":true|false,"poc_payload":string|null,"poc_description":"...","attack_vector":string|null,"preconditions":["..."],"confidence":0.0-1.0}."#;

fn run_verify_finding(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "verify:finding needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("verify:finding requires a findings store for the active workspace")?;
    let input = VerifyFindingInput::from_tool_input(&input, workspace.root())?;
    let Some(finding) = store.get_finding_by_reference(&input.fingerprint)? else {
        return Ok(json!({
            "ok": false,
            "output": format!("[-] No finding with fingerprint '{}'.", input.fingerprint),
        }));
    };
    let Some(triage) = finding.triage.clone() else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "[-] Finding '{}' has no triage verdict. Run triage:run first.",
                finding.fingerprint
            ),
        }));
    };
    let runtime = runtime.context(
        "verify:finding requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = ctx.config.model.clone().context(
        "verify:finding requires an explicit model in config.toml or KUZUSHI_MODEL; Kuzushi will not choose a fallback model",
    )?;

    let prompt = build_verify_prompt(&finding, &triage, input.prompt_template.as_deref())?;
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        workspace.root().to_path_buf(),
        VERIFY_SYSTEM_PROMPT.to_string(),
        prompt,
    ))?;
    let raw = match response.structured {
        Some(value) => value,
        None => parse_json_object_from_agent_text(&response.text).with_context(|| {
            "verify:finding expected pi-agent-core to return a JSON verification result"
        })?,
    };
    let result = normalize_verification_result(raw, &finding.fingerprint)?;
    let exploitable = result
        .get("exploitable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let verdict = if exploitable {
        "VULNERABLE"
    } else {
        "not-exploitable"
    };
    let mut lines = vec![
        "[+] verify:finding complete".to_string(),
        format!("      {verdict}"),
    ];
    if let Some(vector) = result
        .get("attackVector")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        lines.push(format!("      vector: {vector}"));
    }
    lines.push("      cost=$0.0000".to_string());

    Ok(json!({
        "ok": true,
        "output": lines.join("\n"),
        "data": result,
        "costUsd": 0.0,
    }))
}

/// Empirical exploit-gated verify: scaffolds a sandboxed test harness from
/// the finding's location and observes whether it crashes. Promotes to
/// `proof_level=4` only on observed crash inside an isolating sandbox.
/// Complementary to (not a replacement for) the LLM-driven `verify:finding`.
fn run_verify_exploit(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "verify:exploit needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("verify:exploit requires a findings store for the active workspace")?;

    let fingerprint = match input.get("fingerprint") {
        Some(Value::String(value)) if !value.trim().is_empty() => value.trim().to_string(),
        Some(_) => anyhow::bail!("verify:exploit fingerprint must be a non-empty string"),
        None => anyhow::bail!("verify:exploit requires a fingerprint"),
    };
    let trust_plain = input
        .get("trustPlainBackend")
        .or_else(|| input.get("trust_plain_backend"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let timeout_ms = input
        .get("timeoutMs")
        .or_else(|| input.get("timeout_ms"))
        .and_then(Value::as_u64)
        .unwrap_or(60_000);

    let Some(finding) = store.get_finding_by_reference(&fingerprint)? else {
        return Ok(json!({
            "ok": false,
            "output": format!("[-] No finding with fingerprint '{}'.", fingerprint),
        }));
    };

    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("verify:exploit could not start a tokio runtime")?
        .block_on(crate::verify::verify_finding(
            &finding,
            crate::verify::VerifyOptions {
                backend: None,
                timeout_ms,
                trust_plain_backend: trust_plain,
            },
        ))?;

    // Persist the outcome so downstream tools (`/findings`, patch:finding,
    // PR comments) can see the empirical proof level without re-running.
    let mut persisted_id: Option<i64> = None;
    if let Some(finding_db_id) = finding.id {
        let record = outcome.to_persisted();
        match store.save_verification(finding_db_id, &record) {
            Ok(id) => persisted_id = Some(id),
            Err(err) => eprintln!(
                "[verify:exploit] could not persist verification for finding {}: {err}",
                finding.fingerprint
            ),
        }
    }

    let summary = format!(
        "[+] verify:exploit  proof_level={}  verdict={}  backend={:?}  duration_ms={}",
        outcome.proof_level,
        outcome.proof_verdict.as_str(),
        outcome.backend,
        outcome.duration_ms
    );
    let payload = crate::verify::to_tool_json(&finding, &outcome);
    let mut response = payload;
    if let Some(obj) = response.as_object_mut() {
        obj.insert("output".to_string(), Value::String(summary));
        obj.insert("costUsd".to_string(), json!(outcome.cost_usd));
        if let Some(id) = persisted_id {
            obj.insert("verificationRowId".to_string(), json!(id));
        }
    }
    // Keep workspace var live; suppresses unused-binding warning when
    // the binding is only used to validate ctx.workspace is set.
    let _ = workspace;
    Ok(response)
}

fn build_verify_prompt(
    finding: &Finding,
    triage: &TriageOutcome,
    template: Option<&str>,
) -> Result<String> {
    let finding_json =
        serde_json::to_string_pretty(finding).context("Could not serialize finding")?;
    let triage_json = serde_json::to_string_pretty(triage).context("Could not serialize triage")?;
    let prefix = template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(
            "Verify exploitability for this triaged finding. Be conservative and return non-exploitable when runtime evidence is incomplete.",
        );
    Ok(format!(
        "{prefix}\n\nFinding JSON:\n{finding_json}\n\nTriage JSON:\n{triage_json}"
    ))
}

fn parse_json_object_from_agent_text(text: &str) -> Result<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return Ok(value);
    }

    let start = text
        .find('{')
        .context("verification output parse failed: missing JSON object start")?;
    let end = text
        .rfind('}')
        .context("verification output parse failed: missing JSON object end")?;
    if end < start {
        anyhow::bail!("verification output parse failed: malformed JSON object");
    }

    serde_json::from_str(&text[start..=end])
        .with_context(|| "verification output parse failed: invalid JSON object")
}

fn normalize_verification_result(raw: Value, fallback_fingerprint: &str) -> Result<Value> {
    let Value::Object(object) = raw else {
        anyhow::bail!("verification output parse failed: expected a JSON object");
    };

    let fingerprint = read_object_string(&object, &["fingerprint"])
        .unwrap_or_else(|| fallback_fingerprint.to_string());
    let exploitable = read_object_bool(&object, &["exploitable"]).unwrap_or(false);
    let poc_payload = read_object_nullable_string(&object, &["pocPayload", "poc_payload"]);
    let poc_description =
        read_object_string(&object, &["pocDescription", "poc_description"]).unwrap_or_default();
    let attack_vector = read_object_nullable_string(&object, &["attackVector", "attack_vector"]);
    let preconditions = read_object_string_array(&object, &["preconditions"]);
    let confidence = read_object_f64(&object, &["confidence"])
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);

    let mut result = Map::new();
    result.insert("fingerprint".to_string(), json!(fingerprint));
    result.insert("exploitable".to_string(), json!(exploitable));
    result.insert("pocPayload".to_string(), string_or_null(poc_payload));
    result.insert("pocDescription".to_string(), json!(poc_description));
    result.insert("attackVector".to_string(), string_or_null(attack_vector));
    result.insert("preconditions".to_string(), json!(preconditions));
    result.insert("confidence".to_string(), json!(confidence));

    if let Some(level) = read_object_u64(&object, &["proofLevel", "proof_level"])
        .filter(|level| (1..=4).contains(level))
    {
        result.insert("proofLevel".to_string(), json!(level));
    }
    if let Some(verdict) = read_object_string(&object, &["proofVerdict", "proof_verdict"]) {
        result.insert("proofVerdict".to_string(), json!(verdict));
    }
    if let Some(value) = normalize_object_array(&object, &["bypassAttempts", "bypass_attempts"]) {
        result.insert("bypassAttempts".to_string(), value);
    }
    if let Some(value) = normalize_code_citations(&object) {
        result.insert("codeCitations".to_string(), value);
    }
    if let Some(value) = normalize_attack_path(&object) {
        result.insert("attackPath".to_string(), value);
    }
    if let Some(value) = normalize_object_array(&object, &["assumptions"]) {
        result.insert("assumptions".to_string(), value);
    }
    if let Some(value) = normalize_controls(&object) {
        result.insert("controls".to_string(), value);
    }
    if let Some(value) = normalize_object_array(&object, &["blindspots"]) {
        result.insert("blindspots".to_string(), value);
    }

    Ok(Value::Object(result))
}

fn read_object_value<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn read_object_nullable_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys).and_then(|value| match value {
        Value::String(text) => Some(text.to_string()),
        Value::Null => None,
        _ => None,
    })
}

fn read_object_bool(object: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    read_object_value(object, keys).and_then(Value::as_bool)
}

fn read_object_f64(object: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    read_object_value(object, keys).and_then(Value::as_f64)
}

fn read_object_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    read_object_value(object, keys).and_then(Value::as_u64)
}

fn read_object_string_array(object: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    read_object_value(object, keys)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn normalize_object_array(object: &Map<String, Value>, keys: &[&str]) -> Option<Value> {
    let items = read_object_string_array(object, keys);
    if items.is_empty() {
        None
    } else {
        Some(json!(items))
    }
}

fn string_or_null(value: Option<String>) -> Value {
    match value {
        Some(value) => json!(value),
        None => Value::Null,
    }
}

fn normalize_code_citations(object: &Map<String, Value>) -> Option<Value> {
    let citations = read_object_value(object, &["codeCitations", "code_citations"])?.as_array()?;
    let mut out = Vec::new();
    for citation in citations {
        let Value::Object(citation) = citation else {
            continue;
        };
        let Some(file_path) = read_object_string(citation, &["filePath", "file_path"]) else {
            continue;
        };
        let Some(start_line) = read_object_u64(citation, &["startLine", "start_line"]) else {
            continue;
        };
        let end_line = read_object_u64(citation, &["endLine", "end_line"]).unwrap_or(start_line);
        let snippet = read_object_string(citation, &["snippet"]).unwrap_or_default();
        let description = read_object_string(citation, &["description"]).unwrap_or_default();
        if description.is_empty() {
            continue;
        }
        out.push(json!({
            "filePath": file_path,
            "startLine": start_line,
            "endLine": end_line,
            "snippet": snippet,
            "description": description,
        }));
    }
    (!out.is_empty()).then(|| json!(out))
}

fn normalize_attack_path(object: &Map<String, Value>) -> Option<Value> {
    let path = read_object_value(object, &["attackPath", "attack_path"])?.as_object()?;
    let chain = read_object_string_array(path, &["chain"]);
    let narrative = read_object_string(path, &["narrative"]).unwrap_or_default();
    if chain.is_empty() && narrative.is_empty() {
        return None;
    }
    Some(json!({
        "chain": chain,
        "narrative": narrative,
        "likelihoodReasoning": read_object_string(path, &["likelihoodReasoning", "likelihood_reasoning"]).unwrap_or_default(),
        "impactReasoning": read_object_string(path, &["impactReasoning", "impact_reasoning"]).unwrap_or_default(),
    }))
}

fn normalize_controls(object: &Map<String, Value>) -> Option<Value> {
    let controls = read_object_value(object, &["controls"])?.as_array()?;
    let mut out = Vec::new();
    for control in controls {
        let Value::Object(control) = control else {
            continue;
        };
        let Some(name) = read_object_string(control, &["name"]) else {
            continue;
        };
        let Some(description) = read_object_string(control, &["description"]) else {
            continue;
        };
        let mut item = Map::new();
        item.insert("name".to_string(), json!(name));
        item.insert("description".to_string(), json!(description));
        if let Some(file_path) = read_object_string(control, &["filePath", "file_path"]) {
            item.insert("filePath".to_string(), json!(file_path));
        }
        out.push(Value::Object(item));
    }
    (!out.is_empty()).then(|| json!(out))
}

fn optional_nonempty_string(input: &Value, key: &str) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Some(_) => anyhow::bail!("triage:run {key} must be a string"),
        None => Ok(None),
    }
}

fn resolve_prompt_override(value: &str, cwd: &Path) -> Result<String> {
    resolve_prompt_override_for_key(value, cwd, "TRIAGE_PROMPT")
}

fn resolve_prompt_override_for_key(value: &str, cwd: &Path, key: &str) -> Result<String> {
    if !looks_like_prompt_path(value) {
        return Ok(value.to_string());
    }
    let path = Path::new(value);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    fs::read_to_string(&path)
        .with_context(|| format!("Could not read {key} from {}", path.display()))
}

fn looks_like_prompt_path(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.ends_with(".md")
        || value.ends_with(".txt")
        || value.ends_with(".prompt")
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct GenericPersistedRun {
    run_id: String,
    findings_db: String,
}

fn execute_vendor_assessment_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "vendor-assessment:attach" => vendor_assessment_attach(input, ctx),
        "vendor-assessment:scope" => vendor_assessment_scope(input, ctx),
        "vendor-assessment:prompts" => vendor_assessment_prompts(input, ctx),
        "vendor-assessment:assess" => vendor_assessment_assess(input, ctx, runtime),
        _ => anyhow::bail!("unknown vendor-assessment tool {name:?}"),
    }
}

fn vendor_assessment_root(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    resolve_tool_target(input, ctx)
}

fn vendor_assessment_scope_path(root: &Path) -> PathBuf {
    root.join(".kuzushi")
        .join("vendor-assessment")
        .join("scope.json")
}

fn vendor_assessment_runs_dir(root: &Path) -> PathBuf {
    root.join(".kuzushi").join("vendor-assessment").join("runs")
}

fn load_vendor_scope(root: &Path) -> Result<Value> {
    let path = vendor_assessment_scope_path(root);
    if !path.exists() {
        return Ok(empty_vendor_scope());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Could not read vendor assessment scope {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("Could not parse vendor assessment scope {}", path.display()))
}

fn save_vendor_scope(root: &Path, scope: &Value) -> Result<PathBuf> {
    let path = vendor_assessment_scope_path(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(scope)?))
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn empty_vendor_scope() -> Value {
    json!({
        "version": "1",
        "vendorName": "",
        "productName": "",
        "primaryDomain": "",
        "useCase": "",
        "profile": "enterprise-ai",
        "dataClasses": [],
        "integrations": [],
        "documents": [],
        "updatedAt": unix_millis(),
    })
}

fn merge_vendor_scope_inputs(mut scope: Value, input: &Value) -> Value {
    let Value::Object(ref mut object) = scope else {
        return empty_vendor_scope();
    };
    for (input_keys, output_key) in [
        (&["vendorName", "vendor"][..], "vendorName"),
        (&["productName"][..], "productName"),
        (&["primaryDomain", "domain"][..], "primaryDomain"),
        (&["useCase"][..], "useCase"),
        (&["profile"][..], "profile"),
    ] {
        if let Some(value) = string_input_any(input, input_keys) {
            object.insert(output_key.to_string(), json!(value));
        }
    }
    for key in ["dataClasses", "integrations"] {
        if let Some(values) = string_array_or_csv_input(input, &[key]) {
            object.insert(key.to_string(), json!(values));
        }
    }
    object.insert("updatedAt".to_string(), json!(unix_millis()));
    scope
}

fn vendor_assessment_attach(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = vendor_assessment_root(&input, ctx)?;
    let source = string_input_any(&input, &["source", "path", "url", "target"])
        .context("vendor-assessment:attach requires source, path, url, or target")?;
    let mut scope = merge_vendor_scope_inputs(load_vendor_scope(&root)?, &input);
    let kind = string_input_any(&input, &["kind"]).unwrap_or_else(|| "other".to_string());
    let title = string_input_any(&input, &["title"]).unwrap_or_else(|| {
        Path::new(&source)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&source)
            .to_string()
    });
    let (status, text, warnings) = if source.starts_with("http://")
        || source.starts_with("https://")
    {
        (
            "referenced".to_string(),
            String::new(),
            vec![
                "Rust vendor-assessment records URL evidence but does not fetch remote documents; download the document locally and pass source/path to parse text.".to_string(),
            ],
        )
    } else {
        let path = resolve_input_path(&root, &source);
        let raw = fs::read(&path).with_context(|| {
            format!(
                "Could not read vendor assessment attachment {}",
                path.display()
            )
        })?;
        if raw.iter().take(4096).any(|byte| *byte == 0) {
            (
                "attached".to_string(),
                String::new(),
                vec!["Attachment looks binary; stored metadata without parsed text.".to_string()],
            )
        } else {
            let text = String::from_utf8_lossy(&raw[..raw.len().min(256_000)]).to_string();
            ("attached".to_string(), text, Vec::new())
        }
    };
    let doc = json!({
        "id": format!("doc-{}", unix_millis()),
        "source": source,
        "kind": kind,
        "title": title,
        "status": status,
        "text": text,
        "parseWarnings": warnings,
    });
    let documents = scope
        .as_object_mut()
        .expect("vendor scope is an object")
        .entry("documents")
        .or_insert_with(|| json!([]));
    if let Some(items) = documents.as_array_mut() {
        items.push(doc.clone());
    }
    let scope_path = save_vendor_scope(&root, &scope)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "Attached {} ({})\nScope: {}",
            doc.get("title").and_then(Value::as_str).unwrap_or("document"),
            doc.get("status").and_then(Value::as_str).unwrap_or("attached"),
            scope_path.display()
        ),
        "data": {
            "scope": scope,
            "document": doc,
            "scopePath": scope_path.display().to_string(),
        },
    }))
}

fn vendor_assessment_scope(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = vendor_assessment_root(&input, ctx)?;
    if read_bool_any(&input, &["clear"])?.unwrap_or(false) {
        let scope = empty_vendor_scope();
        let scope_path = save_vendor_scope(&root, &scope)?;
        return Ok(json!({
            "ok": true,
            "output": "Vendor assessment draft scope cleared.",
            "data": {
                "cleared": true,
                "scope": scope,
                "scopePath": scope_path.display().to_string(),
            },
        }));
    }
    let scope = merge_vendor_scope_inputs(load_vendor_scope(&root)?, &input);
    let scope_path = save_vendor_scope(&root, &scope)?;
    let docs = scope
        .get("documents")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    Ok(json!({
        "ok": true,
        "output": format!(
            "Vendor assessment scope\n  Vendor: {}\n  Product: {}\n  Documents: {}\n  Scope: {}",
            scope.get("vendorName").and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or("(unset)"),
            scope.get("productName").and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or("(unset)"),
            docs,
            scope_path.display(),
        ),
        "data": {
            "scope": scope,
            "scopePath": scope_path.display().to_string(),
        },
    }))
}

fn vendor_assessment_prompts(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = vendor_assessment_root(&input, ctx)?;
    let scope = merge_vendor_scope_inputs(load_vendor_scope(&root)?, &input);
    save_vendor_scope(&root, &scope)?;
    let run_id = string_input_any(&input, &["runId", "run_id"])
        .unwrap_or_else(|| format!("prompts-{}", unix_millis()));
    let prompts_dir = vendor_assessment_runs_dir(&root)
        .join(&run_id)
        .join("prompts");
    fs::create_dir_all(&prompts_dir)
        .with_context(|| format!("Could not create {}", prompts_dir.display()))?;
    let prompts = build_vendor_prompt_bundle(&scope);
    for (filename, content) in &prompts {
        fs::write(prompts_dir.join(filename), format!("{content}\n"))
            .with_context(|| format!("Could not write {}", prompts_dir.join(filename).display()))?;
    }
    Ok(json!({
        "ok": true,
        "output": format!(
            "Prompt bundle written to {}\nProfile: {}\nPrompts: {}",
            prompts_dir.display(),
            scope.get("profile").and_then(Value::as_str).unwrap_or("enterprise-ai"),
            prompts.len()
        ),
        "data": {
            "runId": run_id,
            "promptsDir": prompts_dir.display().to_string(),
            "prompts": prompts.iter().map(|(file, content)| json!({"fileName": file, "content": content})).collect::<Vec<_>>(),
        },
    }))
}

fn vendor_assessment_assess(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let root = vendor_assessment_root(&input, ctx)?;
    let scope = merge_vendor_scope_inputs(load_vendor_scope(&root)?, &input);
    save_vendor_scope(&root, &scope)?;
    let run_id = format!("va-{}", unix_millis());
    let run_root = vendor_assessment_runs_dir(&root).join(&run_id);
    let prompts_dir = run_root.join("prompts");
    fs::create_dir_all(&prompts_dir)
        .with_context(|| format!("Could not create {}", prompts_dir.display()))?;
    let prompts = build_vendor_prompt_bundle(&scope);
    for (filename, content) in &prompts {
        fs::write(prompts_dir.join(filename), format!("{content}\n"))?;
    }
    let has_text = vendor_scope_has_text(&scope);
    let mut report = build_vendor_fallback_report(&run_id, &scope, &run_root, has_text);
    let mut cost_usd = 0.0;
    if has_text {
        let runtime = runtime.context(
            "vendor-assessment:assess with parsed documents requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
        )?;
        let model = resolve_tool_model("vendor-assessment:assess", &input, ctx)?;
        let response = runtime.query_blocking(AgentQueryRequest::new(
            model,
            root.clone(),
            "You are Kuzushi's vendor security assessment agent. Return only JSON with overallRisk, confidence, summary, domains, mitigations, and documents.".to_string(),
            prompts
                .iter()
                .map(|(_, content)| content.as_str())
                .collect::<Vec<_>>()
                .join("\n\n"),
        ))?;
        let raw = response
            .structured
            .or_else(|| parse_json_object_from_agent_text(&response.text).ok());
        if let Some(Value::Object(object)) = raw {
            merge_vendor_report_object(&mut report, object);
        }
        cost_usd = 0.0;
    }
    let report_md = render_vendor_report_markdown(&report);
    let scope_path = run_root.join("scope.json");
    let report_path = run_root.join("report.md");
    let report_json_path = run_root.join("report.json");
    fs::write(
        &scope_path,
        format!("{}\n", serde_json::to_string_pretty(&scope)?),
    )?;
    fs::write(&report_path, format!("{report_md}\n"))?;
    fs::write(
        &report_json_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "Vendor assessment complete ({}, {}).\nReport: {}\nJSON:   {}\nScope:  {}\nPrompts: {}",
            report.get("overallRisk").and_then(Value::as_str).unwrap_or("needs-review"),
            report.get("confidence").and_then(Value::as_str).unwrap_or("low"),
            report_path.display(),
            report_json_path.display(),
            scope_path.display(),
            prompts_dir.display(),
        ),
        "data": {
            "runId": run_id,
            "report": report,
            "scope": scope,
            "artifacts": {
                "scopePath": scope_path.display().to_string(),
                "reportPath": report_path.display().to_string(),
                "reportJsonPath": report_json_path.display().to_string(),
                "promptsDir": prompts_dir.display().to_string(),
            },
        },
        "costUsd": cost_usd,
    }))
}

fn build_vendor_prompt_bundle(scope: &Value) -> Vec<(String, String)> {
    let pretty_scope = serde_json::to_string_pretty(scope).unwrap_or_else(|_| "{}".to_string());
    vec![
        (
            "overview.md".to_string(),
            format!(
                "Assess this vendor scope for enterprise security risk. Ground all conclusions in attached document text when present.\n\nScope:\n{pretty_scope}"
            ),
        ),
        (
            "evidence-review.md".to_string(),
            "Extract concrete controls, gaps, integrations, data classes, and contractual commitments from the attached evidence.".to_string(),
        ),
        (
            "follow-up-questions.md".to_string(),
            "List high-signal follow-up questions for missing security evidence.".to_string(),
        ),
    ]
}

fn vendor_scope_has_text(scope: &Value) -> bool {
    scope
        .get("documents")
        .and_then(Value::as_array)
        .is_some_and(|documents| {
            documents.iter().any(|doc| {
                doc.get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.trim().is_empty())
            })
        })
}

fn build_vendor_fallback_report(
    run_id: &str,
    scope: &Value,
    run_root: &Path,
    document_backed: bool,
) -> Value {
    let docs = scope
        .get("documents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({
        "runId": run_id,
        "overallRisk": if document_backed { "needs-review" } else { "intake" },
        "confidence": if document_backed { "medium" } else { "low" },
        "summary": if document_backed {
            "Assessment synthesized from attached vendor evidence."
        } else {
            "No parsed evidence was attached; collect documents before making a risk decision."
        },
        "documents": docs,
        "domains": [],
        "mitigations": [],
        "artifacts": {
            "scopePath": run_root.join("scope.json").display().to_string(),
            "reportPath": run_root.join("report.md").display().to_string(),
            "reportJsonPath": run_root.join("report.json").display().to_string(),
            "promptsDir": run_root.join("prompts").display().to_string(),
        },
    })
}

fn merge_vendor_report_object(report: &mut Value, object: Map<String, Value>) {
    if let Value::Object(report_object) = report {
        for key in [
            "overallRisk",
            "confidence",
            "summary",
            "domains",
            "mitigations",
            "documents",
        ] {
            if let Some(value) = object.get(key).cloned() {
                report_object.insert(key.to_string(), value);
            }
        }
    }
}

fn render_vendor_report_markdown(report: &Value) -> String {
    let mut lines = vec![
        "# Vendor AI Security Assessment Report".to_string(),
        String::new(),
        format!(
            "Overall risk: {}",
            report
                .get("overallRisk")
                .and_then(Value::as_str)
                .unwrap_or("needs-review")
        ),
        format!(
            "Confidence: {}",
            report
                .get("confidence")
                .and_then(Value::as_str)
                .unwrap_or("low")
        ),
        String::new(),
        report
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("No summary supplied.")
            .to_string(),
        String::new(),
        "## Appendix".to_string(),
        format!(
            "Documents: {}",
            report
                .get("documents")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        ),
    ];
    if let Some(items) = report.get("mitigations").and_then(Value::as_array) {
        lines.push(String::new());
        lines.push("## Mitigations".to_string());
        for item in items {
            lines.push(format!("- {}", json_summary(item)));
        }
    }
    lines.join("\n")
}

fn run_chrome_rce_scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "chrome-rce:scan target is not a directory: {}",
            target.display()
        );
    }
    let mut findings = Vec::new();
    collect_chrome_rce_findings(&target, &target, &mut findings)?;
    let persisted = persist_tool_findings("chrome-rce", &target, &findings, ctx)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "chrome-rce:scan found {} finding{} under {}",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            target.display()
        ),
        "data": {
            "target": target.display().to_string(),
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        },
    }))
}

fn collect_chrome_rce_findings(root: &Path, dir: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if should_skip_path(&name.to_string_lossy()) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_chrome_rce_findings(root, &path, findings)?;
        } else if file_type.is_file() && is_chrome_rce_source_path(root, &path) {
            let raw = fs::read(&path).unwrap_or_default();
            if raw.iter().take(4096).any(|byte| *byte == 0) {
                continue;
            }
            let text = String::from_utf8_lossy(&raw);
            if !text.contains("DuplicateHandle") {
                continue;
            }
            if text.contains("IsPseudoHandle")
                || text.contains("INVALID_HANDLE_VALUE")
                || text.contains("IsValidHandleValue")
                || text.contains("reinterpret_cast<intptr_t>")
            {
                continue;
            }
            for (index, line) in text.lines().enumerate() {
                if line.contains("DuplicateHandle") {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string();
                    findings.push(Finding::new_tool(
                        "chrome-rce",
                        "chrome-rce-mojo-broker-pseudohandle-reject",
                        relative,
                        (index + 1) as u32,
                        None,
                        Severity::High,
                        "::DuplicateHandle is called in a Chrome IPC/broker path without an obvious pseudo-handle reject. Anchored to CVE-2025-2783; reject Win32 pseudo-handles before duplicating peer-supplied handles.",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn is_chrome_rce_source_path(root: &Path, path: &Path) -> bool {
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    if !matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp") {
        return false;
    }
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/");
    relative.contains("/ipc/")
        || relative.contains("/mojo/")
        || relative.contains("/services/")
        || relative.contains("/sandbox/")
        || relative.contains("broker")
}

fn run_chrome_rce_review_trigger(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let Some(diff_base) = string_input_any(&input, &["diffBase", "diff_base"]) else {
        return Ok(json!({
            "ok": true,
            "output": "chrome-rce:review-trigger skipped: pass diffBase to enable PR hot-path review.",
            "data": {
                "target": target.display().to_string(),
                "count": 0,
                "findings": [],
            },
        }));
    };
    let changed = chrome_rce_changed_files(&target, &diff_base)?;
    let findings = changed
        .iter()
        .filter_map(|file| chrome_rce_hot_path_finding(file))
        .collect::<Vec<_>>();
    let persisted = persist_tool_findings("chrome-rce", &target, &findings, ctx)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "chrome-rce:review-trigger matched {} hot path{} vs {}",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            diff_base
        ),
        "data": {
            "target": target.display().to_string(),
            "diffBase": diff_base,
            "changedFiles": changed,
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        },
    }))
}

fn chrome_rce_changed_files(target: &Path, diff_base: &str) -> Result<Vec<String>> {
    let verify = Command::new("git")
        .args(["rev-parse", "--verify", diff_base])
        .current_dir(target)
        .output()
        .with_context(|| "chrome-rce:review-trigger requires git; install git or omit diffBase")?;
    if !verify.status.success() {
        anyhow::bail!(
            "chrome-rce:review-trigger could not resolve diffBase {:?}: {}",
            diff_base,
            String::from_utf8_lossy(&verify.stderr).trim()
        );
    }
    let output = Command::new("git")
        .args(["diff", "--name-only", &format!("{diff_base}...HEAD")])
        .current_dir(target)
        .output()
        .with_context(|| "chrome-rce:review-trigger requires git; install git or omit diffBase")?;
    if !output.status.success() {
        anyhow::bail!(
            "chrome-rce:review-trigger git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn chrome_rce_hot_path_finding(file: &str) -> Option<Finding> {
    let (rule_id, severity, message) = if file
        .ends_with("v8/src/maglev/maglev-phi-representation-selector.cc")
    {
        (
                "chrome-rce-hot-path-v8-maglev-phi-representation-selector",
                Severity::High,
                "V8 Maglev phi representation selector changed; this path is anchored to CVE-2026-3910 and needs compiler-specialist review.",
            )
    } else if file.contains("v8/src/maglev/") {
        (
                "chrome-rce-hot-path-v8-maglev",
                Severity::Medium,
                "V8 Maglev IR path changed; review representation tracking and type narrowing against historical Chrome RCE shapes.",
            )
    } else if file.contains("v8/src/compiler/backend/arm64/") {
        (
                "chrome-rce-hot-path-v8-arm64-codegen",
                Severity::Medium,
                "V8 ARM64 backend path changed; review cross-architecture register-width assumptions against CVE-2024-7965.",
            )
    } else if file.ends_with("v8/src/compiler/typer.cc") {
        (
                "chrome-rce-hot-path-v8-typer",
                Severity::Medium,
                "V8 typer changed; review type narrowing and CheckMaps preservation against CVE-2025-6554-family issues.",
            )
    } else if file.ends_with("v8/src/compiler/redundancy-elimination.cc") {
        (
                "chrome-rce-hot-path-v8-redundancy-elimination",
                Severity::Medium,
                "V8 redundancy elimination changed; review removed checks before object access against historical CheckMaps issues.",
            )
    } else if file.contains("third_party/dawn/src/dawn/wire/server/") {
        (
                "chrome-rce-hot-path-dawn-wire-server",
                Severity::High,
                "Dawn wire server path changed; review objects_.Get plus re-entrant call plus reuse patterns anchored to CVE-2026-5281-family UAFs.",
            )
    } else if file.contains("third_party/dawn/generator/templates/dawn/wire/server/") {
        (
                "chrome-rce-hot-path-dawn-wire-server-templates",
                Severity::High,
                "Dawn wire server template changed; generated dispatcher code needs review for re-entrant pointer reuse.",
            )
    } else {
        return None;
    };
    Some(Finding::new_tool(
        "chrome-rce",
        rule_id,
        file.to_string(),
        1,
        None,
        severity,
        message,
    ))
}

fn run_vuln_scout_audit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    run_plugin_finding_adapter(
        PluginAdapterSpec {
            tool_name: "vuln-scout:audit",
            tool_slug: "vuln-scout",
            package_name: "@kuzushi/vuln-scout",
            env_var: "KUZUSHI_VULN_SCOUT_PLUGIN",
            install_hint: "pnpm add @kuzushi/vuln-scout",
            prompt_title:
                "Run a whitebox pentest audit using Vuln Scout-style read-only repository analysis.",
            allow_skill_filter: false,
        },
        input,
        ctx,
        runtime,
    )
}

fn run_tob_audit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    validate_requested_tob_skills(&input)?;
    run_plugin_finding_adapter(
        PluginAdapterSpec {
            tool_name: "tob:audit",
            tool_slug: "tob-audit",
            package_name: "@kuzushi/tob-skills",
            env_var: "KUZUSHI_TOB_SKILLS_DIR",
            install_hint: "pnpm add @kuzushi/tob-skills",
            prompt_title:
                "Run a Trail of Bits skills-style audit using read-only repository analysis.",
            allow_skill_filter: true,
        },
        input,
        ctx,
        runtime,
    )
}

#[derive(Debug, Clone, Copy)]
struct PluginAdapterSpec<'a> {
    tool_name: &'a str,
    tool_slug: &'static str,
    package_name: &'static str,
    env_var: &'static str,
    install_hint: &'static str,
    prompt_title: &'static str,
    allow_skill_filter: bool,
}

fn run_plugin_finding_adapter(
    spec: PluginAdapterSpec<'_>,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "{} target is not a directory: {}",
            spec.tool_name,
            target.display()
        );
    }
    let plugin_root = resolve_required_plugin_root(&input, spec)?;
    let runtime = runtime.context(format!(
        "{} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
        spec.tool_name
    ))?;
    let model = resolve_tool_model(spec.tool_name, &input, ctx)?;
    let max_findings =
        positive_usize_input(&input, &["maxFindings", "max_findings"], "maxFindings")?
            .unwrap_or(50)
            .min(200);
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        target.clone(),
        format!(
            "You are Kuzushi's {} pi-agent-core adapter. Return only JSON matching {{\"findings\":[{{\"ruleId\":\"...\",\"filePath\":\"relative/path\",\"startLine\":1,\"severity\":\"critical|high|medium|low|info\",\"message\":\"evidence-backed finding\",\"evidence\":\"source-grounded proof\"}}]}}.",
            spec.tool_name
        ),
        build_plugin_adapter_prompt(spec, &target, &plugin_root, &input, &inventory),
    ))?;
    let raw = response.structured.unwrap_or_else(|| {
        parse_json_object_from_agent_text(&response.text).unwrap_or(json!({"findings": []}))
    });
    let findings = normalize_agent_json_findings(raw, &target, spec.tool_slug, max_findings)?;
    let persisted = persist_tool_findings(spec.tool_slug, &target, &findings, ctx)?;
    Ok(json!({
        "ok": true,
        "output": render_generic_findings_output(spec.tool_name, &target, &findings, &persisted),
        "data": {
            "target": target.display().to_string(),
            "pluginRoot": plugin_root.display().to_string(),
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

fn build_plugin_adapter_prompt(
    spec: PluginAdapterSpec<'_>,
    target: &Path,
    plugin_root: &Path,
    input: &Value,
    inventory: &[(String, String)],
) -> String {
    let mut lines = vec![
        spec.prompt_title.to_string(),
        format!("Target: {}", target.display()),
        format!("Resolved plugin root: {}", plugin_root.display()),
        "Use only the provided repository snippets; do not claim runtime exploitability."
            .to_string(),
    ];
    if spec.allow_skill_filter {
        if let Some(skills) = string_array_or_csv_input(input, &["skills"]) {
            lines.push(format!("Requested skills: {}", skills.join(", ")));
        }
    }
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.join("\n")
}

fn resolve_required_plugin_root(input: &Value, spec: PluginAdapterSpec<'_>) -> Result<PathBuf> {
    let raw = string_input_any(input, &["pluginRoot", "pluginPath", "plugin_root", "plugin_path"])
        .or_else(|| std::env::var(spec.env_var).ok().filter(|value| !value.trim().is_empty()))
        .with_context(|| {
            format!(
                "{} requires {}. Install with `{}` or pass {{\"pluginRoot\":\"/path/to/plugin\"}} or set {}.",
                spec.tool_name, spec.package_name, spec.install_hint, spec.env_var
            )
        })?;
    let path = PathBuf::from(raw.trim());
    if !path.exists() {
        anyhow::bail!(
            "{} plugin root does not exist: {}. Install with `{}` or update {}.",
            spec.tool_name,
            path.display(),
            spec.install_hint,
            spec.env_var
        );
    }
    Ok(path)
}

fn list_tob_skills(input: Value) -> Result<Value> {
    let declared = [
        "fp-check",
        "variant-analysis",
        "sharp-edges",
        "insecure-defaults",
        "static-analysis",
        "differential-review",
    ];
    let spec = PluginAdapterSpec {
        tool_name: "tob:skills",
        tool_slug: "tob-audit",
        package_name: "@kuzushi/tob-skills",
        env_var: "KUZUSHI_TOB_SKILLS_DIR",
        install_hint: "pnpm add @kuzushi/tob-skills",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let root = match resolve_required_plugin_root(&input, spec) {
        Ok(root) => root,
        Err(error) => {
            return Ok(json!({
                "ok": false,
                "output": error.to_string(),
                "data": {
                    "declared": declared,
                    "resolvable": [],
                    "unresolved": declared,
                },
            }));
        }
    };
    let mut resolvable = Vec::new();
    for name in declared {
        let path = root.join(name);
        if path.exists() {
            resolvable.push(json!({"id": name, "path": path.display().to_string()}));
        }
    }
    let unresolved = declared
        .iter()
        .filter(|name| {
            !resolvable
                .iter()
                .any(|row| row.get("id").and_then(Value::as_str) == Some(*name))
        })
        .copied()
        .collect::<Vec<_>>();
    Ok(json!({
        "ok": true,
        "output": format!("Resolvable ToB skill plugins: {}\nDeclared but not resolvable: {}", resolvable.len(), unresolved.join(", ")),
        "data": {
            "pluginRoot": root.display().to_string(),
            "declared": declared,
            "resolvable": resolvable,
            "unresolved": unresolved,
        },
    }))
}

fn validate_requested_tob_skills(input: &Value) -> Result<()> {
    let Some(skills) = string_array_or_csv_input(input, &["skills"]) else {
        return Ok(());
    };
    let declared = [
        "fp-check",
        "variant-analysis",
        "sharp-edges",
        "insecure-defaults",
        "static-analysis",
        "differential-review",
    ];
    let unknown = skills
        .iter()
        .filter(|skill| !declared.contains(&skill.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        anyhow::bail!(
            "tob:audit unknown skill(s): {}. Valid names: {}.",
            unknown.join(", "),
            declared.join(", ")
        );
    }
    Ok(())
}

fn run_shinsa_assessment(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let spec = PluginAdapterSpec {
        tool_name,
        tool_slug: "shinsa",
        package_name: "shinsa-plugin",
        env_var: "KUZUSHI_SHINSA_PLUGIN",
        install_hint: "install shinsa-plugin and set KUZUSHI_SHINSA_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let plugin_root = resolve_required_plugin_root(&input, spec)?;
    let runtime = runtime.context(format!(
        "{tool_name} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies."
    ))?;
    let model = resolve_tool_model(tool_name, &input, ctx)?;
    let mode = match tool_name {
        "shinsa:scan" => "compliance-scan",
        "shinsa:quick-check" => "quick-check",
        "shinsa:nist-scan" => "nist-scan",
        "shinsa:nist-quick-check" => "nist-quick-check",
        _ => "compliance-scan",
    };
    let output_dir = string_input_any(&input, &["outputDir", "output_dir"])
        .unwrap_or_else(|| "shinsa-output".to_string());
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        target.clone(),
        "You are Kuzushi's Shinsa compliance adapter. Return only JSON with summary, findings, controls, and maturity.".to_string(),
        build_shinsa_prompt(mode, &output_dir, &plugin_root, &input, &inventory),
    ))?;
    let raw = response.structured.unwrap_or_else(|| {
        parse_json_object_from_agent_text(&response.text).unwrap_or(json!({"findings": []}))
    });
    let findings = normalize_agent_json_findings(raw.clone(), &target, "shinsa", 100)?;
    let persisted = persist_tool_findings("shinsa", &target, &findings, ctx)?;
    let out_root = target.join(&output_dir);
    fs::create_dir_all(&out_root)
        .with_context(|| format!("Could not create {}", out_root.display()))?;
    let state_path = out_root.join("shinsa-state.json");
    let report_path = out_root.join("compliance-report.md");
    fs::write(
        &state_path,
        format!("{}\n", serde_json::to_string_pretty(&raw)?),
    )?;
    fs::write(
        &report_path,
        format!(
            "# Shinsa Compliance Report\n\nMode: {mode}\nFindings: {}\n",
            findings.len()
        ),
    )?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "{tool_name} complete\n  Mode:     {mode}\n  Output:   {}/\n  Artifacts: shinsa-state.json compliance-report.md\n  Findings: {}",
            output_dir,
            findings.len()
        ),
        "data": {
            "target": target.display().to_string(),
            "mode": mode,
            "pluginRoot": plugin_root.display().to_string(),
            "outputDir": output_dir,
            "statePath": state_path.display().to_string(),
            "reportPath": report_path.display().to_string(),
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

fn build_shinsa_prompt(
    mode: &str,
    output_dir: &str,
    plugin_root: &Path,
    input: &Value,
    inventory: &[(String, String)],
) -> String {
    let mut lines = vec![
        format!("Run a {mode} compliance assessment over the provided repository snippets."),
        format!("Resolved plugin root: {}", plugin_root.display()),
        format!("Artifact output directory: {output_dir}"),
        "Ground every finding in file and line evidence. Do not speculate about unread code."
            .to_string(),
    ];
    if let Some(controls) = string_array_or_csv_input(input, &["controls"]) {
        lines.push(format!("Controls filter: {}", controls.join(", ")));
    }
    if let Some(family) = string_input_any(input, &["family"]) {
        lines.push(format!("Family filter: {family}"));
    }
    if let Some(severity) = string_array_or_csv_input(input, &["severity"]) {
        lines.push(format!("Severity filter: {}", severity.join(", ")));
    }
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.join("\n")
}

fn list_shinsa_frameworks(input: Value) -> Result<Value> {
    let spec = PluginAdapterSpec {
        tool_name: "shinsa:frameworks",
        tool_slug: "shinsa",
        package_name: "shinsa-plugin",
        env_var: "KUZUSHI_SHINSA_PLUGIN",
        install_hint: "install shinsa-plugin and set KUZUSHI_SHINSA_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let root = match resolve_required_plugin_root(&input, spec) {
        Ok(root) => root,
        Err(error) => {
            return Ok(json!({
                "ok": false,
                "output": error.to_string(),
                "data": {
                    "skills": [],
                    "frameworks": ["iso27001-annex-a", "nist-sp-800-53-rev5"],
                },
            }));
        }
    };
    let skills_root = root.join("skills");
    let mut skills = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&skills_root) {
        for entry in read_dir.filter_map(|entry| entry.ok()) {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                skills.push(entry.file_name().to_string_lossy().to_string());
            }
        }
    }
    skills.sort();
    Ok(json!({
        "ok": true,
        "output": format!("shinsa-plugin path: {}\nSkill modules: {}", root.display(), skills.len()),
        "data": {
            "pluginRoot": root.display().to_string(),
            "skills": skills,
            "frameworks": ["iso27001-annex-a", "nist-sp-800-53-rev5"],
        },
    }))
}

fn execute_prompt_armor_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match tool_name {
        "prompt-armor:config" => prompt_armor_config(input, ctx),
        "prompt-armor:diff" => prompt_armor_diff(input, ctx),
        "prompt-armor:report" => prompt_armor_report(input, ctx),
        "prompt-armor:scan" | "prompt-armor:attack" | "prompt-armor:analyze" => {
            prompt_armor_runtime_tool(tool_name, input, ctx, runtime)
        }
        _ => anyhow::bail!("unknown prompt-armor tool {tool_name:?}"),
    }
}

fn prompt_armor_runtime_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let command = tool_name.trim_start_matches("prompt-armor:");
    if matches!(command, "scan" | "attack")
        && !read_bool_any(&input, &["authorized"])?.unwrap_or(false)
    {
        return Ok(json!({
            "ok": false,
            "output": format!("{tool_name} refuses to run: pass authorized=true to confirm you have authorization to test the target endpoint. This command can generate real traffic."),
        }));
    }
    let target = resolve_tool_target(&input, ctx)?;
    let spec = PluginAdapterSpec {
        tool_name,
        tool_slug: "prompt-armor",
        package_name: "promptarmor-plugin",
        env_var: "KUZUSHI_PROMPT_ARMOR_PLUGIN",
        install_hint: "install promptarmor-plugin and set KUZUSHI_PROMPT_ARMOR_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let plugin_root = resolve_required_plugin_root(&input, spec)?;
    let runtime = runtime.context(format!(
        "{tool_name} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies."
    ))?;
    let model = resolve_tool_model(tool_name, &input, ctx)?;
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        target.clone(),
        "You are Kuzushi's PromptArmor adapter. Return only JSON with findings and summary. Ground findings in source snippets when doing static analyze.".to_string(),
        build_prompt_armor_prompt(command, &plugin_root, &input, &inventory),
    ))?;
    let raw = response.structured.unwrap_or_else(|| {
        parse_json_object_from_agent_text(&response.text).unwrap_or(json!({"findings": []}))
    });
    let findings = normalize_agent_json_findings(raw, &target, "prompt-armor", 100)?;
    let persisted = persist_tool_findings("prompt-armor", &target, &findings, ctx)?;
    let output_dir = target.join(".prompt-armor");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("Could not create {}", output_dir.display()))?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "{tool_name} complete\n  Command: /{command}\n  Output: .prompt-armor/\n  Findings: {}",
            findings.len()
        ),
        "data": {
            "target": target.display().to_string(),
            "pluginRoot": plugin_root.display().to_string(),
            "command": command,
            "outputDir": output_dir.display().to_string(),
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

fn build_prompt_armor_prompt(
    command: &str,
    plugin_root: &Path,
    input: &Value,
    inventory: &[(String, String)],
) -> String {
    let mut lines = vec![
        format!("Run PromptArmor /{command} using the provided inputs."),
        format!("Resolved plugin root: {}", plugin_root.display()),
        "For scan and attack, the caller has supplied the required authorization gate.".to_string(),
    ];
    for key in [
        "endpoint",
        "suites",
        "mutations",
        "config",
        "paths",
        "focus",
        "attack",
        "mutation",
        "payload",
    ] {
        if let Some(value) = input.get(key) {
            lines.push(format!("{key}: {}", json_summary(value)));
        }
    }
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.join("\n")
}

fn prompt_armor_config(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let path = target.join("promptarmor.yaml");
    let action = string_input_any(&input, &["action"]).unwrap_or_else(|| "show".to_string());
    if action == "init" && !path.exists() {
        fs::write(
            &path,
            "version: 1\nsuites:\n  - injection\n  - tool-abuse\nmutations: []\n",
        )
        .with_context(|| format!("Could not write {}", path.display()))?;
    }
    let exists = path.exists();
    let body = if exists {
        fs::read_to_string(&path).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(json!({
        "ok": true,
        "output": if exists {
            format!("prompt-armor:config {action}\nConfig: {}", path.display())
        } else {
            format!("prompt-armor:config found no promptarmor.yaml at {}. Run with {{\"action\":\"init\"}} to scaffold one.", path.display())
        },
        "data": {
            "path": path.display().to_string(),
            "exists": exists,
            "content": body,
        },
    }))
}

fn prompt_armor_diff(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let run_a =
        string_input_any(&input, &["runA", "run_a"]).context("prompt-armor:diff requires runA")?;
    let run_b =
        string_input_any(&input, &["runB", "run_b"]).context("prompt-armor:diff requires runB")?;
    let path_a = resolve_input_path(&target, &run_a);
    let path_b = resolve_input_path(&target, &run_b);
    let text_a = fs::read_to_string(&path_a).with_context(|| {
        format!(
            "Could not read prompt-armor diff input {}",
            path_a.display()
        )
    })?;
    let text_b = fs::read_to_string(&path_b).with_context(|| {
        format!(
            "Could not read prompt-armor diff input {}",
            path_b.display()
        )
    })?;
    let delta = text_b.lines().count() as isize - text_a.lines().count() as isize;
    Ok(json!({
        "ok": true,
        "output": format!("prompt-armor:diff complete\n  runA: {}\n  runB: {}\n  lineDelta: {}", path_a.display(), path_b.display(), delta),
        "data": {
            "runA": path_a.display().to_string(),
            "runB": path_b.display().to_string(),
            "lineDelta": delta,
        },
    }))
}

fn prompt_armor_report(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let out_dir = target.join(".prompt-armor");
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("Could not create {}", out_dir.display()))?;
    let output = string_input_any(&input, &["output"])
        .map(|path| resolve_input_path(&target, &path))
        .unwrap_or_else(|| out_dir.join("report.md"));
    let mut entries = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&out_dir) {
        for entry in read_dir.filter_map(|entry| entry.ok()) {
            entries.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    entries.sort();
    let body = format!(
        "# PromptArmor Report\n\nArtifacts in `.prompt-armor`: {}\n",
        if entries.is_empty() {
            "none".to_string()
        } else {
            entries.join(", ")
        }
    );
    fs::write(&output, &body).with_context(|| format!("Could not write {}", output.display()))?;
    Ok(json!({
        "ok": true,
        "output": format!("prompt-armor:report complete\nReport: {}", output.display()),
        "data": {
            "reportPath": output.display().to_string(),
            "artifacts": entries,
        },
    }))
}

fn run_pipeline_task_selector(input: Value, _ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let requested = string_array_or_csv_input(&input, &["tasks", "taskIds", "task_ids"])
        .unwrap_or_else(|| {
            vec![
                "semgrep".to_string(),
                "dep-hygiene".to_string(),
                "secret-scan".to_string(),
                "iac-scan".to_string(),
            ]
        });
    let disabled =
        string_array_or_csv_input(&input, &["disabledTasks", "disabled_tasks"]).unwrap_or_default();
    let selected = requested
        .into_iter()
        .filter(|task| {
            !disabled
                .iter()
                .any(|disabled| same_scan_task(task, disabled))
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "ok": true,
        "output": format!("pipeline:task-selector selected {} task{}", selected.len(), if selected.len() == 1 { "" } else { "s" }),
        "data": {
            "tasks": selected,
            "disabledTasks": disabled,
        },
    }))
}

fn run_pipeline_approval_gate(input: Value) -> Result<Value> {
    let approved = read_bool_any(&input, &["approved", "approve"])?.unwrap_or(true);
    Ok(json!({
        "ok": approved,
        "output": if approved {
            "pipeline:approval-before-verification approved"
        } else {
            "pipeline:approval-before-verification denied"
        },
        "data": {
            "approved": approved,
        },
    }))
}

fn normalize_agent_json_findings(
    raw: Value,
    target: &Path,
    tool_slug: &str,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let findings_value = match raw {
        Value::Object(object) => object
            .get("findings")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        Value::Array(items) => Value::Array(items),
        _ => Value::Array(Vec::new()),
    };
    let Value::Array(items) = findings_value else {
        anyhow::bail!("{tool_slug} adapter output parse failed: findings must be an array");
    };
    let mut findings = Vec::new();
    for item in items.into_iter().take(max_findings) {
        let Value::Object(object) = item else {
            continue;
        };
        let rule_id = read_object_string(&object, &["ruleId", "rule_id", "id"])
            .unwrap_or_else(|| format!("{tool_slug}/finding"));
        let file_path = normalize_agentic_file_path(
            read_object_string(&object, &["filePath", "file_path", "path"])
                .unwrap_or_else(|| "unknown".to_string()),
            target,
        );
        let start_line = read_object_u64(&object, &["startLine", "start_line", "line"])
            .filter(|line| *line > 0)
            .unwrap_or(1) as u32;
        let end_line = read_object_u64(&object, &["endLine", "end_line"])
            .filter(|line| *line > 0)
            .map(|line| line as u32);
        let severity = generic_severity(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or("medium"),
        );
        let mut message = read_object_string(&object, &["message", "title", "summary"])
            .unwrap_or_else(|| rule_id.clone());
        for (label, keys) in [
            ("Evidence", &["evidence", "proof"][..]),
            ("CWE", &["cwe"][..]),
            ("Control", &["control"][..]),
            ("Recommendation", &["recommendation", "recommendedFix"][..]),
        ] {
            if let Some(value) = read_object_string(&object, keys) {
                message.push_str(&format!("\n{label}: {value}"));
            } else {
                let values = read_object_string_array(&object, keys);
                if !values.is_empty() {
                    message.push_str(&format!("\n{label}: {}", values.join(", ")));
                }
            }
        }
        findings.push(Finding::new_tool(
            tool_slug.to_string(),
            rule_id,
            file_path,
            start_line,
            end_line,
            severity,
            message,
        ));
    }
    Ok(findings)
}

fn generic_severity(value: &str) -> Severity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" | "error" => Severity::High,
        "medium" | "warning" => Severity::Medium,
        "low" => Severity::Low,
        "info" | "informational" => Severity::Info,
        _ => Severity::Unknown,
    }
}

fn persist_tool_findings(
    tool_slug: &str,
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<GenericPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = format!("{tool_slug}-{}", Uuid::new_v4());
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;
    Ok(Some(GenericPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

fn render_generic_findings_output(
    tool_name: &str,
    target: &Path,
    findings: &[Finding],
    persisted: &Option<GenericPersistedRun>,
) -> String {
    let mut lines = vec![format!(
        "{tool_name} complete for {}\n  Findings: {}",
        target.display(),
        findings.len()
    )];
    if let Some(persisted) = persisted {
        lines.push(format!(
            "  Persisted run: {} ({})",
            persisted.run_id, persisted.findings_db
        ));
    }
    if !findings.is_empty() {
        lines.push(String::new());
        lines.push("Top findings:".to_string());
        for finding in findings.iter().take(10) {
            lines.push(format!(
                "  - {} - {} - {}:{}",
                finding.severity.as_str(),
                finding.rule_id,
                finding.file_path,
                finding.start_line
            ));
        }
    }
    lines.join("\n")
}

fn resolve_tool_model(
    tool_name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    string_input_any(input, &["model"])
        .or_else(|| ctx.config.model.clone())
        .with_context(|| {
            format!(
                "{tool_name} requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model"
            )
        })
}

fn string_input_any(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn string_array_or_csv_input(input: &Value, keys: &[&str]) -> Option<Vec<String>> {
    keys.iter().find_map(|key| match input.get(*key) {
        Some(Value::String(value)) => Some(
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect(),
        ),
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect(),
        ),
        _ => None,
    })
}

fn read_bool_any(input: &Value, keys: &[&str]) -> Result<Option<bool>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return value
                .as_bool()
                .map(Some)
                .with_context(|| format!("{key} must be a boolean"));
        }
    }
    Ok(None)
}

fn resolve_input_path(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value.trim());
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

pub struct ToolExecutionContext<'a> {
    pub config: &'a V2Config,
    pub workspace: Option<&'a WorkspaceTarget>,
    pub findings_store: Option<&'a FindingStore>,
}

impl<'a> ToolExecutionContext<'a> {
    pub fn artifact_knowledge_context(
        &self,
        target: &Path,
        query: &str,
        limit: usize,
    ) -> ArtifactKnowledgePromptContext {
        if let Some(workspace) = self
            .workspace
            .filter(|workspace| workspace.root() == target)
        {
            return artifact_knowledge_prompt_context(workspace, query, limit);
        }

        match WorkspaceTarget::new(target) {
            Ok(workspace) => artifact_knowledge_prompt_context(&workspace, query, limit),
            Err(error) => ArtifactKnowledgePromptContext {
                db_path: target
                    .join(".kuzushi")
                    .join("v2")
                    .join("artifact-kb.sqlite3")
                    .display()
                    .to_string(),
                missing_db: false,
                query: query.to_string(),
                status: format!("unavailable: {error}"),
                snippets: Vec::new(),
            },
        }
    }
}

fn catalog_module() -> BuiltinModule {
    builtin_module(
        "catalog",
        "Catalog",
        ModuleKind::Governance,
        "List native modules and tools.",
        vec![
            tool("catalog:modules", "List native modules."),
            tool("catalog:tools", "List native tools."),
        ],
        vec![],
    )
}

fn config_module() -> BuiltinModule {
    builtin_module(
        "config",
        "Config",
        ModuleKind::Governance,
        "Inspect effective configuration.",
        vec![tool("config:show", "Show the effective config.")],
        vec![],
    )
}

fn router_show_tool(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    use crate::agent_router::{AgentRole, AgentRouter};
    use crate::config::ConfigPaths;

    // Load models.toml if present. Best-effort — missing file = empty router.
    let target = ctx
        .workspace
        .map(|workspace| workspace.root().to_path_buf());
    let router = ConfigPaths::from_target(target.as_deref())
        .ok()
        .and_then(|paths| AgentRouter::load(&paths).ok())
        .unwrap_or_default();

    let mut roles = Vec::with_capacity(AgentRole::all().len());
    for role in AgentRole::all() {
        let key = role.option_store_key();
        // Operator override merged via effective_tool_input lives in `input`.
        let option_override = input
            .as_object()
            .and_then(|obj| obj.get(&key))
            .and_then(Value::as_str)
            .map(str::to_string);

        let toml_route = router.route(*role).cloned();

        let effective = option_override
            .clone()
            .or_else(|| toml_route.as_ref().map(|r| r.primary.clone()))
            .or_else(|| router.default_model().map(str::to_string))
            .or_else(|| ctx.config.model.clone());

        roles.push(json!({
            "role": role.as_key(),
            "optionKey": key,
            "operatorOverride": option_override,
            "tomlPrimary": toml_route.as_ref().map(|r| r.primary.clone()),
            "tomlFallbacks": toml_route.as_ref().map(|r| r.fallbacks.clone()).unwrap_or_default(),
            "effective": effective,
        }));
    }

    Ok(json!({
        "ok": true,
        "configModel": ctx.config.model,
        "tomlDefaultModel": router.default_model(),
        "roles": roles,
    }))
}

fn run_full_mode_hunt_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::config::ConfigPaths;
    use crate::full_mode_multi::{
        plan as fm_plan, report_to_tool_json, run as run_full_mode_multi, FullModeConfig,
        FullModeLanguage,
    };
    use crate::spend::SpendLimiter;
    use std::sync::Arc;

    let target = resolve_tool_target(&input, ctx)?;
    let language = match input
        .get("language")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("c") | None => FullModeLanguage::C,
        Some("unknown") => FullModeLanguage::Unknown,
        Some(other) => anyhow::bail!("full-mode:hunt: unknown language {other:?}"),
    };
    let max_tokens = input
        .get("maxTokensPerChunk")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(120_000);
    let deposit = input
        .get("depositUsdPerChunk")
        .and_then(Value::as_f64)
        .unwrap_or(2.0);
    let dry_run = input
        .get("dryRun")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Optional scope file: explicit path wins; otherwise look for the
    // since.txt the --since flag wrote.
    let mut scope_files: Option<Vec<std::path::PathBuf>> = None;
    let scope_path = input
        .get("scopeFile")
        .and_then(Value::as_str)
        .map(std::path::PathBuf::from)
        .or_else(|| {
            ctx.workspace.map(|w| {
                w.findings_db_path()
                    .with_file_name("since.txt")
                    .to_path_buf()
            })
        });
    if let Some(p) = scope_path {
        if p.exists() {
            let body = std::fs::read_to_string(&p)
                .with_context(|| format!("could not read scope file {}", p.display()))?;
            let lines: Vec<std::path::PathBuf> = body
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(std::path::PathBuf::from)
                .collect();
            if !lines.is_empty() {
                scope_files = Some(lines);
            }
        }
    }

    let cfg = FullModeConfig {
        workspace_root: target.clone(),
        max_tokens_per_chunk: max_tokens,
        deposit_usd_per_chunk: deposit,
        include_extensions: Vec::new(),
        language,
        dry_run,
        scope_files,
    };

    if dry_run {
        let plan = fm_plan(&cfg)?;
        let model_hint = ctx.config.model.as_deref();
        let cost = crate::full_mode_cost_summary(&plan, model_hint);
        return Ok(json!({
            "ok": true,
            "data": {
                "findings": [],
                "plan": plan,
                "chunksDispatched": 0,
                "chunksFailed": 0,
                "costUsd": 0.0,
                "dryRun": true,
            },
            "summary": {
                "chunks": cost.chunks,
                "files": cost.files,
                "totalTokens": cost.total_tokens,
                "estUsdLow": cost.usd_low,
                "estUsdHigh": cost.usd_high,
                "dryRun": true,
            },
        }));
    }

    let runtime = runtime.ok_or_else(|| {
        anyhow::anyhow!("full-mode:hunt requires an agent runtime; none configured")
    })?;
    let paths = ctx
        .workspace
        .map(|w| ConfigPaths {
            home_dir: dirs::home_dir().unwrap_or_default(),
            target_dir: Some(w.root().to_path_buf()),
        })
        .unwrap_or_else(|| ConfigPaths {
            home_dir: dirs::home_dir().unwrap_or_default(),
            target_dir: None,
        });
    let router = Arc::new(AgentRouter::load(&paths)?);
    let inner_arc: Arc<dyn AgentRuntime> = unsafe_clone_runtime_ref(runtime);
    let routed = RoutedRuntime::new(inner_arc, router, ctx.config.model.clone());

    // Spend ledger lives in the workspace findings DB.
    let limiter = ctx
        .workspace
        .map(|w| SpendLimiter::open(w.findings_db_path()))
        .transpose()?;

    let report = run_full_mode_multi(&routed, limiter.as_ref(), &cfg)?;

    // Persist findings into the workspace store.
    if let Some(workspace) = ctx.workspace {
        let store = FindingStore::open(workspace.findings_db_path())?;
        let scan_id = format!("full-mode-{}", uuid::Uuid::new_v4());
        store.insert_scan_run(&scan_id, workspace.root(), "running")?;
        for f in &report.findings {
            let _ = store.insert_finding(&scan_id, f)?;
        }
        store.complete_scan_run(&scan_id, "completed", report.findings.len())?;
    }

    Ok(report_to_tool_json(&report))
}

fn run_classifier_score_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::classifier_gate::{ClassifierConfig, LikelyVulnClassifier};
    use crate::config::ConfigPaths;
    use std::sync::Arc;

    let runtime = runtime.ok_or_else(|| {
        anyhow::anyhow!("classifier-gate:score requires an agent runtime; none configured")
    })?;
    let workspace = ctx
        .workspace
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score requires a workspace target"))?;
    let store = FindingStore::open(workspace.findings_db_path())?;

    let fingerprint = input
        .get("findingFingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score: findingFingerprint is required"))?;
    let finding = store
        .get_finding_by_reference(fingerprint)?
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score: no finding for {fingerprint:?}"))?;
    let target_percentile = input
        .get("targetPercentile")
        .and_then(Value::as_f64)
        .map(|v| v as f32)
        .unwrap_or(0.80);

    let paths = ConfigPaths {
        home_dir: dirs::home_dir().unwrap_or_default(),
        target_dir: Some(workspace.root().to_path_buf()),
    };
    let router = Arc::new(AgentRouter::load(&paths)?);
    let inner_arc: Arc<dyn AgentRuntime> = unsafe_clone_runtime_ref(runtime);
    let routed = RoutedRuntime::new(inner_arc, router, ctx.config.model.clone());

    let cfg = ClassifierConfig {
        target_percentile,
        state_db: Some(workspace.findings_db_path()),
        ..Default::default()
    };
    let gate = LikelyVulnClassifier::new(&routed, cfg)?;
    let score = gate.score(&finding, workspace.root())?;
    let should_audit = gate.should_deep_audit(score);
    let threshold = gate.current_threshold();
    let n = gate.samples_seen();

    if !should_audit {
        if let Some(id) = finding.id {
            let outcome = gate.skip_outcome(score);
            store.save_triage(id, &outcome)?;
        }
    }

    Ok(json!({
        "ok": true,
        "data": {
            "findingId": finding.id,
            "fingerprint": finding.fingerprint,
            "score": score,
            "shouldDeepAudit": should_audit,
            "threshold": threshold,
            "samplesSeen": n,
        },
    }))
}

fn run_deep_audit_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::config::ConfigPaths;
    use crate::deep_auditor::{run_deep_auditor, save_evidence, DeepAuditConfig};
    use crate::spend::SpendLimiter;
    use std::sync::Arc;

    let runtime = runtime.ok_or_else(|| {
        anyhow::anyhow!("deep-audit:run requires an agent runtime; none configured")
    })?;
    let workspace = ctx
        .workspace
        .ok_or_else(|| anyhow::anyhow!("deep-audit:run requires a workspace target"))?;
    let store = FindingStore::open(workspace.findings_db_path())?;

    let fingerprint = input
        .get("findingFingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("deep-audit:run: findingFingerprint is required"))?;
    let finding = store
        .get_finding_by_reference(fingerprint)?
        .ok_or_else(|| anyhow::anyhow!("deep-audit:run: no finding for {fingerprint:?}"))?;
    let max_steps = input
        .get("maxSteps")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .unwrap_or(24);
    let deposit_usd = input
        .get("depositUsd")
        .and_then(Value::as_f64)
        .unwrap_or(1.0);

    let paths = ConfigPaths {
        home_dir: dirs::home_dir().unwrap_or_default(),
        target_dir: Some(workspace.root().to_path_buf()),
    };
    let router = Arc::new(AgentRouter::load(&paths)?);
    let inner_arc: Arc<dyn AgentRuntime> = unsafe_clone_runtime_ref(runtime);
    let routed = RoutedRuntime::new(inner_arc, router, ctx.config.model.clone());
    let spend = SpendLimiter::open(workspace.findings_db_path())?;

    let cfg = DeepAuditConfig {
        workspace_root: workspace.root().to_path_buf(),
        max_steps,
        deposit_usd,
        system_prompt: None,
        include_static_evidence: true,
    };
    let outcome = run_deep_auditor(&routed, Some(&spend), &cfg, &finding)?;

    if let Some(id) = finding.id {
        store.save_triage(id, &outcome.triage)?;
        save_evidence(&workspace.findings_db_path(), id, &outcome.evidence)?;
    }

    Ok(json!({
        "ok": true,
        "data": {
            "findingId": finding.id,
            "fingerprint": finding.fingerprint,
            "verdict": outcome.triage.verdict,
            "confidence": outcome.triage.confidence,
            "rationale": outcome.triage.rationale,
            "stepsUsed": outcome.steps_used,
            "truncated": outcome.truncated,
            "costUsd": outcome.cost_usd,
            "evidence": outcome.evidence,
        },
    }))
}

/// Adapter: turn a borrowed `&dyn AgentRuntime` into an `Arc<dyn AgentRuntime>`
/// so it can be wrapped by [`RoutedRuntime`]. The borrow's lifetime
/// determines the safety: callers must keep the underlying value alive
/// for the duration of the call.
///
/// Implementation note: we wrap the reference in a thin static-lifetime
/// trait object that delegates everything to the borrowed runtime. This
/// avoids the need to take ownership while still satisfying
/// `RoutedRuntime`'s `Arc<dyn AgentRuntime>` constructor.
fn unsafe_clone_runtime_ref(rt: &dyn AgentRuntime) -> std::sync::Arc<dyn AgentRuntime> {
    use std::sync::Arc;
    // SAFETY: BorrowedRuntime extends the lifetime to 'static via a raw
    // pointer. The caller owns the underlying runtime for the lifetime of
    // this call; the Arc never escapes the helper functions above (they
    // construct it and immediately consume it).
    struct BorrowedRuntime(*const (dyn AgentRuntime + 'static));
    unsafe impl Send for BorrowedRuntime {}
    unsafe impl Sync for BorrowedRuntime {}

    impl AgentRuntime for BorrowedRuntime {
        fn query_blocking(
            &self,
            req: crate::runtime::AgentQueryRequest,
        ) -> anyhow::Result<crate::runtime::AgentQueryResponse> {
            // SAFETY: pointer is valid for the lifetime of this trait
            // object — which the caller upholds by keeping the borrow
            // alive.
            unsafe { (*self.0).query_blocking(req) }
        }
        fn triage_finding_blocking(
            &self,
            req: crate::runtime::TriageRequest,
        ) -> anyhow::Result<crate::findings::TriageOutcome> {
            unsafe { (*self.0).triage_finding_blocking(req) }
        }
        fn supports_tools(&self) -> bool {
            unsafe { (*self.0).supports_tools() }
        }
        fn next_step_blocking(
            &self,
            req: &crate::runtime::AgentToolLoopRequest,
            history: &[crate::runtime::LoopHistoryEntry],
        ) -> anyhow::Result<crate::runtime::AgentLoopStep> {
            unsafe { (*self.0).next_step_blocking(req, history) }
        }
    }

    let static_ref: *const (dyn AgentRuntime + 'static) =
        unsafe { std::mem::transmute::<*const dyn AgentRuntime, _>(rt as *const _) };
    Arc::new(BorrowedRuntime(static_ref))
}

fn router_module() -> BuiltinModule {
    use crate::agent_router::AgentRole;
    let mut model_specs: Vec<OptionSpec> = AgentRole::all()
        .iter()
        .map(|role| {
            let name = role.option_store_key();
            let description = format!(
                "Override model for the `{}` role. Format: provider:modelId. \
                 Settable from the shell with `setg {} <model>`. Wins over models.toml.",
                role.as_key(),
                name
            );
            opt(&name, OptionType::String, &description)
        })
        .collect();
    // Stable order across builds.
    model_specs.sort_by(|a, b| a.name.cmp(&b.name));

    builtin_module(
        "router",
        "Agent router",
        ModuleKind::Governance,
        "Per-role model routing. Set MODEL_<ROLE> via `setg` to override models.toml.",
        vec![tool_with_options(
            "router:show",
            "Show effective per-role model routing.",
            model_specs,
        )],
        vec![],
    )
}

fn smoke_module() -> BuiltinModule {
    builtin_module(
        "smoke",
        "Smoke tests",
        ModuleKind::Governance,
        "Diagnostic flows that exercise the bridge end-to-end without paying for a real scan.",
        vec![tool_with_options(
            "smoke:next-step",
            "Drive a 2-step tool-loop with an `echo` tool to verify next_step_blocking + run_tool_loop.",
            vec![opt(
                "phrase",
                OptionType::String,
                "Phrase the model is asked to echo back. Default: 'kuzushi-ok'.",
            )
            .default(serde_json::json!("kuzushi-ok"))],
        )],
        vec![],
    )
}

fn run_smoke_next_step_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    use crate::runtime::{run_tool_loop, AgentTool, AgentToolLoopRequest, ToolBox, ToolResult};

    let runtime = runtime.ok_or_else(|| {
        anyhow::anyhow!("smoke:next-step requires an agent runtime; none configured")
    })?;
    if !runtime.supports_tools() {
        anyhow::bail!(
            "smoke:next-step: configured runtime does not support tools \
             (PiAgentCoreRuntime should — check the bridge configuration)"
        );
    }
    let phrase = input
        .get("phrase")
        .and_then(Value::as_str)
        .unwrap_or("kuzushi-ok")
        .to_string();
    let model = ctx
        .config
        .model
        .clone()
        .unwrap_or_else(|| "anthropic:claude-haiku-4-5".to_string());

    let request = AgentToolLoopRequest {
        model,
        cwd: std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        system_prompt: "You are participating in a Kuzushi smoke test. \
                        Call the `echo` tool exactly once with input {{ \"x\": <phrase> }}, \
                        then return the echoed text as your final answer."
            .to_string(),
        prompt: format!(
            "Phrase to echo: {phrase}\n\nUse the echo tool, then reply with the result."
        ),
        tools: vec![AgentTool {
            name: "echo".to_string(),
            description: "Returns its input under the key `out` verbatim.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "x": { "type": "string" } },
                "required": ["x"]
            }),
        }],
        max_steps: 4,
    };

    let mut toolbox = ToolBox::new();
    toolbox.register("echo", |call| {
        let x = call
            .input
            .get("x")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(ToolResult {
            call_id: call.call_id.clone(),
            output: json!({ "out": x }),
            is_error: false,
        })
    });

    let outcome = run_tool_loop(runtime, &request, &mut toolbox)?;
    let echoed = outcome.text.contains(&phrase);

    Ok(json!({
        "ok": true,
        "data": {
            "echoedPhrase": echoed,
            "stepsUsed": outcome.steps_used,
            "truncated": outcome.truncated,
            "costUsd": outcome.cost_usd,
            "transcript": outcome.transcript,
            "finalText": outcome.text,
        },
    }))
}

fn full_mode_module() -> BuiltinModule {
    builtin_module(
        "full-mode",
        "Full-codebase scan",
        ModuleKind::Offense,
        "Whole-codebase chunked LLM pass — token-greedy file clustering, per-chunk model query.",
        vec![tool_with_options(
            "full-mode:hunt",
            "Run a chunked LLM scan over the target. Use dryRun=true to plan + estimate cost without spending tokens.",
            vec![
                opt(
                    "language",
                    OptionType::Enum,
                    "Per-chunk system prompt selector.",
                )
                .choices(&["c", "unknown"])
                .default(serde_json::json!("c")),
                opt(
                    "maxTokensPerChunk",
                    OptionType::Int,
                    "Token budget per chunk; chunks pack files up to this cap.",
                )
                .default(serde_json::json!(120_000)),
                opt(
                    "depositUsdPerChunk",
                    OptionType::Float,
                    "Initial spend ticket per chunk; refunded with the bridge's reported cost.",
                )
                .default(serde_json::json!(2.0)),
                opt(
                    "dryRun",
                    OptionType::Bool,
                    "Plan + cost estimate only; do not invoke any model.",
                )
                .default(serde_json::json!(false)),
                opt(
                    "scopeFile",
                    OptionType::Path,
                    "Optional repo-relative path to a newline-delimited scope file. Defaults to <target>/.kuzushi/v2/since.txt when --since populated it.",
                ),
            ],
        )],
        vec![],
    )
}

fn classifier_gate_module() -> BuiltinModule {
    builtin_module(
        "classifier-gate",
        "Classifier gate",
        ModuleKind::Triage,
        "Cheap LLM classifier with adaptive p80 quantile gate. Score one finding to decide whether the deep auditor should run.",
        vec![tool_with_options(
            "classifier-gate:score",
            "Score a finding with the cheap classifier; updates the running quantile.",
            vec![
                opt(
                    "findingFingerprint",
                    OptionType::String,
                    "Fingerprint (or short prefix) of the finding to score.",
                )
                .required(),
                opt(
                    "targetPercentile",
                    OptionType::Float,
                    "Target percentile for the adaptive threshold (0.0 < p < 1.0).",
                )
                .default(serde_json::json!(0.80)),
            ],
        )],
        vec![],
    )
}

fn deep_audit_module() -> BuiltinModule {
    builtin_module(
        "deep-audit",
        "Deep auditor",
        ModuleKind::Triage,
        "Tool-augmented LLM auditor — uses code-nav primitives to verify a finding's triggerability.",
        vec![tool_with_options(
            "deep-audit:run",
            "Run the deep auditor on a single finding; persists triage outcome + evidence.",
            vec![
                opt(
                    "findingFingerprint",
                    OptionType::String,
                    "Fingerprint (or short prefix) of the finding to audit.",
                )
                .required(),
                opt(
                    "maxSteps",
                    OptionType::Int,
                    "Hard cap on tool-loop steps per finding.",
                )
                .default(serde_json::json!(24)),
                opt(
                    "depositUsd",
                    OptionType::Float,
                    "Initial spend ticket; refunded with the bridge's reported cost.",
                )
                .default(serde_json::json!(1.0)),
            ],
        )],
        vec![],
    )
}

fn workspace_module() -> BuiltinModule {
    builtin_module(
        "workspace",
        "Workspace",
        ModuleKind::Intel,
        "Report target and state paths.",
        vec![
            tool(
                "workspace:status",
                "Show current target and state paths.",
            ),
            tool_with_options(
                "workspace:export-findings",
                "Export persisted workspace findings to a local JSON or JSONL file.",
                vec![
                    opt(
                        "output",
                        OptionType::Path,
                        "Output path for exported findings. Relative paths resolve under the workspace root.",
                    )
                    .required(),
                    opt("format", OptionType::Enum, "Export format.")
                        .choices(&["json", "jsonl"]),
                ],
            ),
        ],
        vec![],
    )
}

fn sast_module() -> BuiltinModule {
    builtin_module(
        "sast",
        "SAST Pipeline",
        ModuleKind::Defense,
        "Full SAST pipeline: context, scanners, AI triage, verification, patch, and report.",
        vec![tool_with_options(
            "sast:scan",
            "Run the full SAST pipeline for the current target.",
            vec![
                opt("mode", OptionType::Enum, "Analysis mode or preset.")
                    .choices(&["standard", "whitebox-static"])
                    .default(json!("standard")),
                opt("taskMode", OptionType::Enum, "Task-selection mode.")
                    .choices(&["auto", "manual"])
                    .default(json!("auto")),
                opt(
                    "tasks",
                    OptionType::StringList,
                    "Manual task allowlist. Use /tasks to edit.",
                ),
                opt(
                    "disabledTasks",
                    OptionType::StringList,
                    "Auto-mode task denylist. Use /tasks to edit.",
                ),
                opt(
                    "severity",
                    OptionType::StringList,
                    "Optional severity filter: critical, high, medium, low, or info.",
                ),
                opt(
                    "diffBase",
                    OptionType::String,
                    "Git revision for whitebox-static PR diff scope.",
                )
                .advanced(),
                opt(
                    "triage",
                    OptionType::Bool,
                    "Run model-backed triage after static scanners.",
                )
                .default(json!(false)),
                opt(
                    "verify",
                    OptionType::Bool,
                    "Run exploitability verification after triage.",
                )
                .default(json!(false))
                .advanced(),
                opt(
                    "autoPatch",
                    OptionType::Bool,
                    "Generate patches for verified true positives.",
                )
                .default(json!(false))
                .advanced(),
                model_option(),
            ],
        )],
        vec![dag("sast:scan", "report", &["context:build"])],
    )
}

fn semgrep_module() -> BuiltinModule {
    builtin_module(
        "semgrep",
        "Semgrep Scan",
        ModuleKind::Defense,
        "Native SAST path using semgrep JSON output.",
        vec![tool_with_options(
            "semgrep:scan",
            "Run semgrep and persist normalized findings.",
            vec![
                target_option(),
                binary_option("Semgrep binary path."),
                opt("config", OptionType::String, "Semgrep config name or path.")
                    .default(json!("auto")),
            ],
        )],
        vec![dag("semgrep:scan", "findings", &["context:build"])],
    )
}

fn codeql_module() -> BuiltinModule {
    builtin_module(
        "codeql",
        "CodeQL",
        ModuleKind::Defense,
        "GitHub's taint-query semantic analyzer: deeper than pattern scanners but slower.",
        vec![tool_with_options(
            "codeql:scan",
            "Run CodeQL and normalize semantic findings.",
            vec![
                target_option(),
                binary_option("CodeQL binary path."),
                opt("dbPath", OptionType::Path, "Existing CodeQL database path.").advanced(),
                opt("language", OptionType::Enum, "CodeQL language to analyze.").choices(&[
                    "javascript",
                    "python",
                    "csharp",
                    "c#",
                    "java",
                    "go",
                    "cpp",
                    "c++",
                    "c-cpp",
                    "swift",
                    "ruby",
                    "rust",
                    "typescript",
                ]),
                opt("suite", OptionType::String, "CodeQL query suite.").advanced(),
                opt("threads", OptionType::Int, "CodeQL worker thread count.").advanced(),
                opt("ram", OptionType::Int, "CodeQL RAM budget in MB.").advanced(),
                opt(
                    "multiLanguage",
                    OptionType::Bool,
                    "Analyze all detected CodeQL languages.",
                )
                .default(json!(false)),
            ],
        )],
        vec![dag("codeql:scan", "findings", &["context:build"])],
    )
}

fn agentic_sast_module() -> BuiltinModule {
    builtin_module(
        "agentic-sast",
        "Agentic SAST",
        ModuleKind::Defense,
        "LLM-driven detectors that reason about data flow and intent rather than pattern-match.",
        vec![tool_with_options(
            "agentic-sast:scan",
            "Run agentic SAST detectors for the current target.",
            vec![
                target_option(),
                max_findings_option(40),
                opt("passes", OptionType::Int, "Agentic review pass count.").default(json!(1)),
                model_option(),
            ],
        )],
        vec![dag("agentic-sast:scan", "findings", &["context:build"])],
    )
}

fn carlini_threat_hunt_module() -> BuiltinModule {
    builtin_module(
        "carlini-threat-hunt",
        "Carlini Threat Hunt",
        ModuleKind::Offense,
        "Hunt threats from the active threat-model document via parallel scoped agents.",
        vec![tool_with_options(
            "carlini-threat-hunt:run",
            "Run threat-model-scoped offensive hunting agents.",
            vec![target_option(), max_findings_option(20), model_option()],
        )],
        vec![dag(
            "carlini-threat-hunt:run",
            "findings",
            &["threat-model:build"],
        )],
    )
}

fn taint_iris_module() -> BuiltinModule {
    builtin_module(
        "taint-iris",
        "Taint IRIS",
        ModuleKind::Defense,
        "LLM-driven taint analysis selecting relevant CWEs then tracing source to sink.",
        vec![tool_with_options(
            "taint-iris:hunt",
            "Run IRIS-style taint hunting over the current target.",
            vec![target_option(), max_findings_option(20), model_option()],
        )],
        vec![dag("taint-iris:hunt", "findings", &["context:build"])],
    )
}

fn taint_iris_next_module() -> BuiltinModule {
    builtin_module(
        "taint-iris-next",
        "Taint IRIS Next",
        ModuleKind::Defense,
        "Bounded IRIS-style taint analysis with deterministic evidence extraction and agent review.",
        vec![tool_with_options(
            "taint-iris-next:hunt",
            "Run the next-generation bounded taint hunting pipeline.",
            vec![target_option(), max_findings_option(20), model_option()],
        )],
        vec![dag("taint-iris-next:hunt", "findings", &["context:build"])],
    )
}

fn systems_hunt_module() -> BuiltinModule {
    hidden_module(
        "systems-hunt",
        "Systems Hunt",
        ModuleKind::Internal,
        "Internal DAG nodes for memory-safety and low-level protocol bug hunting.",
        vec![],
        vec![
            dag(
                "systems-hunt:systems-context-gatherer",
                "context",
                &["context:build"],
            ),
            dag(
                "systems-hunt:systems-invariant-extract",
                "invariants",
                &["systems-hunt:systems-context-gatherer"],
            ),
            dag(
                "systems-hunt:systems-trigger-synth",
                "triggers",
                &["systems-hunt:systems-invariant-extract"],
            ),
            dag(
                "systems-hunt:systems-hunt",
                "findings",
                &["systems-hunt:systems-trigger-synth"],
            ),
            dag(
                "systems-hunt:deep-semantic-cwe-select",
                "cwe-selection",
                &["context:build"],
            ),
            dag(
                "systems-hunt:deep-semantic-hunt",
                "findings",
                &["systems-hunt:deep-semantic-cwe-select"],
            ),
        ],
    )
}

fn triage_module() -> BuiltinModule {
    builtin_module(
        "triage",
        "Triage",
        ModuleKind::Defense,
        "LLM-driven triage of scanner findings with evidence-backed verdicts.",
        vec![tool_with_options(
            "triage:run",
            "Triage findings with pi-agent-core.",
            vec![
                opt("scanId", OptionType::String, "Scan run id to triage."),
                opt(
                    "fingerprint",
                    OptionType::String,
                    "Single finding fingerprint to triage.",
                ),
                opt(
                    "batchSize",
                    OptionType::Int,
                    "Maximum findings per runtime batch.",
                )
                .default(json!(20)),
                model_option(),
            ],
        )],
        vec![dag("triage:run", "triage", &["semgrep:scan"])],
    )
}

fn verify_module() -> BuiltinModule {
    builtin_module(
        "verify",
        "Verify",
        ModuleKind::Offense,
        "Exploitability verification through proof-of-concept construction and sandboxed execution.",
        vec![
            tool_with_options(
                "verify:finding",
                "Verify whether a finding is exploitable (LLM-driven; consults runtime for PoC reasoning).",
                vec![fingerprint_option(), model_option()],
            ),
            tool_with_options(
                "verify:exploit",
                "Empirical exploit-gated verify: scaffolds a sandboxed test harness from the finding's location and observes whether it crashes. Only Rust language is wired today; other languages return language_unsupported_yet.",
                vec![fingerprint_option()],
            ),
        ],
        vec![dag("verify:finding", "verification", &["triage:run"])],
    )
}

fn patch_module() -> BuiltinModule {
    builtin_module(
        "patch",
        "Patch",
        ModuleKind::Defense,
        "Generate and validate a patch for a finding.",
        vec![tool_with_options(
            "patch:finding",
            "Generate a patch for a finding.",
            vec![
                fingerprint_option(),
                opt("maxIterations", OptionType::Int, "Maximum patch attempts.").default(json!(3)),
                opt(
                    "buildCmd",
                    OptionType::String,
                    "Build command used for patch validation.",
                )
                .advanced(),
                opt(
                    "testCmd",
                    OptionType::String,
                    "Test command used for patch validation.",
                )
                .advanced(),
            ],
        )],
        vec![dag("patch:finding", "patch", &["verify:finding"])],
    )
}

fn findings_module() -> BuiltinModule {
    builtin_module(
        "findings",
        "Findings",
        ModuleKind::Defense,
        "Persist and inspect findings in SQLite.",
        vec![tool_with_options(
            "findings:list",
            "List persisted findings.",
            vec![
                opt("limit", OptionType::Int, "Maximum findings to return.").default(json!(50)),
                opt(
                    "name",
                    OptionType::String,
                    "Substring filter for finding titles.",
                ),
                opt("filePath", OptionType::Path, "File path filter."),
            ],
        )],
        vec![],
    )
}

fn threat_model_module() -> BuiltinModule {
    builtin_module(
        "threat-model",
        "Threat Model",
        ModuleKind::Intel,
        "Build and read threat-model artifacts and methodology overlays.",
        vec![
            tool_with_options(
                "threat-model:build",
                "Build a threat model for the current target.",
                vec![
                    target_option(),
                    opt(
                        "methodology",
                        OptionType::Enum,
                        "Threat-model methodology overlay.",
                    )
                    .choices(&["pasta", "stride", "dread"])
                    .default(json!("stride")),
                    model_option(),
                ],
            ),
            tool(
                "threat-model:read",
                "Read the current threat model artifact.",
            ),
            tool(
                "threat-model:methodologies",
                "List supported threat-model methodologies.",
            ),
        ],
        vec![dag(
            "threat-model:build",
            "threat-model",
            &["context:build"],
        )],
    )
}

fn x_ray_module() -> BuiltinModule {
    builtin_module(
        "x-ray",
        "X-Ray",
        ModuleKind::Intel,
        "Pashov X-Ray repository analysis and report artifacts.",
        vec![
            tool_with_options(
                "x-ray:run",
                "Run repository X-Ray analysis.",
                vec![
                    target_option(),
                    model_option(),
                    opt(
                        "effort",
                        OptionType::String,
                        "Runtime reasoning effort hint.",
                    )
                    .advanced(),
                    opt(
                        "maxBudgetUsd",
                        OptionType::Float,
                        "Maximum runtime budget for the X-Ray request.",
                    )
                    .advanced(),
                ],
            ),
            tool("x-ray:read", "Read the latest X-Ray analysis report."),
        ],
        vec![dag("x-ray:x-ray", "report", &["context:build"])],
    )
}

fn vendor_assessment_module() -> BuiltinModule {
    builtin_module(
        "vendor-assessment",
        "Vendor Assessment",
        ModuleKind::Governance,
        "Vendor security assessment workspace: attach docs, set scope, generate prompts, assess.",
        vec![
            tool_with_options(
                "vendor-assessment:attach",
                "Attach vendor evidence documents.",
                vec![
                    opt("source", OptionType::String, "Evidence source path or URL."),
                    opt("path", OptionType::Path, "Evidence document path."),
                    opt("url", OptionType::String, "Evidence document URL."),
                ],
            ),
            tool_with_options(
                "vendor-assessment:scope",
                "Set or inspect assessment scope.",
                vec![
                    opt("vendorName", OptionType::String, "Vendor name."),
                    opt("productName", OptionType::String, "Product name."),
                    opt("profile", OptionType::String, "Assessment profile.")
                        .default(json!("enterprise-ai")),
                ],
            ),
            tool(
                "vendor-assessment:prompts",
                "Generate assessment prompt packets.",
            ),
            tool_with_options(
                "vendor-assessment:assess",
                "Run vendor assessment.",
                vec![model_option()],
            ),
        ],
        vec![],
    )
}

fn chrome_rce_module() -> BuiltinModule {
    builtin_module(
        "chrome-rce",
        "Chrome RCE",
        ModuleKind::Defense,
        "Detection rules anchored to verified Chrome and Chromium RCE CVEs.",
        vec![
            tool_with_options(
                "chrome-rce:scan",
                "Scan for Chrome RCE bug patterns.",
                vec![target_option(), max_findings_option(50)],
            ),
            tool_with_options(
                "chrome-rce:review-trigger",
                "Review candidate Chrome RCE trigger paths.",
                vec![
                    target_option(),
                    opt(
                        "diffBase",
                        OptionType::String,
                        "Git reference for PR hot-path review.",
                    ),
                ],
            ),
        ],
        vec![
            dag("chrome-rce:scan", "findings", &["context:build"]),
            dag("chrome-rce:review-trigger", "review", &["chrome-rce:scan"]),
        ],
    )
}

fn dep_hygiene_module() -> BuiltinModule {
    builtin_module(
        "dep-hygiene",
        "Dependency Hygiene",
        ModuleKind::Defense,
        "Check dependency manifests for stale, vulnerable, or policy-risky packages.",
        vec![tool_with_options(
            "dep-hygiene:check",
            "Run dependency hygiene checks.",
            vec![target_option()],
        )],
        vec![dag("dep-hygiene:check", "findings", &["context:build"])],
    )
}

fn secret_scan_module() -> BuiltinModule {
    builtin_module(
        "secret-scan",
        "Secret Scan",
        ModuleKind::Defense,
        "Fast deterministic secret scanner over source files.",
        vec![tool_with_options(
            "secret-scan:scan",
            "Scan source files for high-confidence secrets.",
            vec![
                target_option(),
                opt(
                    "maxFileBytes",
                    OptionType::Int,
                    "Maximum file size to scan.",
                )
                .default(json!(524288)),
                max_findings_option(1000),
            ],
        )],
        vec![dag("secret-scan:scan", "findings", &["context:build"])],
    )
}

fn pipeline_module() -> BuiltinModule {
    hidden_module(
        "pipeline",
        "Pipeline",
        ModuleKind::Internal,
        "Internal orchestrator DAG nodes for task selection, approval gates, and taint sub-tasks.",
        vec![],
        vec![
            dag(
                "pipeline:task-selector",
                "task-selection",
                &["context:build"],
            ),
            dag(
                "pipeline:approval-before-verification",
                "approval",
                &["triage:run"],
            ),
            dag(
                "pipeline:taint-cwe-select",
                "cwe-selection",
                &["context:build"],
            ),
        ],
    )
}

fn variant_module() -> BuiltinModule {
    builtin_module(
        "variant",
        "Variant Hunter",
        ModuleKind::Offense,
        "Lift exploit patterns from confirmed findings and hunt sibling variants.",
        vec![
            tool_with_options(
                "variant:lift-pattern",
                "Lift a reusable vulnerability pattern from a confirmed finding.",
                vec![fingerprint_option(), model_option()],
            ),
            tool_with_options(
                "variant:hunt",
                "Hunt variants of a confirmed finding.",
                vec![
                    target_option(),
                    fingerprint_option(),
                    max_findings_option(25),
                    model_option(),
                ],
            ),
        ],
        vec![dag("variant:hunt", "findings", &["variant:lift-pattern"])],
    )
}

fn ndiff_module() -> BuiltinModule {
    builtin_module(
        "ndiff",
        "N-Day Diff Hunter",
        ModuleKind::Intel,
        "Fetch CVE fix context, extract fix patterns, and hunt n-day variants.",
        vec![
            tool_with_options(
                "ndiff:fetch-cve",
                "Fetch CVE and patch metadata.",
                vec![opt("id", OptionType::String, "CVE or advisory id to fetch.").required()],
            ),
            tool_with_options(
                "ndiff:extract-fix-pattern",
                "Extract a vulnerability fix pattern from a patch.",
                vec![model_option()],
            ),
            tool_with_options(
                "ndiff:hunt-variants",
                "Hunt variants using an extracted n-day fix pattern.",
                vec![target_option(), max_findings_option(25), model_option()],
            ),
        ],
        vec![dag(
            "ndiff:hunt-variants",
            "findings",
            &["ndiff:extract-fix-pattern"],
        )],
    )
}

fn randori_module() -> BuiltinModule {
    builtin_module(
        "randori",
        "Randori",
        ModuleKind::Intel,
        "PASTA and randori threat-model generation.",
        vec![
            tool_with_options(
                "randori:pasta",
                "Generate a PASTA threat model.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "randori:threat-model",
                "Generate a randori threat model.",
                vec![target_option(), model_option()],
            ),
        ],
        vec![dag(
            "randori:threat-model",
            "threat-model",
            &["context:build"],
        )],
    )
}

fn vuln_scout_module() -> BuiltinModule {
    builtin_module(
        "vuln-scout",
        "Vuln Scout",
        ModuleKind::Offense,
        "Whitebox pentest wrapper around the @kuzushi/vuln-scout Claude Code plugin.",
        vec![tool_with_options(
            "vuln-scout:audit",
            "Run the Vuln Scout audit plugin.",
            vec![target_option(), model_option()],
        )],
        vec![dag("vuln-scout:audit", "findings", &["context:build"])],
    )
}

fn tob_module() -> BuiltinModule {
    builtin_module(
        "tob",
        "Trail of Bits Skills",
        ModuleKind::Offense,
        "Audit wrapper around the @kuzushi/tob-skills Claude Code plugin collection.",
        vec![
            tool_with_options(
                "tob:audit",
                "Run a Trail of Bits skills audit.",
                vec![target_option(), model_option()],
            ),
            tool("tob:skills", "List available Trail of Bits skill modules."),
        ],
        vec![dag("tob:audit", "findings", &["context:build"])],
    )
}

fn shinsa_module() -> BuiltinModule {
    builtin_module(
        "shinsa",
        "Shinsa Compliance",
        ModuleKind::Governance,
        "Compliance assessment wrapper around the shinsa-plugin Claude Code plugin.",
        vec![
            tool_with_options(
                "shinsa:scan",
                "Run a full ISO 27001 Annex A compliance assessment.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "shinsa:quick-check",
                "Run a fast ISO 27001 Annex A check.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "shinsa:nist-scan",
                "Run a full NIST SP 800-53 Rev 5 compliance assessment.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "shinsa:nist-quick-check",
                "Run a fast NIST SP 800-53 Rev 5 check.",
                vec![target_option(), model_option()],
            ),
            tool("shinsa:frameworks", "List supported compliance frameworks."),
        ],
        vec![
            dag("shinsa:scan", "assessment", &["context:build"]),
            dag("shinsa:nist-scan", "assessment", &["context:build"]),
        ],
    )
}

fn prompt_armor_module() -> BuiltinModule {
    builtin_module(
        "prompt-armor",
        "PromptArmor",
        ModuleKind::Offense,
        "LLM red-team wrapper around promptarmor-plugin attack suites and mutations.",
        vec![
            tool_with_options(
                "prompt-armor:scan",
                "Run a full LLM red-team scan.",
                vec![
                    target_option(),
                    opt(
                        "authorized",
                        OptionType::Bool,
                        "Confirm authorization to test.",
                    )
                    .default(json!(false)),
                    opt(
                        "payload",
                        OptionType::String,
                        "Single attack payload to test.",
                    )
                    .evasion(),
                    model_option(),
                ],
            ),
            tool_with_options(
                "prompt-armor:analyze",
                "Statically analyze prompt-injection surface.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "prompt-armor:attack",
                "Send a single authorized attack payload and judge the response.",
                vec![
                    target_option(),
                    opt(
                        "authorized",
                        OptionType::Bool,
                        "Confirm authorization to test.",
                    )
                    .default(json!(false)),
                    opt(
                        "payload",
                        OptionType::String,
                        "Single attack payload to test.",
                    )
                    .evasion(),
                    model_option(),
                ],
            ),
            tool_with_options(
                "prompt-armor:diff",
                "Diff two prior red-team runs.",
                vec![
                    opt("runA", OptionType::Path, "Baseline prompt-armor run path.").required(),
                    opt(
                        "runB",
                        OptionType::Path,
                        "Comparison prompt-armor run path.",
                    )
                    .required(),
                ],
            ),
            tool_with_options(
                "prompt-armor:report",
                "Generate a consolidated red-team report.",
                vec![target_option()],
            ),
            tool_with_options(
                "prompt-armor:config",
                "Inspect or scaffold promptarmor.yaml.",
                vec![target_option()],
            ),
        ],
        vec![dag("prompt-armor:scan", "findings", &["context:build"])],
    )
}

fn recon_module() -> BuiltinModule {
    builtin_module(
        "recon",
        "Recon",
        ModuleKind::Intel,
        "Network and web reconnaissance tools.",
        vec![
            tool_with_options(
                "recon:nmap",
                "Run nmap reconnaissance.",
                vec![
                    opt("target", OptionType::String, "Host or network target.").required(),
                    opt(
                        "ports",
                        OptionType::String,
                        "Port set or comma-separated port list.",
                    )
                    .default(json!("top100")),
                    binary_option("nmap binary path."),
                ],
            ),
            tool_with_options(
                "recon:subdomain",
                "Run subdomain reconnaissance.",
                vec![
                    opt("domain", OptionType::String, "Domain to enumerate.").required(),
                    opt("source", OptionType::Enum, "Subdomain source.")
                        .choices(&["crtsh", "wayback", "both"])
                        .default(json!("both")),
                    opt(
                        "timeoutSeconds",
                        OptionType::Int,
                        "HTTP fetch timeout in seconds.",
                    )
                    .default(json!(20)),
                    binary_option("curl binary path."),
                ],
            ),
            tool_with_options(
                "recon:http-fingerprint",
                "Fingerprint HTTP services and technology stacks.",
                vec![
                    opt("target", OptionType::String, "HTTP service URL or host.").required(),
                    opt(
                        "timeoutSeconds",
                        OptionType::Int,
                        "HTTP fetch timeout in seconds.",
                    )
                    .default(json!(10)),
                    binary_option("curl binary path."),
                ],
            ),
        ],
        vec![dag("recon:http-fingerprint", "context", &["context:build"])],
    )
}

fn iac_scan_module() -> BuiltinModule {
    builtin_module(
        "iac-scan",
        "IaC Scan",
        ModuleKind::Defense,
        "Scan IaC manifests for security misconfigurations.",
        vec![tool_with_options(
            "iac-scan:scan",
            "Scan Terraform, Kubernetes, and related IaC manifests.",
            vec![
                target_option(),
                opt("kind", OptionType::Enum, "IaC file family to scan.")
                    .choices(&[
                        "all",
                        "dockerfile",
                        "docker",
                        "github-actions",
                        "github_actions",
                        "actions",
                        "terraform",
                        "tf",
                    ])
                    .default(json!("all")),
                opt(
                    "maxFileBytes",
                    OptionType::Int,
                    "Maximum file size to scan.",
                )
                .default(json!(524288)),
            ],
        )],
        vec![dag("iac-scan:scan", "findings", &["context:build"])],
    )
}

fn builtin_module(
    id: &str,
    name: &str,
    kind: ModuleKind,
    description: &str,
    tools: Vec<ToolDescriptor>,
    dag_nodes: Vec<DagNodeDescriptor>,
) -> BuiltinModule {
    module(id, name, kind, description, tools, dag_nodes, false)
}

fn hidden_module(
    id: &str,
    name: &str,
    kind: ModuleKind,
    description: &str,
    tools: Vec<ToolDescriptor>,
    dag_nodes: Vec<DagNodeDescriptor>,
) -> BuiltinModule {
    module(id, name, kind, description, tools, dag_nodes, true)
}

fn module(
    id: &str,
    name: &str,
    kind: ModuleKind,
    description: &str,
    tools: Vec<ToolDescriptor>,
    dag_nodes: Vec<DagNodeDescriptor>,
    hidden: bool,
) -> BuiltinModule {
    BuiltinModule {
        metadata: ModuleMetadata {
            id: id.to_string(),
            name: name.to_string(),
            kind,
            description: description.to_string(),
        },
        tools,
        dag_nodes,
        hidden,
    }
}

fn tool(name: &str, description: &str) -> ToolDescriptor {
    tool_with_options(name, description, vec![])
}

fn tool_with_options(name: &str, description: &str, options: Vec<OptionSpec>) -> ToolDescriptor {
    ToolDescriptor {
        name: name.to_string(),
        description: description.to_string(),
        headless: true,
        options,
    }
}

fn opt(name: &str, option_type: OptionType, description: &str) -> OptionSpec {
    OptionSpec::new(name, option_type, description)
}

fn target_option() -> OptionSpec {
    opt(
        "target",
        OptionType::Path,
        "Repository or workspace path; defaults to the active workspace when supported.",
    )
}

fn model_option() -> OptionSpec {
    opt(
        "model",
        OptionType::String,
        "Explicit provider:model override for this tool run.",
    )
    .advanced()
}

fn max_findings_option(default: usize) -> OptionSpec {
    opt(
        "maxFindings",
        OptionType::Int,
        "Maximum findings or candidates to return.",
    )
    .default(json!(default))
}

fn fingerprint_option() -> OptionSpec {
    opt(
        "fingerprint",
        OptionType::String,
        "Finding fingerprint or stable finding alias.",
    )
    .required()
}

fn binary_option(description: &str) -> OptionSpec {
    opt("binary", OptionType::Path, description).advanced()
}

fn dag(id: &str, output_kind: &str, depends_on: &[&str]) -> DagNodeDescriptor {
    DagNodeDescriptor {
        id: id.to_string(),
        output_kind: output_kind.to_string(),
        depends_on: depends_on
            .iter()
            .map(|dependency| dependency.to_string())
            .collect(),
    }
}

fn resolve_tool_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        let trimmed = target.trim();
        let path = if trimmed.is_empty() {
            std::env::current_dir().context("Could not resolve current directory")?
        } else {
            let candidate = PathBuf::from(trimmed);
            if candidate.is_absolute() {
                candidate
            } else {
                std::env::current_dir()
                    .context("Could not resolve current directory")?
                    .join(candidate)
            }
        };
        return Ok(path);
    }

    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }

    std::env::current_dir().context("Could not resolve current directory")
}

fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::{Finding, PatchStatus, Severity, TriageOutcome, TriageVerdict};
    use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
    use crate::runtime::AgentQueryResponse;
    use std::process::Command;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct MockRuntime {
        requests: Mutex<Vec<TriageRequest>>,
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    impl MockRuntime {
        fn new() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                queries: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<TriageRequest> {
            self.requests.lock().unwrap().clone()
        }

        fn queries(&self) -> Vec<AgentQueryRequest> {
            self.queries.lock().unwrap().clone()
        }
    }

    impl AgentRuntime for MockRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.queries.lock().unwrap().push(request);
            let is_patch_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("security patch generator"));
            if is_patch_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "diff": "--- a/src/db.ts\n+++ b/src/db.ts\n@@ -1 +1 @@\n-const query = req.query.q;\n+const query = String(req.query.q).replace(/[^a-z0-9]/gi, \"\");\n",
                        "explanation": "sanitize query input before use"
                    })),
                    ..Default::default()
                });
            }
            let is_agentic_sast_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("agentic SAST scanner"));
            if is_agentic_sast_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "ruleId": "agentic/sql-injection",
                            "filePath": "src/db.ts",
                            "startLine": 1,
                            "severity": "ERROR",
                            "message": "User input reaches SQL query",
                            "confidence": "HIGH",
                            "evidence": "Source: req.query.q -> sink: db.query"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_taint_cwe_select_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("Taint CWE selector"));
            if is_taint_cwe_select_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "cwes": [{
                            "id": "CWE-89",
                            "name": "SQL Injection",
                            "reason": "database query uses request input"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_taint_iris_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("IRIS-style taint analysis"));
            if is_taint_iris_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "title": "Request input reaches SQL query",
                            "cwe": "CWE-89",
                            "severity": "high",
                            "filePath": "src/db.ts",
                            "startLine": 1,
                            "message": "The request query is concatenated into a SQL query.",
                            "sourceSinkTrace": "req.query.q -> db.query",
                            "taintPath": [{
                                "filePath": "src/db.ts",
                                "line": 1,
                                "message": "source and sink",
                                "snippet": "db.query(req.query.q)"
                            }],
                            "confidence": "high",
                            "exploitPreconditions": "attacker controls q"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_taint_iris_next_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("Taint IRIS Next agent"));
            if is_taint_iris_next_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "selectedCwes": [{
                            "cwe": "CWE-89",
                            "reason": "raw query receives request data",
                            "catalogSignals": ["sink: query("],
                            "sourceSpec": "request query parameters",
                            "sinkSpec": "database query calls",
                            "sanitizerSpec": "parameterized query APIs",
                            "customCweRationale": ""
                        }],
                        "findings": [{
                            "title": "Request parameter reaches raw SQL query",
                            "cwe": "CWE-89",
                            "severity": "high",
                            "confidence": "medium",
                            "evidenceLevel": "linked",
                            "filePath": "src/routes.ts",
                            "startLine": 1,
                            "message": "The query uses request-controlled data in SQL construction.",
                            "sourceSinkTrace": "req.query.id -> db.query(sql)",
                            "catalogSignals": ["source: req.query", "sink: query("],
                            "customCweRationale": "",
                            "taintPath": [{
                                "filePath": "src/routes.ts",
                                "line": 1,
                                "message": "source and SQL sink",
                                "snippet": "db.query(req.query.id)"
                            }]
                        }],
                        "triage": [{
                            "status": "finding",
                            "cwe": "CWE-89",
                            "evidenceLevel": "linked",
                            "rationale": "request data reaches raw SQL query",
                            "filePath": "src/routes.ts",
                            "line": 1,
                            "catalogSignals": ["sink: query("]
                        }],
                        "notes": []
                    })),
                    ..Default::default()
                });
            }
            let is_carlini_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("Carlini Threat Hunt"));
            if is_carlini_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "ruleId": "carlini-threat-hunt/actor-xss",
                            "filePath": "src/app.ts",
                            "startLine": 9,
                            "severity": "ERROR",
                            "message": "Actor-controlled input reaches HTML response",
                            "confidence": "HIGH",
                            "evidence": "Source: request query -> sink: response HTML"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_systems_invariant_request =
                self.queries.lock().unwrap().last().is_some_and(|query| {
                    query
                        .system_prompt
                        .contains("Systems Hunt invariant extractor")
                });
            if is_systems_invariant_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "invariants": [{
                            "id": "inv-1",
                            "surfaceId": "surface-1",
                            "kind": "length-buffer-coupling",
                            "summary": "packet length must fit the fixed buffer",
                            "statement": "length is checked before copy",
                            "rationale": "copy uses packet-controlled length",
                            "evidence": ["memcpy"],
                            "attackerControlledFields": ["len"],
                            "cheapVerifiable": true
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_systems_trigger_request =
                self.queries.lock().unwrap().last().is_some_and(|query| {
                    query
                        .system_prompt
                        .contains("Systems Hunt trigger synthesizer")
                });
            if is_systems_trigger_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "triggers": [{
                            "id": "trig-1",
                            "surfaceId": "surface-1",
                            "orderedSteps": ["send oversized packet"],
                            "boundaryAssignments": {"len": "4096"},
                            "statePreconditions": ["connected"],
                            "attackerControlledFields": ["len"],
                            "expectedPrimitive": "stack overwrite",
                            "cheapVerifiable": true,
                            "rationale": "length reaches memcpy"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_systems_hunt_request =
                self.queries.lock().unwrap().last().is_some_and(|query| {
                    query
                        .system_prompt
                        .contains("Systems Hunt low-level vulnerability hunter")
                });
            if is_systems_hunt_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "title": "Oversized packet length reaches fixed buffer",
                            "cwe": "CWE-787",
                            "severity": "ERROR",
                            "filePath": "src/parser.c",
                            "startLine": 3,
                            "message": "packet length is copied into a 64-byte stack buffer",
                            "reasoning": "len comes from the packet header",
                            "triggerHypothesisIds": ["trig-1"],
                            "violatedInvariantIds": ["inv-1"],
                            "triggerSequence": ["send len=4096"],
                            "attackerControlledFields": ["len"],
                            "memoryPrimitive": "stack overwrite",
                            "cheapVerifiable": true
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_plugin_adapter_request =
                self.queries.lock().unwrap().last().is_some_and(|query| {
                    query.system_prompt.contains("pi-agent-core adapter")
                        || query.system_prompt.contains("Shinsa compliance adapter")
                        || query.system_prompt.contains("PromptArmor adapter")
                        || query
                            .system_prompt
                            .contains("vendor security assessment agent")
                });
            if is_plugin_adapter_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "summary": "mock adapter result",
                        "findings": [{
                            "ruleId": "adapter/mock-finding",
                            "filePath": "src/app.ts",
                            "startLine": 1,
                            "severity": "high",
                            "message": "Mock adapter finding grounded in source",
                            "evidence": "src/app.ts:1"
                        }],
                        "overallRisk": "medium",
                        "confidence": "medium"
                    })),
                    ..Default::default()
                });
            }
            Ok(AgentQueryResponse {
                text: String::new(),
                structured: Some(json!({
                    "fingerprint": "from-bridge",
                    "exploitable": true,
                    "poc_payload": "curl -X POST /admin",
                    "poc_description": "POST reaches the admin sink.",
                    "attack_vector": "curl POST /admin",
                    "preconditions": ["network access"],
                    "confidence": 0.82,
                    "proof_level": 3,
                    "proof_verdict": "exploited",
                })),
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
            let verdict = if request.finding.rule_id.contains("fp") {
                TriageVerdict::FalsePositive
            } else {
                TriageVerdict::TruePositive
            };
            self.requests.lock().unwrap().push(request);
            Ok(TriageOutcome {
                verdict,
                confidence: 0.87,
                rationale: "mock pi-agent-core triage".to_string(),
                ..Default::default()
            })
        }
    }

    #[cfg(unix)]
    fn fake_semgrep_binary(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("semgrep-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat <<'JSON'
{
  "results": [
    {
      "check_id": "javascript.express.security.audit.xss",
      "path": "server.js",
      "start": { "line": 9 },
      "end": { "line": 11 },
      "extra": {
        "severity": "ERROR",
        "message": "Detected unescaped user input in HTML response"
      }
    }
  ]
}
JSON
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_codeql_binary(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("codeql-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
if [ "$1" = "database" ] && [ "$2" = "create" ]; then
  mkdir -p "$3"
  printf 'name: test\n' > "$3/codeql-database.yml"
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "analyze" ]; then
  out=""
  for arg in "$@"; do
    case "$arg" in
      --output=*) out="${arg#--output=}" ;;
    esac
  done
  cat > "$out" <<'JSON'
{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              "id": "js/sql-injection",
              "properties": { "problem": { "severity": "error" } }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "js/sql-injection",
          "message": { "text": "User input reaches SQL sink" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "server.js" },
                "region": { "startLine": 9 }
              }
            }
          ],
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {
                      "message": { "text": "request query parameter" },
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": { "uri": "server.js" },
                          "region": { "startLine": 1 }
                        }
                      }
                    },
                    {
                      "message": { "text": "query reaches db.query" },
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": { "uri": "server.js" },
                          "region": { "startLine": 9 }
                        }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
JSON
  exit 0
fi
echo "unexpected codeql args: $*" >&2
exit 2
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_curl_binary(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("curl-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
case "$*" in
  *crt.sh*)
    cat <<'JSON'
[{"name_value":"www.example.com\napi.example.com"}]
JSON
    ;;
  *)
    cat <<'HTTP'
HTTP/1.1 200 OK
Server: nginx
X-Powered-By: Express

<html><title>Acme</title></html>
HTTP
    ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_nmap_binary(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("nmap-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat <<'OUT'
Host: 192.0.2.10 (web.example) Ports: 80/open/tcp//http//nginx/, 443/open/tcp//https//nginx TLS/
OUT
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    fn write_carlini_threat_model_fixture(dir: &Path) {
        let state_dir = dir.join(".kuzushi");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(
            state_dir.join("threat-model.json"),
            r#"{
  "version": "2.0",
  "dfd": {
    "nodes": [
      {"id":"actor-user","type":"external-entity","name":"Authenticated User","description":"External authenticated user","trustZone":"external"},
      {"id":"web","type":"process","name":"Web","description":"Web app","trustZone":"internal"}
    ],
    "flows": [
      {"id":"flow-1","sourceId":"actor-user","targetId":"web","description":"profile request","trustBoundaryIds":["tb-1"],"protocol":"https"}
    ],
    "trustBoundaries": [
      {"id":"tb-1","name":"edge","innerZone":"internal","outerZone":"external","crossingFlowIds":["flow-1"]}
    ]
  },
  "threats": [
    {"id":"T-001","actorIds":["actor-user"],"flowIds":["flow-1"],"targetElementIds":["web"],"category":"tampering","title":"Profile HTML injection","description":"query reaches HTML","attackVector":"crafted profile query","impact":"high","likelihood":"medium","affectedFiles":[{"filePath":"src/app.ts","startLine":9}]}
  ],
  "summary": {"total": 1, "bySeverity": {"high": 1}, "byCategory": {"tampering": 1}}
}
"#,
        )
        .unwrap();
    }

    fn write_systems_hunt_fixture(dir: &Path) {
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();
    }

    #[cfg(unix)]
    fn init_git_repo(dir: &Path) {
        for args in [
            vec!["init"],
            vec!["config", "user.email", "kuzushi@example.test"],
            vec!["config", "user.name", "Kuzushi Test"],
            vec!["add", "."],
            vec!["commit", "-m", "fixture"],
        ] {
            let output = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn validates_and_coerces_declared_tool_options() {
        let descriptor = tool_with_options(
            "test:demo",
            "exercise option validation",
            vec![
                opt("enabled", OptionType::Bool, "boolean option").default(json!(false)),
                opt("limit", OptionType::Int, "integer option").default(json!(10)),
                opt("ratio", OptionType::Float, "floating-point option"),
                opt("target", OptionType::Path, "path option").required(),
                opt("label", OptionType::String, "string option"),
                opt("tags", OptionType::StringList, "string-list option"),
                opt("mode", OptionType::Enum, "enum option")
                    .choices(&["auto", "manual"])
                    .default(json!("auto")),
            ],
        );

        let validated = validate_tool_input_options(
            &descriptor,
            json!({
                "enabled": "yes",
                "limit": "42",
                "ratio": "0.75",
                "target": "./repo",
                "label": "baseline",
                "tags": ["one", "two"],
                "mode": "manual",
                "extra": {"left": "untouched"}
            }),
        )
        .unwrap();
        assert_eq!(validated["enabled"], json!(true));
        assert_eq!(validated["limit"], json!(42));
        assert_eq!(validated["ratio"], json!(0.75));
        assert_eq!(validated["target"], json!("./repo"));
        assert_eq!(validated["label"], json!("baseline"));
        assert_eq!(validated["tags"], json!(["one", "two"]));
        assert_eq!(validated["mode"], json!("manual"));
        assert_eq!(validated["extra"], json!({"left": "untouched"}));

        let with_defaults = validate_tool_input_options(
            &descriptor,
            json!({
                "target": "./repo",
                "ratio": 1.25
            }),
        )
        .unwrap();
        assert_eq!(with_defaults["enabled"], json!(false));
        assert_eq!(with_defaults["limit"], json!(10));
        assert_eq!(with_defaults["mode"], json!("auto"));
    }

    #[test]
    fn rejects_missing_required_and_invalid_option_values() {
        let descriptor = tool_with_options(
            "test:demo",
            "exercise option validation",
            vec![
                opt("enabled", OptionType::Bool, "boolean option"),
                opt("limit", OptionType::Int, "integer option"),
                opt("ratio", OptionType::Float, "floating-point option"),
                opt("target", OptionType::Path, "path option").required(),
                opt("mode", OptionType::Enum, "enum option").choices(&["auto", "manual"]),
            ],
        );

        for (input, expected) in [
            (json!({}), "requires option target"),
            (
                json!({"target": "./repo", "enabled": "maybe"}),
                "must be a boolean",
            ),
            (
                json!({"target": "./repo", "limit": "many"}),
                "must be an integer",
            ),
            (
                json!({"target": "./repo", "ratio": "wide"}),
                "must be a number",
            ),
            (
                json!({"target": "./repo", "mode": "toggle"}),
                "must be one of auto|manual",
            ),
        ] {
            let error = validate_tool_input_options(&descriptor, input).unwrap_err();
            let error = format!("{error:#}");
            assert!(
                error.contains(expected),
                "expected {error:?} to contain {expected:?}"
            );
        }
    }

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
    }

    #[test]
    fn resolves_representative_ported_tools() {
        let registry = ModuleRegistry::with_v2_builtins();
        for expected in [
            "context:build",
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

    #[test]
    fn dispatches_vendor_assessment_artifacts_through_registry() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("soc2.md"),
            "SOC 2 controls cover access review.",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let runtime = MockRuntime::new();

        let attach = registry
            .execute_tool(
                "vendor-assessment:attach",
                json!({
                    "source": "soc2.md",
                    "vendorName": "Acme",
                    "productName": "Acme AI"
                }),
                &ctx,
            )
            .unwrap();
        assert_eq!(attach.get("ok").and_then(Value::as_bool), Some(true));
        assert!(workspace
            .root()
            .join(".kuzushi/vendor-assessment/scope.json")
            .exists());

        let prompts = registry
            .execute_tool(
                "vendor-assessment:prompts",
                json!({"runId": "prompt-fixture"}),
                &ctx,
            )
            .unwrap();
        assert_eq!(
            prompts
                .pointer("/data/prompts")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(3)
        );

        let assessed = registry
            .execute_tool_with_runtime("vendor-assessment:assess", json!({}), &ctx, Some(&runtime))
            .unwrap();
        assert_eq!(assessed.get("ok").and_then(Value::as_bool), Some(true));
        let report_path = assessed
            .pointer("/data/artifacts/reportPath")
            .and_then(Value::as_str)
            .unwrap();
        assert!(Path::new(report_path).exists());
        assert_eq!(
            assessed
                .pointer("/data/report/overallRisk")
                .and_then(Value::as_str),
            Some("medium")
        );
    }

    #[test]
    fn dispatches_chrome_rce_scan_through_registry_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("services/mojo/broker")).unwrap();
        fs::write(
            temp.path().join("services/mojo/broker/handle.cc"),
            "void Broker(HANDLE h) {\n  ::DuplicateHandle(src, h, dst, &out, 0, false, 0);\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool("chrome-rce:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        let stored = store.list_findings(FindingListFilter::MAX_LIMIT).unwrap();
        assert!(stored.iter().any(|finding| finding.tool == "chrome-rce"));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_chrome_rce_review_trigger_with_git_diff() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("README.md"), "fixture\n").unwrap();
        init_git_repo(temp.path());
        fs::create_dir_all(temp.path().join("v8/src/maglev")).unwrap();
        fs::write(
            temp.path()
                .join("v8/src/maglev/maglev-phi-representation-selector.cc"),
            "// risky path\n",
        )
        .unwrap();
        let output = Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = Command::new("git")
            .args(["commit", "-m", "hot path"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "chrome-rce:review-trigger",
                json!({"diffBase": "HEAD~1"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .or_else(|| result.pointer("/data/findings/0/ruleId"))
                .and_then(Value::as_str),
            Some("chrome-rce-hot-path-v8-maglev-phi-representation-selector")
        );
    }

    #[test]
    fn dispatches_plugin_backed_adapters_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/app.ts"),
            "export const handler = (req: any) => req.query.name;\n",
        )
        .unwrap();
        let plugin_root = temp.path().join("plugin-root");
        fs::create_dir_all(&plugin_root).unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let runtime = MockRuntime::new();

        for tool in [
            "vuln-scout:audit",
            "tob:audit",
            "shinsa:quick-check",
            "prompt-armor:analyze",
        ] {
            let result = registry
                .execute_tool_with_runtime(
                    tool,
                    json!({"pluginRoot": plugin_root.display().to_string()}),
                    &ctx,
                    Some(&runtime),
                )
                .unwrap();
            assert_eq!(
                result.get("ok").and_then(Value::as_bool),
                Some(true),
                "{tool}"
            );
            assert!(
                result.pointer("/data/findings/0").is_some()
                    || result.pointer("/data/count").and_then(Value::as_u64) == Some(1),
                "{tool}"
            );
        }

        let stored = store.list_findings(FindingListFilter::MAX_LIMIT).unwrap();
        for tool in ["vuln-scout", "tob-audit", "shinsa", "prompt-armor"] {
            assert!(
                stored.iter().any(|finding| finding.tool == tool),
                "expected persisted finding from {tool}"
            );
        }
    }

    #[test]
    fn plugin_adapters_missing_dependency_fail_actionably() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };
        let runtime = MockRuntime::new();

        let err = registry
            .execute_tool_with_runtime("vuln-scout:audit", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();

        assert!(err.contains("@kuzushi/vuln-scout"));
        assert!(err.contains("pluginRoot"));
    }

    #[test]
    fn prompt_armor_network_tools_require_authorization() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("prompt-armor:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("authorized=true")));
    }

    #[test]
    fn hidden_pipeline_nodes_dispatch_without_visibility() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        assert!(!registry
            .modules()
            .any(|module| module.metadata().id == "pipeline"));
        let selector = registry
            .execute_tool(
                "pipeline:task-selector",
                json!({"tasks": ["semgrep", "secret-scan"], "disabledTasks": ["semgrep"]}),
                &ctx,
            )
            .unwrap();
        assert_eq!(
            selector.pointer("/data/tasks/0").and_then(Value::as_str),
            Some("secret-scan")
        );
        let approval = registry
            .execute_tool(
                "pipeline:approval-before-verification",
                json!({"approved": false}),
                &ctx,
            )
            .unwrap();
        assert_eq!(approval.get("ok").and_then(Value::as_bool), Some(false));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_recon_nmap_through_registry_and_persists() {
        let temp = tempdir().unwrap();
        let binary = fake_nmap_binary(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool(
                "recon:nmap",
                json!({"target":"192.0.2.10","ports":"80,443","binary":binary.display().to_string()}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/hosts/0/address")
                .and_then(Value::as_str),
            Some("192.0.2.10")
        );
        assert_eq!(
            result
                .pointer("/data/services/1/port")
                .and_then(Value::as_u64),
            Some(443)
        );
        let mut store = crate::recon::ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        let hosts = store.list_hosts(&workspace_id).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_recon_http_fingerprint_through_registry_and_persists() {
        let temp = tempdir().unwrap();
        let binary = fake_curl_binary(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool(
                "recon:http-fingerprint",
                json!({"target":"https://www.example.com","binary":binary.display().to_string()}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/hosts/0/address")
                .and_then(Value::as_str),
            Some("www.example.com")
        );
        assert_eq!(
            result
                .pointer("/data/services/0/name")
                .and_then(Value::as_str),
            Some("https")
        );
        let mut store = crate::recon::ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        let hosts = store.list_hosts(&workspace_id).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_recon_subdomain_through_registry_and_persists() {
        let temp = tempdir().unwrap();
        let binary = fake_curl_binary(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool(
                "recon:subdomain",
                json!({"domain":"example.com","source":"crtsh","binary":binary.display().to_string()}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/subdomains/0").and_then(Value::as_str),
            Some("api.example.com")
        );
        let mut store = crate::recon::ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        assert_eq!(store.list_hosts(&workspace_id).unwrap().len(), 2);
    }

    #[test]
    fn recon_missing_workspace_failure_is_explicit() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let error = registry
            .execute_tool(
                "recon:http-fingerprint",
                json!({"target":"example.com"}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("active workspace"));
    }

    #[test]
    fn dispatches_workspace_status_and_findings_export() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        store
            .insert_finding(
                "run-1",
                &Finding::new_tool(
                    "fixture",
                    "fixture/sql",
                    "src/app.ts",
                    3,
                    None,
                    Severity::High,
                    "request data reaches SQL",
                ),
            )
            .unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let status = registry
            .execute_tool("workspace:status", json!({}), &ctx)
            .unwrap();
        assert_eq!(status.get("ok").and_then(Value::as_bool), Some(true));
        assert!(status
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("workspace status")));

        let export = registry
            .execute_tool(
                "workspace:export-findings",
                json!({"output": "exports/findings.json"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            export.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        let output_path = workspace.root().join("exports/findings.json");
        assert!(output_path.exists());
        let exported: Value =
            serde_json::from_str(&fs::read_to_string(output_path).unwrap()).unwrap();
        assert_eq!(exported["count"], json!(1));
    }

    #[test]
    fn dispatches_catalog_tools() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let result = registry
            .execute_tool("catalog:modules", Value::Null, &ctx)
            .unwrap();
        assert!(result
            .as_array()
            .unwrap()
            .iter()
            .any(|module| { module.get("id").and_then(Value::as_str) == Some("semgrep") }));
        assert!(!result
            .as_array()
            .unwrap()
            .iter()
            .any(|module| { module.get("id").and_then(Value::as_str) == Some("context-lite") }));
    }

    #[test]
    fn dispatches_context_build_snapshot() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
        fs::create_dir(temp.path().join("node_modules")).unwrap();
        fs::write(temp.path().join("node_modules/skip.js"), "skip\n").unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("context:build", json!({"sampleLimit": 10}), &ctx)
            .unwrap();
        let sample = result
            .pointer("/data/snapshot/filesSample")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/snapshot/fileIndex/totalFiles")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            result
                .pointer("/data/snapshot/repoContext/languages/0")
                .and_then(Value::as_str),
            Some("Rust")
        );
        assert!(sample.contains(&"Cargo.toml"));
        assert!(sample.contains(&"src/lib.rs"));
        assert!(!sample.contains(&"node_modules/skip.js"));
        let snapshot_path = result
            .pointer("/data/snapshotPath")
            .and_then(Value::as_str)
            .unwrap();
        let persisted = fs::read_to_string(snapshot_path).unwrap();
        let persisted: Value = serde_json::from_str(&persisted).unwrap();
        assert_eq!(
            persisted.get("target").and_then(Value::as_str),
            Some(workspace.root().to_str().unwrap())
        );
        assert_eq!(
            persisted
                .pointer("/fileIndex/totalFiles")
                .and_then(Value::as_u64),
            Some(2)
        );
    }

    #[test]
    fn dispatches_hidden_context_lite_index_without_listing_it_as_visible_tool() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("server.ts"), "export const ok = true;\n").unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        assert!(registry.resolve_tool("context-lite:index").is_none());
        let result = registry
            .execute_tool("context-lite:index", json!({"sampleLimit": 5}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/snapshot/repoContext/languages/0")
                .and_then(Value::as_str),
            Some("TypeScript")
        );
    }

    #[test]
    fn context_build_enrichment_request_fails_explicitly() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let err = registry
            .execute_tool("context:build", json!({"enrichment": true}), &ctx)
            .unwrap_err()
            .to_string();

        assert!(err.contains("does not support LLM enrichment yet"));
        assert!(err.contains(r#""enrichment":false"#));
    }

    // ----- prefilter_score scoring ------------------------------------

    fn finding_with(severity: Severity, tool: &str, message: &str) -> Finding {
        Finding::new_tool(tool, "demo.rule", "src/x.c", 1, None, severity, message)
    }

    #[test]
    fn prefilter_score_scales_with_severity() {
        let crit = prefilter_score(&finding_with(Severity::Critical, "semgrep", ""));
        let high = prefilter_score(&finding_with(Severity::High, "semgrep", ""));
        let med = prefilter_score(&finding_with(Severity::Medium, "semgrep", ""));
        let low = prefilter_score(&finding_with(Severity::Low, "semgrep", ""));
        assert!(crit > high);
        assert!(high > med);
        assert!(med > low);
    }

    #[test]
    fn prefilter_score_bumps_for_attacker_keywords() {
        let plain = prefilter_score(&finding_with(Severity::High, "semgrep", "generic warning"));
        let with_keyword = prefilter_score(&finding_with(
            Severity::High,
            "semgrep",
            "user-controlled buffer overflow with attacker-supplied length",
        ));
        assert!(with_keyword > plain);
    }

    #[test]
    fn prefilter_score_bumps_for_curated_tools() {
        let semgrep = prefilter_score(&finding_with(Severity::Medium, "semgrep", ""));
        let cargo_audit = prefilter_score(&finding_with(Severity::Medium, "cargo-audit", ""));
        let codeql = prefilter_score(&finding_with(Severity::Medium, "codeql", ""));
        let unknown = prefilter_score(&finding_with(Severity::Medium, "random-tool", ""));
        assert!(cargo_audit > semgrep);
        assert!(codeql > semgrep);
        assert!(semgrep > unknown);
    }

    #[test]
    fn prefilter_score_unknown_severity_is_low() {
        let unk = prefilter_score(&finding_with(Severity::Unknown, "semgrep", ""));
        let crit = prefilter_score(&finding_with(Severity::Critical, "semgrep", ""));
        assert!(unk < crit);
    }

    #[test]
    fn prefilter_score_is_deterministic() {
        let f = finding_with(Severity::High, "codeql", "use-after-free in handler");
        assert_eq!(prefilter_score(&f), prefilter_score(&f));
    }

    // ----- TriageOutcome cost field round-trips through persistence

    #[test]
    fn triage_outcome_persists_cost_usd() {
        use crate::findings::FindingStore;
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-cost-test", std::path::Path::new("/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool("test", "rule", "src/x.c", 1, None, Severity::High, "msg");
        let finding_id = store.insert_finding("run-cost-test", &finding).unwrap();

        let outcome = TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "test".to_string(),
            cost_usd: 0.0123,
        };
        store.save_triage(finding_id, &outcome).unwrap();

        // Reload the finding via the public API and confirm the
        // verdict + confidence round-trip; cost_usd persists in the
        // triage table even if Finding.triage doesn't surface it.
        let reloaded = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        assert!(reloaded.triage.is_some());
        let triage = reloaded.triage.unwrap();
        assert_eq!(triage.verdict, TriageVerdict::TruePositive);
        assert!((triage.confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn triage_outcome_default_cost_is_zero() {
        let o = TriageOutcome::default();
        assert_eq!(o.cost_usd, 0.0);
        assert_eq!(o.verdict, TriageVerdict::NeedsReview);
    }

    #[test]
    fn dispatches_dep_hygiene_check() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest","react":"^18.2.0"}}"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("dep-hygiene:check", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/packageName")
                .and_then(Value::as_str),
            Some("lodash")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("dep-hygiene: 1 risky specifier")));
    }

    #[test]
    fn dep_hygiene_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "dep-hygiene:check",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("dep-hygiene: target does not exist"));
    }

    #[test]
    fn dispatches_secret_scan() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("config.env"),
            [
                "OPENAI_API_KEY=",
                "sk",
                "-proj-",
                "abcdefghijklmnopqrstuvwxyzABCDEFGH",
            ]
            .concat(),
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("secret-scan:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findings/0/ruleId")
                .and_then(Value::as_str),
            Some("secret-scan/openai-api-key")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("secret-scan: 1 finding")));
    }

    #[test]
    fn secret_scan_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "secret-scan:scan",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("secret-scan: target is not a directory"));
    }

    #[test]
    fn dispatches_iac_scan_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("Dockerfile"),
            "FROM node:latest\nUSER root\n",
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool("iac-scan:scan", json!({"kind": "dockerfile"}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/ruleId")
                .and_then(Value::as_str),
            Some("iac-scan/dockerfile-floating-image")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap().len(), 3);
    }

    #[test]
    fn iac_scan_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "iac-scan:scan",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("iac-scan: target does not exist"));
    }

    #[test]
    fn dispatches_sast_scan_through_scan_runner_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("config.env"),
            [
                "OPENAI_API_KEY=",
                "sk",
                "-proj-",
                "abcdefghijklmnopqrstuvwxyzABCDEFGH",
            ]
            .concat(),
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["dep-hygiene", "secret-scan"],
                    "severity": ["high"]
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(store.list_findings(10).unwrap().len(), 2);
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| {
                output.contains("sast:scan")
                    && output.contains("dep-hygiene")
                    && output.contains("secret-scan")
            }));
    }

    #[test]
    fn sast_scan_can_continue_into_pi_agent_core_triage() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["dep-hygiene"],
                    "triage": true
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/triage/triaged")
                .and_then(Value::as_u64),
            Some(1)
        );
        let stored = store.list_findings(10).unwrap();
        assert_eq!(
            stored[0].triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::TruePositive)
        );
        assert_eq!(runtime.requests().len(), 1);
    }

    #[test]
    fn dispatches_agentic_sast_scan_through_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "agentic-sast:scan",
                json!({"maxFindings": 5, "severity": ["ERROR"]}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("agentic/sql-injection")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
        let query = runtime.queries().pop().unwrap();
        assert_eq!(query.model, "openai:gpt-4.1");
        assert!(query.prompt.contains("src/db.ts"));
        assert!(query.prompt.contains("db.query(req.query.q)"));
    }

    #[test]
    fn whitebox_agent_tools_for_agentic_sast_are_read_only() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "mode": "whitebox-static",
                    "taskMode": "manual",
                    "tasks": ["agentic"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(
            result.pointer("/data/mode").and_then(Value::as_str),
            Some("whitebox-static")
        );
        let query = runtime.queries().pop().unwrap();
        assert_eq!(query.tool_policy.profile, "whitebox-static");
        assert_eq!(
            query.tool_policy.tools,
            vec![
                "Read".to_string(),
                "Glob".to_string(),
                "Grep".to_string(),
                "LS".to_string()
            ]
        );
        for forbidden in ["Bash", "shell", "Write", "Edit", "patch", "apply_patch"] {
            assert!(
                !query
                    .tool_policy
                    .tools
                    .iter()
                    .any(|tool| tool.eq_ignore_ascii_case(forbidden)),
                "forbidden whitebox tool was enabled: {forbidden}"
            );
        }
    }

    #[test]
    fn whitebox_triage_prompt_for_agentic_sast_uses_static_schema() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "mode": "whitebox-static",
                    "taskMode": "manual",
                    "tasks": ["agentic"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        let query = runtime.queries().pop().unwrap();
        assert!(query.system_prompt.contains("whitebox-static mode"));
        for field in [
            "\"verdict\"",
            "\"staticProofState\"",
            "\"source\"",
            "\"sink\"",
            "\"path\"",
            "\"sanitizerAssessment\"",
            "\"guardAssessment\"",
            "\"citations\"",
            "\"assumptions\"",
            "\"missingEvidence\"",
            "\"triggerNarrative\"",
            "\"impactNarrative\"",
            "\"recommendedFix\"",
        ] {
            assert!(query.system_prompt.contains(field), "missing {field}");
        }
        for rule in [
            "Do not include payloads",
            "PoCs",
            "exploit execution",
            "runtime exploitability claims",
            "no active exploitation",
            "no HTTP replay",
            "no fuzzing",
            "no live target scanning",
            "no PoC generation",
            "no PoC execution",
        ] {
            assert!(
                query.system_prompt.contains(rule) || query.prompt.contains(rule),
                "whitebox prompt did not include rule {rule}"
            );
        }
        assert!(query
            .prompt
            .contains("Every reported claim must cite repository source lines"));
    }

    #[test]
    fn whitebox_triage_prompt_response_normalizes_static_schema_fields() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        let mut source = (1..=11)
            .map(|line| format!("// filler {line}"))
            .collect::<Vec<_>>();
        source.push("const q = req.query.q;".to_string());
        source.push("db.query(q);".to_string());
        source.push("return q;".to_string());
        fs::write(
            temp.path().join("src/routes.ts"),
            format!("{}\n", source.join("\n")),
        )
        .unwrap();
        let raw = json!({
            "findings": [{
                "ruleId": "agentic/whitebox-sql",
                "title": "Request input reaches SQL query",
                "verdict": "needs_review",
                "staticProofState": "sanitizer_checked",
                "severity": "high",
                "confidence": "medium",
                "source": {
                    "kind": "attacker_input",
                    "filePath": "src/routes.ts",
                    "startLine": 12,
                    "endLine": 12,
                    "description": "req.query.q is read by the route"
                },
                "sink": {
                    "kind": "sql_query",
                    "filePath": "src/routes.ts",
                    "startLine": 13,
                    "endLine": 13,
                    "description": "db.query receives the interpolated value"
                },
                "path": {
                    "kind": "direct",
                    "explanation": "The local handler passes q into db.query."
                },
                "sanitizerAssessment": {
                    "status": "unknown",
                    "explanation": "No sanitizer appears in the cited snippet."
                },
                "guardAssessment": {
                    "status": "present",
                    "explanation": "requireAuth gates the route."
                },
                "citations": [{
                    "filePath": "src/routes.ts",
                    "startLine": 12,
                    "endLine": 14,
                    "snippet": "const q = req.query.q;\ndb.query(q);\nreturn q;"
                }],
                "assumptions": ["Express route wiring is static."],
                "missingEvidence": ["Runtime reachability is not assessed."],
                "triggerNarrative": "Static trigger path: GET /search reads q.",
                "impactNarrative": "Potential SQL injection if q is unsanitized.",
                "recommendedFix": "Use parameterized queries."
            }]
        });

        let findings = normalize_agentic_sast_findings(raw, temp.path(), 5, true).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "agentic/whitebox-sql");
        assert_eq!(findings[0].file_path, "src/routes.ts");
        assert_eq!(findings[0].start_line, 12);
        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::SanitizerChecked)
        );
        assert!(findings[0]
            .message
            .contains("Static proof state: sanitizer_checked"));
        assert!(findings[0]
            .message
            .contains("Sanitizer assessment: No sanitizer appears"));
        assert!(findings[0]
            .message
            .contains("Trigger narrative: Static trigger path"));
        assert!(findings[0]
            .message
            .contains("Recommended fix: Use parameterized queries."));
    }

    #[test]
    fn whitebox_citations_downgrade_statically_confirmed_before_persistence() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "const q = req.query.q;\ndb.query(q);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let raw = json!({
            "findings": [{
                "ruleId": "agentic/whitebox-stale",
                "title": "Request input reaches SQL query",
                "verdict": "true_positive",
                "staticProofState": "statically_confirmed",
                "severity": "high",
                "source": {
                    "kind": "attacker_input",
                    "filePath": "src/routes.ts",
                    "startLine": 1,
                    "endLine": 1,
                    "description": "req.query.q is read"
                },
                "sink": {
                    "kind": "sql_query",
                    "filePath": "src/routes.ts",
                    "startLine": 2,
                    "endLine": 2,
                    "description": "db.query receives q"
                },
                "path": {
                    "kind": "direct",
                    "explanation": "q is passed directly to db.query."
                },
                "sanitizerAssessment": {
                    "status": "absent",
                    "explanation": "No sanitizer appears between source and sink."
                },
                "guardAssessment": {
                    "status": "not_applicable",
                    "explanation": "The claim does not depend on an auth guard."
                },
                "citations": [{
                    "filePath": "src/routes.ts",
                    "startLine": 1,
                    "endLine": 2,
                    "snippet": "const q = req.query.q;\ndb.query(req.body.q);"
                }],
                "assumptions": ["Static route wiring is inferred from source."],
                "missingEvidence": ["Runtime reachability is not assessed."]
            }]
        });

        let findings = normalize_agentic_sast_findings(raw, temp.path(), 5, true).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::NeedsRuntimeEvidence)
        );
        assert!(findings[0]
            .message
            .contains("Whitebox citation validation: downgraded"));
        assert!(findings[0].message.contains("snippet text does not match"));

        let persisted = persist_agentic_sast_findings(temp.path(), &findings, &ctx)
            .unwrap()
            .unwrap();
        assert!(!persisted.run_id.is_empty());
        let stored = store.list_findings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].static_proof_state,
            Some(StaticProofState::NeedsRuntimeEvidence)
        );
    }

    #[test]
    fn agentic_sast_scan_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool("agentic-sast:scan", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime("agentic-sast:scan", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn dispatches_taint_iris_hunt_through_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "taint-iris:hunt",
                json!({
                    "maxFindings": 5,
                    "TAINT_IRIS_PROMPT": "Focus on SQL sinks only."
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/cwes/0/id").and_then(Value::as_str),
            Some("CWE-89")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("taint-iris/cwe-89")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        let stored = store.list_findings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].tool, "taint-iris");
        assert!(stored[0].message.contains("req.query.q -> db.query"));

        let queries = runtime.queries();
        assert_eq!(queries.len(), 2);
        assert!(queries[0].system_prompt.contains("Taint CWE selector"));
        assert!(queries[1]
            .system_prompt
            .contains("IRIS-style taint analysis"));
        assert!(queries[1].prompt.contains("Focus on SQL sinks only."));
        assert!(queries[1].prompt.contains("CWE-89"));
    }

    #[test]
    fn taint_iris_hunt_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool("taint-iris:hunt", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime("taint-iris:hunt", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn taint_iris_next_plan_mode_is_deterministic_and_does_not_require_runtime() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "taint-iris-next:hunt",
                json!({"mode": "plan", "maxCatalogEntries": 1}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/status").and_then(Value::as_str),
            Some("planned")
        );
        assert_eq!(
            result
                .pointer("/data/cweCatalog/0/cwe")
                .and_then(Value::as_str),
            Some("CWE-89")
        );
        assert!(result
            .pointer("/data/agentPrompt")
            .and_then(Value::as_str)
            .is_some_and(|prompt| prompt.contains("CWE Candidate Catalog")));
        assert_eq!(store.list_findings(10).unwrap().len(), 0);
    }

    #[test]
    fn dispatches_taint_iris_next_hunt_through_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "taint-iris-next:hunt",
                json!({
                    "mode": "hunt",
                    "maxCatalogEntries": 3,
                    "maxAgentFindings": 5,
                    "minEvidenceLevel": "candidate"
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/status").and_then(Value::as_str),
            Some("hunted")
        );
        assert_eq!(
            result
                .pointer("/data/selectedCwes/0/cwe")
                .and_then(Value::as_str),
            Some("CWE-89")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("taint-iris-next/cwe-89")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        let stored = store.list_findings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].tool, "taint-iris-next");
        assert!(stored[0].message.contains("req.query.id -> db.query"));

        let queries = runtime.queries();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].model, "openai:gpt-4.1");
        assert!(queries[0].prompt.contains("Taint IRIS Next"));
        assert!(queries[0].prompt.contains("CWE Candidate Catalog"));
        assert!(queries[0].prompt.contains("src/routes.ts"));
    }

    #[test]
    fn taint_iris_next_hunt_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "db.query(req.query.id)\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool(
                "taint-iris-next:hunt",
                json!({"mode": "hunt", "maxCatalogEntries": 5}),
                &ctx,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime(
                "taint-iris-next:hunt",
                json!({"mode": "hunt", "maxCatalogEntries": 5}),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn dispatches_hidden_taint_cwe_selector_through_runtime_without_listing_it_as_visible_tool() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        assert!(registry.resolve_tool("pipeline:taint-cwe-select").is_none());

        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime("pipeline:taint-cwe-select", json!({}), &ctx, Some(&runtime))
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/cwes/0/id").and_then(Value::as_str),
            Some("CWE-89")
        );
        assert_eq!(runtime.queries().len(), 1);
    }

    #[test]
    fn dispatches_carlini_threat_hunt_through_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/app.ts"),
            "res.send(`<p>${req.query.name}</p>`)\n",
        )
        .unwrap();
        write_carlini_threat_model_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "carlini-threat-hunt:run",
                json!({"maxActors": 1, "runsPerActor": 1}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("carlini-threat-hunt/actor-xss")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/actor_fingerprint")
                .and_then(Value::as_str),
            Some("carlini-threat-hunt:Authenticated_User:0")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        let stored = store.list_findings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].tool, "carlini-threat-hunt");
        assert_eq!(
            stored[0].actor_fingerprint.as_deref(),
            Some("carlini-threat-hunt:Authenticated_User:0")
        );
        let query = runtime.queries().pop().unwrap();
        assert_eq!(query.model, "openai:gpt-4.1");
        assert!(query.prompt.contains("Authenticated User"));
        assert!(query.prompt.contains("src/app.ts"));
    }

    #[test]
    fn carlini_threat_hunt_requires_threat_model_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool("carlini-threat-hunt:run", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an existing .kuzushi/threat-model.json"));

        write_carlini_threat_model_fixture(temp.path());
        let err = registry
            .execute_tool("carlini-threat-hunt:run", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime("carlini-threat-hunt:run", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn sast_scan_routes_agentic_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["agentic"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("agentic")
        );
        assert!(result
            .pointer("/data/agentic/count")
            .and_then(Value::as_u64)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "agentic");
    }

    #[test]
    fn sast_scan_routes_carlini_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/app.ts"),
            "res.send(`<p>${req.query.name}</p>`)\n",
        )
        .unwrap();
        write_carlini_threat_model_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["carlini-threat-hunt"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("carlini-threat-hunt")
        );
        assert!(result
            .pointer("/data/carliniThreatHunt/count")
            .and_then(Value::as_u64)
            .is_some());
        assert_eq!(
            store.list_findings(10).unwrap()[0].tool,
            "carlini-threat-hunt"
        );
    }

    #[test]
    fn sast_scan_routes_taint_iris_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["taint-iris"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("taint-iris")
        );
        assert!(result
            .pointer("/data/taintIris/count")
            .and_then(Value::as_u64)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "taint-iris");
    }

    #[test]
    fn sast_scan_routes_taint_iris_next_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["taint-iris-next"],
                    "maxCatalogEntries": 3,
                    "maxAgentFindings": 5,
                    "minEvidenceLevel": "candidate"
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("taint-iris-next")
        );
        assert!(result
            .pointer("/data/taintIrisNext/count")
            .and_then(Value::as_u64)
            .is_some());
        assert!(result
            .pointer("/data/runIds/taintIrisNext")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "taint-iris-next");
    }

    #[test]
    fn dispatches_systems_hunt_through_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        write_systems_hunt_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "systems-hunt:systems-hunt",
                json!({"maxFindings": 5}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("systems-hunt/cwe-787")
        );
        assert!(result
            .pointer("/data/artifacts/0")
            .and_then(Value::as_str)
            .is_some_and(|path| path.starts_with(".kuzushi/systems-hunt/")));
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "systems-hunt");
    }

    #[test]
    fn systems_hunt_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        write_systems_hunt_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let err = registry
            .execute_tool("systems-hunt:systems-hunt", json!({"maxFindings": 5}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime(
                "systems-hunt:systems-hunt",
                json!({"maxFindings": 5}),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn sast_scan_routes_systems_hunt_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        write_systems_hunt_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["systems-hunt"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("systems-hunt")
        );
        assert!(result
            .pointer("/data/systemsHunt/count")
            .and_then(Value::as_u64)
            .is_some());
        assert!(result
            .pointer("/data/runIds/systemsHunt")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "systems-hunt");
    }

    #[test]
    fn sast_scan_runs_verify_patch_and_writes_run_artifacts() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/db.ts"),
            "const query = req.query.q;\n",
        )
        .unwrap();
        init_git_repo(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["agentic"],
                    "verify": true,
                    "autoPatch": true,
                    "maxIterations": 1,
                    "buildCmd": "true",
                    "testCmd": "true"
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/triage/triaged")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/verification/verified")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/patch/patched")
                .and_then(Value::as_u64),
            Some(1)
        );

        let summary = result
            .pointer("/data/artifacts/summary")
            .and_then(Value::as_str)
            .unwrap();
        let triage_log = result
            .pointer("/data/artifacts/triageJsonl")
            .and_then(Value::as_str)
            .unwrap();
        let verify_log = result
            .pointer("/data/artifacts/verifyJsonl")
            .and_then(Value::as_str)
            .unwrap();
        assert!(Path::new(summary).exists());
        assert!(fs::read_to_string(summary)
            .unwrap()
            .contains("\"verification\""));
        assert!(fs::read_to_string(triage_log)
            .unwrap()
            .contains("triage:complete"));
        let verify_log = fs::read_to_string(verify_log).unwrap();
        assert!(verify_log.contains("verification:complete"));
        assert!(verify_log.contains("patch:complete"));

        let finding = store.list_findings(10).unwrap().pop().unwrap();
        let patch_results = store
            .get_patch_results_for_finding(&finding.fingerprint)
            .unwrap();
        assert_eq!(patch_results.len(), 1);
        assert_eq!(patch_results[0].status, PatchStatus::Sound);
    }

    #[test]
    fn whitebox_static_sast_mode_disables_execution_and_patch_paths() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "mode": "whitebox-static",
                    "taskMode": "manual",
                    "tasks": ["dep-hygiene"],
                    "verify": true,
                    "autoPatch": true,
                    "pocHarness": true,
                    "pocExecution": true,
                    "dynamicAnalysis": true,
                    "cryptoBehavioralTesting": true,
                    "proofState": "execution_confirmed"
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(
            result.pointer("/data/mode").and_then(Value::as_str),
            Some("whitebox-static")
        );
        assert_eq!(
            result
                .pointer("/data/whiteboxStatic/enabled")
                .and_then(Value::as_bool),
            Some(true)
        );
        for pointer in [
            "/data/whiteboxStatic/verify",
            "/data/whiteboxStatic/pocHarness",
            "/data/whiteboxStatic/pocExecution",
            "/data/whiteboxStatic/dynamicAnalysis",
            "/data/whiteboxStatic/cryptoBehavioralTesting",
            "/data/whiteboxStatic/patching",
            "/data/whiteboxStatic/autoPatch",
            "/data/whiteboxStatic/executionProofStates",
            "/data/whiteboxStatic/runtimeExploitabilityClaims",
        ] {
            assert_eq!(
                result.pointer(pointer).and_then(Value::as_bool),
                Some(false)
            );
        }
        assert_eq!(
            result
                .pointer("/data/verification/verified")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            result
                .pointer("/data/patch/patched")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert!(runtime.requests().is_empty());
        assert!(runtime.queries().is_empty());

        let scan_input = fs::read_to_string(
            result
                .pointer("/data/artifacts/dir")
                .and_then(Value::as_str)
                .map(Path::new)
                .unwrap()
                .join("scan-input.json"),
        )
        .unwrap();
        assert!(scan_input.contains("\"mode\": \"whitebox-static\""));
        assert!(!scan_input.contains("execution_confirmed"));
        assert!(scan_input.contains("needs_runtime_evidence"));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("Static narrative: trigger path summarized"));
        assert!(result
            .pointer("/data/staticNarratives/count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0));
        let static_narratives = fs::read_to_string(
            result
                .pointer("/data/artifacts/staticNarratives")
                .and_then(Value::as_str)
                .unwrap(),
        )
        .unwrap();
        assert!(static_narratives.contains("Static trigger path"));
        assert!(static_narratives.contains("Potential impact"));
        assert!(static_narratives.contains("Evidence limits"));
        assert!(!static_narratives
            .to_ascii_lowercase()
            .contains("confirmed exploit"));
        assert!(!static_narratives
            .to_ascii_lowercase()
            .contains("poc payload"));

        let stored = store.list_findings(10).unwrap();
        assert!(!stored.is_empty());
        assert!(stored
            .iter()
            .all(|finding| { finding.static_proof_state == Some(StaticProofState::SignalOnly) }));
    }

    #[cfg(unix)]
    #[test]
    fn whitebox_diff_sast_mode_writes_pr_scope_artifact() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        init_git_repo(temp.path());
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest","express":"latest"}}"#,
        )
        .unwrap();
        for args in [vec!["add", "."], vec!["commit", "-m", "pr"]] {
            let output = Command::new("git")
                .args(args)
                .current_dir(temp.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "sast:scan",
                json!({
                    "mode": "whitebox-static",
                    "taskMode": "manual",
                    "tasks": ["dep-hygiene"],
                    "diffBase": "HEAD~1"
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result.pointer("/data/mode").and_then(Value::as_str),
            Some("whitebox-static")
        );
        assert_eq!(
            result
                .pointer("/data/whiteboxDiff/noRemoteProviderRequired")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            result
                .pointer("/data/whiteboxDiff/summary/changedFiles")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert!(result
            .pointer("/data/whiteboxDiff/findingTags")
            .and_then(Value::as_array)
            .is_some_and(|tags| !tags.is_empty()));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("Diff scope: 1 changed file"));
        let artifact = result
            .pointer("/data/artifacts/whiteboxDiff")
            .and_then(Value::as_str)
            .unwrap();
        let artifact_body = fs::read_to_string(artifact).unwrap();
        assert!(artifact_body.contains("\"changedFiles\""));
        assert!(artifact_body.contains("\"noRemoteProviderRequired\": true"));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_semgrep_scan_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("server.js"), "res.send(req.query.x)\n").unwrap();
        let binary = fake_semgrep_binary(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "semgrep:scan",
                json!({"binary": binary.display().to_string(), "config": "p/security-audit"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("javascript.express.security.audit.xss")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn semgrep_static_evidence_direct_tool_indexes_whitebox_signal_only() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("server.js"),
            [
                "const express = require('express');",
                "const app = express();",
                "app.get('/x', (req, res) => {",
                "  const name = req.query.name;",
                "  const prefix = '<h1>';",
                "  const suffix = '</h1>';",
                "  const body = prefix + name;",
                "  const html = body + suffix;",
                "  res.status(200);",
                "  res.set('content-type', 'text/html');",
                "  res.send(html);",
            ]
            .join("\n"),
        )
        .unwrap();
        let binary = fake_semgrep_binary(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "semgrep:scan",
                json!({
                    "binary": binary.display().to_string(),
                    "mode": "whitebox-static"
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result
                .pointer("/data/findings/0/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert_eq!(
            result
                .pointer("/data/persisted/staticEvidence/findingsIndexed")
                .and_then(Value::as_u64),
            Some(1)
        );

        let finding = store.list_findings(10).unwrap().pop().unwrap();
        let evidence_store = crate::static_evidence::StaticEvidenceStore::open(&workspace).unwrap();
        let nodes = evidence_store
            .list_nodes_for_finding(&finding.fingerprint)
            .unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().any(|node| {
            node.kind == crate::static_evidence::StaticEvidenceNodeKind::ScannerSignal
                && node
                    .metadata
                    .pointer("/truePositiveByDefault")
                    .and_then(Value::as_bool)
                    == Some(false)
        }));
    }

    #[test]
    fn semgrep_missing_binary_failure_is_actionable() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "semgrep:scan",
                json!({"binary": temp.path().join("missing-semgrep").display().to_string()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("semgrep: could not find scanner binary"));
        assert!(err.contains("Install Semgrep"));
        assert!(err.contains(r#""binary":"/path/to/semgrep""#));
        assert!(err.contains("Next: run semgrep:scan"));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_codeql_scan_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("package.json"), "{}\n").unwrap();
        fs::write(temp.path().join("server.js"), "db.query(req.query.q)\n").unwrap();
        let binary = fake_codeql_binary(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "codeql:scan",
                json!({"binary": binary.display().to_string(), "language": "javascript"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("js/sql-injection")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn codeql_static_evidence_direct_tool_indexes_whitebox_code_flow() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("package.json"), "{}\n").unwrap();
        fs::write(
            temp.path().join("server.js"),
            [
                "const q = req.query.q;",
                "function load(db) {",
                "  const prefix = 'select ';",
                "  const table = 'users';",
                "  const where = ' where name = ';",
                "  const sql = prefix + '* from ' + table + where;",
                "  const suffix = q;",
                "  const built = sql + suffix;",
                "  return db.query(built);",
            ]
            .join("\n"),
        )
        .unwrap();
        let binary = fake_codeql_binary(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "codeql:scan",
                json!({
                    "binary": binary.display().to_string(),
                    "language": "javascript",
                    "mode": "whitebox-static"
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result
                .pointer("/data/findings/0/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert_eq!(
            result
                .pointer("/data/persisted/staticEvidence/findingsIndexed")
                .and_then(Value::as_u64),
            Some(1)
        );

        let finding = store.list_findings(10).unwrap().pop().unwrap();
        let evidence_store = crate::static_evidence::StaticEvidenceStore::open(&workspace).unwrap();
        let nodes = evidence_store
            .list_nodes_for_finding(&finding.fingerprint)
            .unwrap();
        assert!(nodes.iter().any(|node| {
            node.kind == crate::static_evidence::StaticEvidenceNodeKind::ScannerSignal
                && node
                    .metadata
                    .pointer("/truePositiveByDefault")
                    .and_then(Value::as_bool)
                    == Some(false)
        }));
        assert!(nodes
            .iter()
            .any(|node| node.kind == crate::static_evidence::StaticEvidenceNodeKind::DataflowStep));
    }

    #[test]
    fn codeql_missing_binary_failure_is_actionable() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "codeql:scan",
                json!({
                    "binary": temp.path().join("missing-codeql").display().to_string(),
                    "language": "javascript"
                }),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("codeql: could not find CodeQL CLI"));
        assert!(err.contains("github/codeql-cli-binaries"));
        assert!(err.contains(r#""binary":"/path/to/codeql""#));
        assert!(err.contains("Next: run codeql:scan"));
    }

    #[test]
    fn dispatches_findings_list_with_filters() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let confirmed = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let low = Finding::new_semgrep(
            "demo.token",
            "tests/token.ts",
            3,
            Some(3),
            Severity::Low,
            "Hardcoded token in tests",
        );
        let confirmed_id = store.insert_finding("run-1", &confirmed).unwrap();
        store.insert_finding("run-1", &low).unwrap();
        store
            .save_triage(
                confirmed_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "confirmed path".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let result = registry
            .execute_tool(
                "findings:list",
                json!({"severity": ["high"], "verdict": ["tp"], "name": "sql"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("demo.sql")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("SQL injection in search")));
    }

    #[test]
    fn dispatches_triage_run_with_runtime_and_persists_outcomes() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let confirmed = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let ignored = Finding::new_semgrep(
            "demo.fp",
            "src/debug.ts",
            2,
            Some(2),
            Severity::Low,
            "Debug log flagged",
        );
        store.insert_finding("run-1", &confirmed).unwrap();
        store.insert_finding("run-1", &ignored).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "triage:run",
                json!({
                    "fingerprint": confirmed.fingerprint.clone(),
                    "TRIAGE_PROMPT": "Use repository evidence only."
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/triaged").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(result.pointer("/data/tp").and_then(Value::as_u64), Some(1));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("Triaged 1 of 1")));

        let stored = store
            .get_finding_by_fingerprint(&confirmed.fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::TruePositive)
        );
        let requests = runtime.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].model, "openai:gpt-4.1");
        assert_eq!(
            requests[0].prompt_template.as_deref(),
            Some("Use repository evidence only.")
        );
    }

    #[test]
    fn triage_run_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        store.insert_finding("run-1", &finding).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool("triage:run", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime("triage:run", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn triage_run_reports_no_matching_findings_without_calling_runtime() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "triage:run",
                json!({"fingerprint": "missing"}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(
            result.pointer("/data/triaged").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            result
                .pointer("/data/missingFingerprints/0")
                .and_then(Value::as_str),
            Some("missing")
        );
        assert!(runtime.requests().is_empty());
    }

    #[test]
    fn dispatches_verify_finding_through_runtime() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "verify:finding",
                json!({
                    "fingerprint": finding.fingerprint.clone(),
                    "VERIFY_PROMPT": "Prove exploitability with concrete runtime evidence."
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/fingerprint").and_then(Value::as_str),
            Some("from-bridge")
        );
        assert_eq!(
            result.pointer("/data/exploitable").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            result.pointer("/data/attackVector").and_then(Value::as_str),
            Some("curl POST /admin")
        );
        assert_eq!(
            result.pointer("/data/proofLevel").and_then(Value::as_u64),
            Some(3)
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("VULNERABLE")));

        let queries = runtime.queries();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].model, "openai:gpt-4.1");
        assert!(queries[0]
            .prompt
            .contains("Prove exploitability with concrete runtime evidence."));
        assert!(queries[0].prompt.contains(&finding.fingerprint));
    }

    #[test]
    fn verify_finding_requires_triage_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "verify:finding",
                json!({"fingerprint": finding.fingerprint.clone()}),
                &ctx,
            )
            .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("Run triage:run first")));

        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let err = registry
            .execute_tool(
                "verify:finding",
                json!({"fingerprint": finding.fingerprint.clone()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime(
                "verify:finding",
                json!({"fingerprint": finding.fingerprint}),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_patch_finding_through_runtime_and_persists_result() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/db.ts"),
            "const query = req.query.q;\n",
        )
        .unwrap();
        init_git_repo(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            1,
            Some(1),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "patch:finding",
                json!({
                    "fingerprint": finding.fingerprint.clone(),
                    "maxIterations": 1,
                    "buildCmd": "true",
                    "testCmd": "true"
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(
            result.get("ok").and_then(Value::as_bool),
            Some(true),
            "result: {result}"
        );
        assert_eq!(
            result.pointer("/data/status").and_then(Value::as_str),
            Some("SOUND")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("patch:finding SOUND")
                && output.contains("--- a/src/db.ts")));

        let patch_results = store
            .get_patch_results_for_finding(&finding.fingerprint)
            .unwrap();
        assert_eq!(patch_results.len(), 1);
        assert_eq!(patch_results[0].status, PatchStatus::Sound);
        assert_eq!(patch_results[0].iterations, 1);

        let queries = runtime.queries();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].model, "openai:gpt-4.1");
        assert!(queries[0].prompt.contains(&finding.fingerprint));
        assert!(queries[0].prompt.contains("const query = req.query.q"));
    }

    #[test]
    fn patch_finding_requires_triage_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "patch:finding",
                json!({"fingerprint": finding.fingerprint.clone()}),
                &ctx,
            )
            .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("Run triage:run first")));

        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let err = registry
            .execute_tool(
                "patch:finding",
                json!({"fingerprint": finding.fingerprint.clone()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime(
                "patch:finding",
                json!({"fingerprint": finding.fingerprint}),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn dispatches_x_ray_read_artifact_parser() {
        let temp = tempdir().unwrap();
        let artifact_dir = temp.path().join("x-ray");
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("x-ray.md"),
            "# X-Ray\n\n## X-Ray Verdict\nREADY\nReviewable surface.\n",
        )
        .unwrap();
        fs::write(
            artifact_dir.join("entry-points.md"),
            "# Entry Points\n\n> App | 2 entry points | 1 permissionless | 1 role-gated | 0 admin-only\n",
        )
        .unwrap();
        fs::write(
            artifact_dir.join("invariants.md"),
            "# Invariants\n\n### G-1 Balance\n### I-1 Oracle\n",
        )
        .unwrap();
        fs::write(
            artifact_dir.join("architecture.svg"),
            r#"<svg xmlns="http://www.w3.org/2000/svg" />"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("x-ray:read", json!({}), &ctx)
            .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/verdict/tier").and_then(Value::as_str),
            Some("READY")
        );
        assert_eq!(
            result
                .pointer("/data/entryPointCounts/total")
                .and_then(Value::as_u64),
            Some(2)
        );
    }
}
