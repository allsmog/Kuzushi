use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::findings::{Finding, Severity};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolPolicy};
use crate::whitebox_static::agent_tool_policy_for_input;

const SYSTEMS_INVARIANT_SYSTEM_PROMPT: &str = "Systems Hunt invariant extractor";
const SYSTEMS_TRIGGER_SYSTEM_PROMPT: &str = "Systems Hunt trigger synthesizer";
const SYSTEMS_HUNT_SYSTEM_PROMPT: &str = "Systems Hunt low-level vulnerability hunter";
const DEEP_SEMANTIC_CWE_SYSTEM_PROMPT: &str = "Deep Semantic CWE selector";
const DEEP_SEMANTIC_HUNT_SYSTEM_PROMPT: &str = "Deep Semantic Hunt vulnerability hunter";

const SYSTEMS_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx", "rs", "go", "zig",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".kuzushi",
    ".next",
    ".turbo",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
];

#[derive(Debug, Clone)]
struct SystemsHuntInput {
    max_findings: usize,
    max_surfaces: usize,
    max_trigger_hypotheses_per_surface: usize,
    max_cwe_classes: usize,
    artifact_dir: String,
    model: Option<String>,
}

impl SystemsHuntInput {
    fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            max_findings: positive_usize(input, &["maxFindings", "max_findings"], 30)?,
            max_surfaces: positive_usize(input, &["maxSurfaces", "max_surfaces"], 10)?,
            max_trigger_hypotheses_per_surface: positive_usize(
                input,
                &[
                    "maxTriggerHypothesesPerSurface",
                    "max_trigger_hypotheses_per_surface",
                ],
                3,
            )?,
            max_cwe_classes: positive_usize(input, &["maxCweClasses", "max_cwe_classes"], 6)?,
            artifact_dir: optional_nonempty_string(input, "artifactDir")?
                .or(optional_nonempty_string(input, "artifact_dir")?)
                .unwrap_or_else(|| ".kuzushi/systems-hunt".to_string()),
            model: optional_nonempty_string(input, "model")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsContextOutput {
    pub surfaces: Vec<RankedSystemsSurface>,
    pub surface_packs: Vec<SystemsSurfacePack>,
    pub metadata: SystemsContextMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsContextMetadata {
    pub codeql_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codeql_db_path: Option<String>,
    pub bash_probing_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RankedSystemsSurface {
    pub id: String,
    pub file_path: String,
    pub start_line: u32,
    pub display_name: String,
    pub kind: String,
    pub score: i64,
    pub domains: Vec<String>,
    pub reasons: Vec<String>,
    pub attacker_controlled_fields: Vec<String>,
    pub hardening_signals: Vec<String>,
    pub evidence: Vec<SystemsSurfaceSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsSurfaceSignal {
    pub domain: String,
    pub line_number: u32,
    pub line_content: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsSurfacePack {
    pub surface_id: String,
    pub anchor_file_path: String,
    pub anchor_start_line: u32,
    pub related_files: Vec<String>,
    pub unsafe_sites: Vec<SystemsCodeLocation>,
    pub resource_provenance_sites: Vec<SystemsCodeLocation>,
    pub hardening_sites: Vec<SystemsCodeLocation>,
    pub input_sites: Vec<SystemsCodeLocation>,
    pub helper_templates: Vec<SystemsHelperTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsCodeLocation {
    pub file_path: String,
    pub line: u32,
    pub snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsHelperTemplate {
    pub id: String,
    pub title: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsInvariant {
    pub id: String,
    pub surface_id: String,
    pub kind: String,
    pub summary: String,
    pub statement: String,
    pub rationale: String,
    pub evidence: Vec<String>,
    pub attacker_controlled_fields: Vec<String>,
    pub cheap_verifiable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsInvariantOutput {
    pub invariants: Vec<SystemsInvariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsTriggerHypothesis {
    pub id: String,
    pub surface_id: String,
    pub ordered_steps: Vec<String>,
    pub boundary_assignments: BTreeMap<String, String>,
    pub state_preconditions: Vec<String>,
    pub attacker_controlled_fields: Vec<String>,
    pub expected_primitive: String,
    pub cheap_verifiable: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsTriggerOutput {
    pub triggers: Vec<SystemsTriggerHypothesis>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsHuntReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<SystemsHuntPersistedRun>,
    pub artifacts: Vec<String>,
    pub cost_usd: f64,
}

impl SystemsHuntReport {
    pub fn output(&self) -> String {
        let mut lines = vec![format!(
            "systems-hunt: {} finding{} under {}",
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
        for finding in self.findings.iter().take(10) {
            lines.push(format!(
                "  - {} - {} - {}:{}",
                finding.severity.as_str(),
                finding.rule_id,
                finding.file_path,
                finding.start_line
            ));
        }
        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
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
pub struct SystemsHuntPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeepSemanticCweSelection {
    pub id: String,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeepSemanticCweOutput {
    pub cwes: Vec<DeepSemanticCweSelection>,
}

pub fn execute_systems_hunt_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "systems-hunt:systems-context-gatherer" => {
            let target = resolve_target(&input, ctx)?;
            let options = SystemsHuntInput::from_tool_input(&input)?;
            let output = gather_systems_context(&target, &options)?;
            Ok(json!({
                "ok": true,
                "output": format!("systems-hunt context: {} surface(s)", output.surfaces.len()),
                "data": output,
                "costUsd": 0.0,
            }))
        }
        "systems-hunt:systems-invariant-extract" => {
            let output = run_systems_invariant_extract(&input, ctx, runtime)?;
            Ok(json!({
                "ok": true,
                "output": format!("systems-hunt invariants: {}", output.invariants.len()),
                "data": output,
                "costUsd": 0.0,
            }))
        }
        "systems-hunt:systems-trigger-synth" => {
            let output = run_systems_trigger_synth(&input, ctx, runtime)?;
            Ok(json!({
                "ok": true,
                "output": format!("systems-hunt triggers: {}", output.triggers.len()),
                "data": output,
                "costUsd": 0.0,
            }))
        }
        "systems-hunt:systems-hunt" => {
            Ok(run_systems_hunt_report(&input, ctx, runtime)?.to_tool_json())
        }
        "systems-hunt:deep-semantic-cwe-select" => {
            let output = run_deep_semantic_cwe_select(&input, ctx, runtime)?;
            Ok(json!({
                "ok": true,
                "output": format!("deep-semantic cwes: {}", output.cwes.len()),
                "data": output,
                "costUsd": 0.0,
            }))
        }
        "systems-hunt:deep-semantic-hunt" => {
            Ok(run_deep_semantic_hunt_report(&input, ctx, runtime)?.to_tool_json())
        }
        other => anyhow::bail!("unknown systems-hunt tool {other:?}"),
    }
}

pub fn run_systems_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsHuntReport> {
    let target = resolve_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "systems-hunt: target is not a directory: {}",
            target.display()
        );
    }
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = gather_systems_context(&target, &options)?;
    if context.surfaces.is_empty() {
        return Ok(SystemsHuntReport {
            target: target.display().to_string(),
            count: 0,
            findings: Vec::new(),
            persisted: persist_systems_findings(&target, &[], ctx)?,
            artifacts: Vec::new(),
            cost_usd: 0.0,
        });
    }

    let runtime = runtime.context(
        "systems-hunt requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model("systems-hunt", input, ctx, &options)?;
    let agent_tool_policy = agent_tool_policy_for_input(input)?;
    let invariants = query_systems_invariants(
        runtime,
        &model,
        &target,
        &context,
        &options,
        agent_tool_policy.clone(),
    )?;
    let triggers = query_systems_triggers(
        runtime,
        &model,
        &target,
        &context,
        &invariants,
        &options,
        agent_tool_policy.clone(),
    )?;
    let response = runtime.query_blocking(
        AgentQueryRequest::new(
            model,
            target.clone(),
            SYSTEMS_HUNT_SYSTEM_PROMPT.to_string(),
            build_systems_hunt_prompt(&target, &context, &invariants, &triggers, &options)?,
        )
        .with_tool_policy(agent_tool_policy),
    )?;
    let raw = parse_agent_json(response)
        .context("systems-hunt expected pi-agent-core to return JSON with a findings array")?;
    let artifact_root = artifact_root(&target, &options.artifact_dir)?;
    let (findings, artifacts) = normalize_systems_hunt_findings(
        raw,
        &target,
        &context,
        &artifact_root,
        options.max_findings,
    )?;
    let persisted = persist_systems_findings(&target, &findings, ctx)?;

    Ok(SystemsHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        artifacts,
        cost_usd: 0.0,
    })
}

fn run_systems_invariant_extract(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsInvariantOutput> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = context_from_input(input).transpose()?.unwrap_or_else(|| {
        gather_systems_context(&target, &options).unwrap_or_else(|_| empty_context())
    });
    if context.surfaces.is_empty() {
        return Ok(SystemsInvariantOutput {
            invariants: Vec::new(),
        });
    }
    let runtime = runtime.context(
        "systems-hunt:systems-invariant-extract requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model(
        "systems-hunt:systems-invariant-extract",
        input,
        ctx,
        &options,
    )?;
    query_systems_invariants(
        runtime,
        &model,
        &target,
        &context,
        &options,
        agent_tool_policy_for_input(input)?,
    )
}

fn run_systems_trigger_synth(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsTriggerOutput> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = context_from_input(input).transpose()?.unwrap_or_else(|| {
        gather_systems_context(&target, &options).unwrap_or_else(|_| empty_context())
    });
    if context.surfaces.is_empty() {
        return Ok(SystemsTriggerOutput {
            triggers: Vec::new(),
        });
    }
    let runtime = runtime.context(
        "systems-hunt:systems-trigger-synth requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model("systems-hunt:systems-trigger-synth", input, ctx, &options)?;
    let agent_tool_policy = agent_tool_policy_for_input(input)?;
    let invariant_output = match invariants_from_input(input).transpose()? {
        Some(output) => output,
        None => query_systems_invariants(
            runtime,
            &model,
            &target,
            &context,
            &options,
            agent_tool_policy.clone(),
        )?,
    };
    query_systems_triggers(
        runtime,
        &model,
        &target,
        &context,
        &invariant_output,
        &options,
        agent_tool_policy,
    )
}

fn run_deep_semantic_cwe_select(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<DeepSemanticCweOutput> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let runtime = runtime.context(
        "systems-hunt:deep-semantic-cwe-select requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model(
        "systems-hunt:deep-semantic-cwe-select",
        input,
        ctx,
        &options,
    )?;
    let inventory = collect_inventory(&target, 80, 2048)?;
    let response = runtime.query_blocking(
        AgentQueryRequest::new(
            model,
            target.clone(),
            DEEP_SEMANTIC_CWE_SYSTEM_PROMPT.to_string(),
            format!(
            "Select relevant native-code CWE classes for this repository. Return JSON with cwes[].\n\n{}",
            format_inventory(&inventory)
        ),
        )
        .with_tool_policy(agent_tool_policy_for_input(input)?),
    )?;
    let raw = parse_agent_json(response)
        .context("systems-hunt:deep-semantic-cwe-select expected JSON with a cwes array")?;
    Ok(DeepSemanticCweOutput {
        cwes: parse_cwe_selections(&raw)
            .into_iter()
            .take(options.max_cwe_classes)
            .collect(),
    })
}

fn run_deep_semantic_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsHuntReport> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let runtime = runtime.context(
        "systems-hunt:deep-semantic-hunt requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model("systems-hunt:deep-semantic-hunt", input, ctx, &options)?;
    let cwes = cwes_from_input(input)
        .unwrap_or_else(|| {
            run_deep_semantic_cwe_select(input, ctx, Some(runtime))
                .map(|output| output.cwes)
                .unwrap_or_default()
        })
        .into_iter()
        .take(options.max_cwe_classes)
        .collect::<Vec<_>>();

    if cwes.is_empty() {
        return Ok(SystemsHuntReport {
            target: target.display().to_string(),
            count: 0,
            findings: Vec::new(),
            persisted: persist_systems_findings(&target, &[], ctx)?,
            artifacts: Vec::new(),
            cost_usd: 0.0,
        });
    }

    let inventory = collect_inventory(&target, 80, 2048)?;
    let response = runtime.query_blocking(
        AgentQueryRequest::new(
            model,
            target.clone(),
            DEEP_SEMANTIC_HUNT_SYSTEM_PROMPT.to_string(),
            format!(
            "Find verified variants of these native-code CWE classes. Return JSON with findings[].\n\nCWEs:\n{}\n\n{}",
            cwes.iter()
                .map(|cwe| format!("- {} {}: {}", cwe.id, cwe.name, cwe.reason))
                .collect::<Vec<_>>()
                .join("\n"),
            format_inventory(&inventory)
        ),
        )
        .with_tool_policy(agent_tool_policy_for_input(input)?),
    )?;
    let raw = parse_agent_json(response)
        .context("systems-hunt:deep-semantic-hunt expected JSON with a findings array")?;
    let artifact_root = artifact_root(&target, &options.artifact_dir)?;
    let (findings, artifacts) =
        normalize_deep_semantic_findings(raw, &target, &artifact_root, options.max_findings)?;
    let persisted = persist_systems_findings(&target, &findings, ctx)?;

    Ok(SystemsHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        artifacts,
        cost_usd: 0.0,
    })
}

fn gather_systems_context(
    target: &Path,
    options: &SystemsHuntInput,
) -> Result<SystemsContextOutput> {
    let inventory = collect_inventory(target, 200, 4096)?;
    let mut by_file: BTreeMap<String, SurfaceAccumulator> = BTreeMap::new();

    for (file_path, body) in &inventory {
        for (idx, line) in body.lines().enumerate() {
            let line_number = (idx + 1) as u32;
            let signals = classify_line(line);
            if signals.is_empty() {
                continue;
            }
            let key = file_path.clone();
            let accumulator = by_file.entry(key.clone()).or_insert_with(|| {
                SurfaceAccumulator::new(file_path.clone(), infer_kind(file_path, line), line_number)
            });
            accumulator.start_line = accumulator.start_line.min(line_number);
            for (domain, reason, weight) in signals {
                accumulator.score += weight;
                accumulator.domains.insert(domain.to_string());
                accumulator.reasons.insert(reason.to_string());
                accumulator.evidence.push(SystemsSurfaceSignal {
                    domain: domain.to_string(),
                    line_number,
                    line_content: trim_line(line),
                    reason: reason.to_string(),
                });
            }
            for field in attacker_fields(line) {
                accumulator.attacker_controlled_fields.insert(field);
            }
            for hardening in hardening_signals(line) {
                accumulator.hardening_signals.insert(hardening);
            }
        }
    }

    let mut surfaces = by_file
        .into_values()
        .map(SurfaceAccumulator::finish)
        .collect::<Vec<_>>();
    surfaces.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.start_line.cmp(&right.start_line))
    });
    surfaces.truncate(options.max_surfaces);

    let surface_packs = surfaces
        .iter()
        .map(|surface| build_surface_pack(target, surface))
        .collect::<Result<Vec<_>>>()?;
    let codeql_db_path = resolve_codeql_db_path(target);
    Ok(SystemsContextOutput {
        surfaces,
        surface_packs,
        metadata: SystemsContextMetadata {
            codeql_available: codeql_db_path.is_some(),
            codeql_db_path: codeql_db_path.map(|path| path.display().to_string()),
            bash_probing_used: false,
        },
    })
}

fn query_systems_invariants(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    _options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
) -> Result<SystemsInvariantOutput> {
    let response = runtime.query_blocking(
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            SYSTEMS_INVARIANT_SYSTEM_PROMPT.to_string(),
            format!(
            "Extract safety invariants for these low-level surfaces. Return JSON with invariants[].\n\n{}",
            serde_json::to_string_pretty(context)?
        ),
        )
        .with_tool_policy(agent_tool_policy),
    )?;
    let raw = parse_agent_json(response)
        .context("systems-hunt:systems-invariant-extract expected JSON with an invariants array")?;
    Ok(SystemsInvariantOutput {
        invariants: parse_invariants(&raw),
    })
}

fn query_systems_triggers(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    invariants: &SystemsInvariantOutput,
    options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
) -> Result<SystemsTriggerOutput> {
    let response = runtime.query_blocking(
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            SYSTEMS_TRIGGER_SYSTEM_PROMPT.to_string(),
            format!(
            "Synthesize at most {} attacker trigger hypotheses per surface. Return JSON with triggers[].\n\nContext:\n{}\n\nInvariants:\n{}",
            options.max_trigger_hypotheses_per_surface,
            serde_json::to_string_pretty(context)?,
            serde_json::to_string_pretty(invariants)?,
        ),
        )
        .with_tool_policy(agent_tool_policy),
    )?;
    let raw = parse_agent_json(response)
        .context("systems-hunt:systems-trigger-synth expected JSON with a triggers array")?;
    Ok(SystemsTriggerOutput {
        triggers: parse_triggers(&raw),
    })
}

fn build_systems_hunt_prompt(
    target: &Path,
    context: &SystemsContextOutput,
    invariants: &SystemsInvariantOutput,
    triggers: &SystemsTriggerOutput,
    options: &SystemsHuntInput,
) -> Result<String> {
    let inventory = collect_inventory(target, 80, 2048)?;
    Ok(format!(
        "Hunt for concrete memory-safety, integer-boundary, parser-state, resource-provenance, or hardening-bypass vulnerabilities. Return JSON with findings[]. Limit to {} findings.\n\nContext:\n{}\n\nInvariants:\n{}\n\nTriggers:\n{}\n\nRepository snippets:\n{}",
        options.max_findings,
        serde_json::to_string_pretty(context)?,
        serde_json::to_string_pretty(invariants)?,
        serde_json::to_string_pretty(triggers)?,
        format_inventory(&inventory)
    ))
}

fn normalize_systems_hunt_findings(
    raw: Value,
    target: &Path,
    context: &SystemsContextOutput,
    artifact_root: &Path,
    max_findings: usize,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut artifacts = Vec::new();
    let Some(items) = raw.get("findings").and_then(Value::as_array) else {
        return Ok((findings, artifacts));
    };

    for item in items.iter().take(max_findings) {
        let Some(object) = item.as_object() else {
            continue;
        };
        let title = string_field(object.get("title"));
        let file_path = normalize_relative_path(string_field(object.get("filePath")));
        let message = string_field(object.get("message"));
        if title.is_empty() || file_path.is_empty() || message.is_empty() {
            continue;
        }
        let start_line = object
            .get("startLine")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1) as u32;
        let severity = parse_severity(string_field(object.get("severity")));
        let cwe = string_or_first_array(object.get("cwe")).unwrap_or_else(|| "unknown".to_string());
        let rule_id = object
            .get("ruleId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("systems-hunt/{}", sanitize_rule_segment(&cwe)));
        let mut finding = Finding::new_tool(
            "systems-hunt",
            rule_id,
            file_path.clone(),
            start_line,
            None,
            severity,
            format!(
                "{title}: {message}\n\nReasoning: {}\nTrigger: {}\nSystems hunt artifact: pending",
                string_field(object.get("reasoning")),
                string_array(object.get("triggerSequence")).join(" -> ")
            ),
        );
        finding.title = title;

        let surface = context
            .surfaces
            .iter()
            .find(|surface| surface.file_path == file_path)
            .or_else(|| context.surfaces.first());
        let artifact = json!({
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "cwe": string_array(object.get("cwe")),
            "severity": severity.as_str(),
            "filePath": file_path,
            "startLine": start_line,
            "surfaceId": surface.map(|surface| surface.id.clone()).unwrap_or_default(),
            "surfaceKind": surface.map(|surface| surface.kind.clone()).unwrap_or_else(|| "unknown".to_string()),
            "lenses": string_array(object.get("lenses")),
            "violatedInvariantIds": string_array(object.get("violatedInvariantIds")),
            "violatedInvariant": string_field(object.get("violatedInvariant")),
            "triggerHypothesisIds": string_array(object.get("triggerHypothesisIds")),
            "triggerSequence": string_array(object.get("triggerSequence")),
            "stateMachine": string_array(object.get("stateMachine")),
            "boundaryAssignments": object.get("boundaryAssignments").cloned().unwrap_or_else(|| json!({})),
            "attackerControlledFields": string_array(object.get("attackerControlledFields")),
            "memoryPrimitive": string_field(object.get("memoryPrimitive")),
            "hardeningNotes": string_array(object.get("hardeningNotes")),
            "cheapVerifiable": object.get("cheapVerifiable").and_then(Value::as_bool).unwrap_or(false),
            "reasoning": string_field(object.get("reasoning")),
            "analysisPath": object.get("analysisPath").cloned().unwrap_or_else(|| json!([])),
            "guardLocations": object.get("guardLocations").cloned().unwrap_or_else(|| json!([])),
            "counterexampleNotes": string_array(object.get("counterexampleNotes")),
            "relatedFiles": surface.map(|surface| vec![surface.file_path.clone()]).unwrap_or_default(),
            "corroborationStatus": string_field(object.get("corroborationStatus")),
        });
        let artifact_path = write_artifact(artifact_root, &finding.fingerprint, &artifact)?;
        let relative_artifact = path_relative_to(target, &artifact_path);
        finding.message = finding.message.replace(
            "Systems hunt artifact: pending",
            &format!("Systems hunt artifact: {relative_artifact}"),
        );
        artifacts.push(relative_artifact);
        findings.push(finding);
    }
    Ok((findings, artifacts))
}

fn normalize_deep_semantic_findings(
    raw: Value,
    target: &Path,
    artifact_root: &Path,
    max_findings: usize,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut artifacts = Vec::new();
    let Some(items) = raw.get("findings").and_then(Value::as_array) else {
        return Ok((findings, artifacts));
    };
    for item in items.iter().take(max_findings) {
        let Some(object) = item.as_object() else {
            continue;
        };
        let title = string_field(object.get("title"));
        let file_path = normalize_relative_path(string_field(object.get("filePath")));
        let message = string_field(object.get("message"));
        if title.is_empty() || file_path.is_empty() || message.is_empty() {
            continue;
        }
        let start_line = object
            .get("startLine")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1) as u32;
        let cwe = string_or_first_array(object.get("cwe")).unwrap_or_else(|| "unknown".to_string());
        let mut finding = Finding::new_tool(
            "deep-semantic-hunt",
            format!("deep-semantic/{}", sanitize_rule_segment(&cwe)),
            file_path.clone(),
            start_line,
            None,
            parse_severity(string_field(object.get("severity"))),
            format!(
                "[{cwe}] {title}: {message}\n\nReasoning: {}\nSystems hunt artifact: pending",
                string_field(object.get("reasoningChain"))
            ),
        );
        finding.title = title;
        let artifact = json!({
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "cwe": [cwe],
            "severity": finding.severity.as_str(),
            "filePath": file_path,
            "startLine": start_line,
            "reasoning": string_field(object.get("reasoningChain")),
            "analysisPath": object.get("analysisPath").cloned().unwrap_or_else(|| json!([])),
            "corroborationStatus": "deep-semantic",
        });
        let artifact_path = write_artifact(artifact_root, &finding.fingerprint, &artifact)?;
        let relative_artifact = path_relative_to(target, &artifact_path);
        finding.message = finding.message.replace(
            "Systems hunt artifact: pending",
            &format!("Systems hunt artifact: {relative_artifact}"),
        );
        artifacts.push(relative_artifact);
        findings.push(finding);
    }
    Ok((findings, artifacts))
}

fn persist_systems_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<SystemsHuntPersistedRun>> {
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

    Ok(Some(SystemsHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

fn build_surface_pack(target: &Path, surface: &RankedSystemsSurface) -> Result<SystemsSurfacePack> {
    let body = fs::read_to_string(target.join(&surface.file_path)).unwrap_or_default();
    let mut unsafe_sites = Vec::new();
    let mut resource_provenance_sites = Vec::new();
    let mut hardening_sites = Vec::new();
    let mut input_sites = Vec::new();

    for (idx, line) in body.lines().enumerate() {
        let line_number = (idx + 1) as u32;
        let location = SystemsCodeLocation {
            file_path: surface.file_path.clone(),
            line: line_number,
            snippet: trim_line(line),
            reason: None,
        };
        let lower = line.to_ascii_lowercase();
        if lower.contains("unsafe")
            || lower.contains("memcpy")
            || lower.contains("copy_from")
            || lower.contains("*mut")
            || lower.contains("*const")
        {
            unsafe_sites.push(SystemsCodeLocation {
                reason: Some("unsafe memory operation".to_string()),
                ..location.clone()
            });
        }
        if lower.contains("shared")
            || lower.contains("splice")
            || lower.contains("pipe")
            || lower.contains("iov")
            || lower.contains("scatter")
        {
            resource_provenance_sites.push(SystemsCodeLocation {
                reason: Some("resource provenance or aliasing signal".to_string()),
                ..location.clone()
            });
        }
        if lower.contains("check")
            || lower.contains("validate")
            || lower.contains("guard")
            || lower.contains("assert")
        {
            hardening_sites.push(SystemsCodeLocation {
                reason: Some("hardening or guard signal".to_string()),
                ..location.clone()
            });
        }
        if lower.contains("recv")
            || lower.contains("read")
            || lower.contains("packet")
            || lower.contains("request")
        {
            input_sites.push(SystemsCodeLocation {
                reason: Some("attacker input boundary signal".to_string()),
                ..location
            });
        }
    }

    Ok(SystemsSurfacePack {
        surface_id: surface.id.clone(),
        anchor_file_path: surface.file_path.clone(),
        anchor_start_line: surface.start_line,
        related_files: vec![surface.file_path.clone()],
        unsafe_sites: unsafe_sites.into_iter().take(12).collect(),
        resource_provenance_sites: resource_provenance_sites.into_iter().take(12).collect(),
        hardening_sites: hardening_sites.into_iter().take(12).collect(),
        input_sites: input_sites.into_iter().take(12).collect(),
        helper_templates: helper_templates_for(surface),
    })
}

fn helper_templates_for(surface: &RankedSystemsSurface) -> Vec<SystemsHelperTemplate> {
    let mut templates = Vec::new();
    if surface
        .domains
        .iter()
        .any(|domain| domain == "integer-boundary")
    {
        templates.push(SystemsHelperTemplate {
            id: "signed-wraparound".to_string(),
            title: "Signed or narrow counter wraparound".to_string(),
            rationale: "Check whether arithmetic reaches allocation, copy, or sentinel decisions."
                .to_string(),
        });
    }
    if surface
        .domains
        .iter()
        .any(|domain| domain == "resource-provenance")
    {
        templates.push(SystemsHelperTemplate {
            id: "shared-backing-resource".to_string(),
            title: "Shared backing resource provenance".to_string(),
            rationale: "Track whether shared backing storage crosses a writable alias boundary."
                .to_string(),
        });
    }
    if surface
        .domains
        .iter()
        .any(|domain| domain == "unsafe-memory")
    {
        templates.push(SystemsHelperTemplate {
            id: "stack-length-copy".to_string(),
            title: "Length-controlled memory copy".to_string(),
            rationale: "Check whether attacker-controlled length dominates destination capacity."
                .to_string(),
        });
    }
    templates
}

fn collect_inventory(
    root: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    collect_inventory_inner(root, root, max_files, max_bytes_per_file, &mut files)?;
    Ok(files)
}

fn collect_inventory_inner(
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
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            collect_inventory_inner(root, &path, max_files, max_bytes_per_file, files)?;
            continue;
        }
        if !is_systems_source(&path) {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let content =
            String::from_utf8_lossy(&bytes[..bytes.len().min(max_bytes_per_file)]).to_string();
        let rel = path_relative_to(root, &path);
        files.push((rel, content));
    }
    Ok(())
}

fn is_systems_source(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| SYSTEMS_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn classify_line(line: &str) -> Vec<(&'static str, &'static str, i64)> {
    let lower = line.to_ascii_lowercase();
    let mut signals = Vec::new();
    if contains_any(
        &lower,
        &[
            "packet", "parser", "parse", "decode", "frame", "segment", "recv", "rpc", "xdr",
            "header",
        ],
    ) {
        signals.push((
            "protocol-parser",
            "protocol parser or input framing signal",
            7,
        ));
    }
    if contains_any(
        &lower,
        &[
            "uint16", "u16", "usize", "size_t", "len", "length", "offset", "wrap", "overflow",
            "sentinel",
        ],
    ) {
        signals.push(("integer-boundary", "integer boundary or sentinel signal", 5));
    }
    if contains_any(
        &lower,
        &[
            "unsafe",
            "memcpy",
            "memmove",
            "strcpy",
            "copy_from",
            "from_raw_parts",
            "*mut",
            "*const",
        ],
    ) {
        signals.push(("unsafe-memory", "unsafe memory operation signal", 6));
    }
    if contains_any(
        &lower,
        &[
            "shared",
            "splice",
            "pipe_buffer",
            "iov_iter",
            "scatterlist",
            "page",
            "alias",
        ],
    ) {
        signals.push((
            "resource-provenance",
            "shared resource provenance signal",
            8,
        ));
    }
    if contains_any(
        &lower,
        &[
            "checked_",
            "saturating_",
            "validate",
            "guard",
            "assert",
            "bounds",
        ],
    ) {
        signals.push(("hardening", "hardening or guard signal", 2));
    }
    signals
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn infer_kind(file_path: &str, line: &str) -> String {
    let raw = format!("{file_path}\n{line}").to_ascii_lowercase();
    if contains_any(&raw, &["rpc", "xdr", "nfs"]) {
        "rpc-handler".to_string()
    } else if contains_any(&raw, &["codec", "decode", "frame", "h264", "parser"]) {
        "codec-parser".to_string()
    } else if contains_any(&raw, &["hypervisor", "guest", "virt", "vmexit"]) {
        "hypervisor-boundary".to_string()
    } else if contains_any(
        &raw,
        &["shared", "splice", "pipe", "iov_iter", "scatterlist"],
    ) {
        "resource-provenance".to_string()
    } else if contains_any(&raw, &["unsafe", "memcpy", "*mut", "*const"]) {
        "unsafe-region".to_string()
    } else {
        "protocol-parser".to_string()
    }
}

fn attacker_fields(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let mut out = Vec::new();
    for candidate in [
        "len", "length", "size", "offset", "packet", "frame", "count",
    ] {
        if lower.contains(candidate) {
            out.push(candidate.to_string());
        }
    }
    out
}

fn hardening_signals(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let mut out = Vec::new();
    for candidate in [
        "checked_",
        "saturating_",
        "validate",
        "guard",
        "assert",
        "bounds",
    ] {
        if lower.contains(candidate) {
            out.push(trim_line(line));
        }
    }
    out
}

#[derive(Debug, Clone)]
struct SurfaceAccumulator {
    file_path: String,
    start_line: u32,
    kind: String,
    score: i64,
    domains: BTreeSet<String>,
    reasons: BTreeSet<String>,
    attacker_controlled_fields: BTreeSet<String>,
    hardening_signals: BTreeSet<String>,
    evidence: Vec<SystemsSurfaceSignal>,
}

impl SurfaceAccumulator {
    fn new(file_path: String, kind: String, start_line: u32) -> Self {
        Self {
            file_path,
            start_line,
            kind,
            score: 0,
            domains: BTreeSet::new(),
            reasons: BTreeSet::new(),
            attacker_controlled_fields: BTreeSet::new(),
            hardening_signals: BTreeSet::new(),
            evidence: Vec::new(),
        }
    }

    fn finish(self) -> RankedSystemsSurface {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (&self.kind, &self.file_path).hash(&mut hasher);
        let id = format!("surface-{:016x}", hasher.finish());
        RankedSystemsSurface {
            id,
            file_path: self.file_path.clone(),
            start_line: self.start_line,
            display_name: Path::new(&self.file_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(&self.file_path)
                .to_string(),
            kind: self.kind,
            score: self.score,
            domains: self.domains.into_iter().collect(),
            reasons: self.reasons.into_iter().collect(),
            attacker_controlled_fields: self.attacker_controlled_fields.into_iter().collect(),
            hardening_signals: self.hardening_signals.into_iter().collect(),
            evidence: self.evidence.into_iter().take(12).collect(),
        }
    }
}

fn parse_invariants(raw: &Value) -> Vec<SystemsInvariant> {
    let Some(items) = raw.get("invariants").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let object = item.as_object()?;
            let id = string_field(object.get("id"));
            let surface_id = string_field(object.get("surfaceId"));
            let summary = string_field(object.get("summary"));
            let statement = string_field(object.get("statement"));
            let rationale = string_field(object.get("rationale"));
            if id.is_empty()
                || surface_id.is_empty()
                || summary.is_empty()
                || statement.is_empty()
                || rationale.is_empty()
            {
                return None;
            }
            Some(SystemsInvariant {
                id,
                surface_id,
                kind: string_field(object.get("kind")),
                summary,
                statement,
                rationale,
                evidence: string_array(object.get("evidence")),
                attacker_controlled_fields: string_array(object.get("attackerControlledFields")),
                cheap_verifiable: object
                    .get("cheapVerifiable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

fn parse_triggers(raw: &Value) -> Vec<SystemsTriggerHypothesis> {
    let Some(items) = raw.get("triggers").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let object = item.as_object()?;
            let id = string_field(object.get("id"));
            let surface_id = string_field(object.get("surfaceId"));
            let ordered_steps = string_array(object.get("orderedSteps"));
            let expected_primitive = string_field(object.get("expectedPrimitive"));
            let rationale = string_field(object.get("rationale"));
            if id.is_empty()
                || surface_id.is_empty()
                || ordered_steps.is_empty()
                || expected_primitive.is_empty()
                || rationale.is_empty()
            {
                return None;
            }
            Some(SystemsTriggerHypothesis {
                id,
                surface_id,
                ordered_steps,
                boundary_assignments: string_record(object.get("boundaryAssignments")),
                state_preconditions: string_array(object.get("statePreconditions")),
                attacker_controlled_fields: string_array(object.get("attackerControlledFields")),
                expected_primitive,
                cheap_verifiable: object
                    .get("cheapVerifiable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                rationale,
            })
        })
        .collect()
}

fn parse_cwe_selections(raw: &Value) -> Vec<DeepSemanticCweSelection> {
    let Some(items) = raw.get("cwes").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let object = item.as_object()?;
            let id = string_field(object.get("id"));
            let name = string_field(object.get("name"));
            if id.is_empty() || name.is_empty() {
                return None;
            }
            Some(DeepSemanticCweSelection {
                id,
                name,
                reason: string_field(object.get("reason")),
            })
        })
        .collect()
}

fn cwes_from_input(input: &Value) -> Option<Vec<DeepSemanticCweSelection>> {
    let cwes = input.get("cwes")?.as_array()?;
    Some(
        cwes.iter()
            .filter_map(|entry| {
                if let Some(value) = entry.as_str() {
                    let id = value.trim();
                    if id.is_empty() {
                        return None;
                    }
                    return Some(DeepSemanticCweSelection {
                        id: id.to_string(),
                        name: id.to_string(),
                        reason: "provided by operator input".to_string(),
                    });
                }
                let object = entry.as_object()?;
                let id = string_field(object.get("id"));
                let name = string_field(object.get("name"));
                if id.is_empty() {
                    return None;
                }
                Some(DeepSemanticCweSelection {
                    id,
                    name: if name.is_empty() {
                        "custom".to_string()
                    } else {
                        name
                    },
                    reason: string_field(object.get("reason")),
                })
            })
            .collect(),
    )
}

fn context_from_input(input: &Value) -> Option<Result<SystemsContextOutput>> {
    let value = input
        .get("systemsContext")
        .or_else(|| input.get("systems_context"))
        .or_else(|| input.get("context"))?;
    Some(serde_json::from_value(value.clone()).context("invalid systems context input"))
}

fn invariants_from_input(input: &Value) -> Option<Result<SystemsInvariantOutput>> {
    let value = input
        .get("invariants")
        .or_else(|| input.get("systemsInvariants"))
        .or_else(|| input.get("systems_invariants"))?;
    if value.get("invariants").is_some() {
        Some(serde_json::from_value(value.clone()).context("invalid systems invariants input"))
    } else {
        Some(
            serde_json::from_value(json!({ "invariants": value.clone() }))
                .context("invalid systems invariants input"),
        )
    }
}

fn parse_agent_json(response: AgentQueryResponse) -> Result<Value> {
    if let Some(value) = response.structured {
        return Ok(value);
    }
    parse_json_object_from_text(&response.text)
}

fn parse_json_object_from_text(text: &str) -> Result<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return Ok(value);
    }
    let start = text
        .find('{')
        .context("agent response did not contain JSON")?;
    let end = text
        .rfind('}')
        .context("agent response did not contain JSON")?;
    serde_json::from_str(&text[start..=end]).context("agent response JSON was invalid")
}

fn resolve_model(
    label: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    options: &SystemsHuntInput,
) -> Result<String> {
    options
        .model
        .clone()
        .or_else(|| optional_nonempty_string(input, "MODEL").ok().flatten())
        .or_else(|| ctx.config.model.clone())
        .with_context(|| {
            format!("{label} requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model")
        })
}

fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
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

fn positive_usize(input: &Value, keys: &[&str], default: usize) -> Result<usize> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            let Some(number) = value.as_u64() else {
                anyhow::bail!("systems-hunt {key} must be a positive integer");
            };
            if number == 0 {
                anyhow::bail!("systems-hunt {key} must be a positive integer");
            }
            return Ok(number as usize);
        }
    }
    Ok(default)
}

fn optional_nonempty_string(input: &Value, key: &str) -> Result<Option<String>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        anyhow::bail!("systems-hunt {key} must be a string");
    };
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

fn artifact_root(target: &Path, raw: &str) -> Result<PathBuf> {
    let normalized = raw
        .trim()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string();
    let relative = if normalized.is_empty() {
        ".kuzushi/systems-hunt"
    } else {
        normalized.as_str()
    };
    let path = Path::new(relative);
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        anyhow::bail!("systems-hunt artifactDir must stay inside the repository root: {relative}");
    }
    Ok(target.join(path))
}

fn write_artifact(root: &Path, fingerprint: &str, artifact: &Value) -> Result<PathBuf> {
    fs::create_dir_all(root).with_context(|| format!("Could not create {}", root.display()))?;
    let path = root.join(format!("{fingerprint}.json"));
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(artifact)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn resolve_codeql_db_path(target: &Path) -> Option<PathBuf> {
    [target.join(".kuzushi/codeql-db"), target.join(".codeql/db")]
        .into_iter()
        .find(|path| path.exists())
}

fn path_relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

fn normalize_relative_path(value: String) -> String {
    let path = Path::new(value.trim());
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str().map(ToString::to_string),
            Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn format_inventory(inventory: &[(String, String)]) -> String {
    inventory
        .iter()
        .map(|(path, body)| format!("## {path}\n```text\n{}\n```", body.trim()))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn parse_severity(value: String) -> Severity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "error" | "high" => Severity::High,
        "warning" | "medium" => Severity::Medium,
        "info" | "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn string_field(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(Value::String(value)) if !value.trim().is_empty() => vec![value.trim().to_string()],
        _ => Vec::new(),
    }
}

fn string_record(value: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match value {
        Some(Value::Object(object)) => {
            for (key, value) in object {
                if let Some(value) = value
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    out.insert(key.clone(), value.to_string());
                }
            }
        }
        Some(Value::Array(items)) => {
            for item in items {
                let Some(object) = item.as_object() else {
                    continue;
                };
                let key = string_field(object.get("field"));
                let value = string_field(object.get("value"));
                if !key.is_empty() && !value.is_empty() {
                    out.insert(key, value);
                }
            }
        }
        _ => {}
    }
    out
}

fn string_or_first_array(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => {
            Some(value.trim().to_string()).filter(|value| !value.is_empty())
        }
        Some(Value::Array(items)) => items
            .iter()
            .find_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        _ => None,
    }
}

fn sanitize_rule_segment(value: &str) -> String {
    let mut out = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out.trim_matches('-').to_string()
}

fn trim_line(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.len() <= 240 {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..240])
    }
}

fn empty_context() -> SystemsContextOutput {
    SystemsContextOutput {
        surfaces: Vec::new(),
        surface_packs: Vec::new(),
        metadata: SystemsContextMetadata {
            codeql_available: false,
            codeql_db_path: None,
            bash_probing_used: false,
        },
    }
}

#[allow(dead_code)]
fn now_isoish() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{seconds}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::FindingStore;
    use crate::runtime::TriageRequest;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct FakeRuntime {
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    impl FakeRuntime {
        fn new() -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for FakeRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let system_prompt = request.system_prompt.clone();
            self.queries.lock().unwrap().push(request);
            if system_prompt == SYSTEMS_INVARIANT_SYSTEM_PROMPT {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "invariants": [{
                            "id": "inv-1",
                            "surfaceId": "surface",
                            "kind": "length-buffer-coupling",
                            "summary": "length must fit the stack buffer",
                            "statement": "packet length is checked before copy",
                            "rationale": "copy uses attacker length",
                            "evidence": ["memcpy"],
                            "attackerControlledFields": ["len"],
                            "cheapVerifiable": true
                        }]
                    })),
                });
            }
            if system_prompt == SYSTEMS_TRIGGER_SYSTEM_PROMPT {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "triggers": [{
                            "id": "trig-1",
                            "surfaceId": "surface",
                            "orderedSteps": ["send oversized packet"],
                            "boundaryAssignments": {"len": "4096"},
                            "statePreconditions": ["connected"],
                            "attackerControlledFields": ["len"],
                            "expectedPrimitive": "stack overwrite",
                            "cheapVerifiable": true,
                            "rationale": "length reaches memcpy"
                        }]
                    })),
                });
            }
            if system_prompt == SYSTEMS_HUNT_SYSTEM_PROMPT {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "title": "Oversized packet length reaches fixed buffer",
                            "cwe": "CWE-787",
                            "severity": "ERROR",
                            "filePath": "src/parser.c",
                            "startLine": 3,
                            "message": "packet len is copied into a 64-byte stack buffer",
                            "reasoning": "len comes from packet header",
                            "triggerHypothesisIds": ["trig-1"],
                            "violatedInvariantIds": ["inv-1"],
                            "triggerSequence": ["send len=4096"],
                            "attackerControlledFields": ["len"],
                            "memoryPrimitive": "stack overwrite",
                            "cheapVerifiable": true
                        }]
                    })),
                });
            }
            anyhow::bail!("unexpected prompt {system_prompt}")
        }

        fn triage_finding_blocking(
            &self,
            _request: TriageRequest,
        ) -> Result<crate::findings::TriageOutcome> {
            unreachable!("systems-hunt tests do not triage")
        }
    }

    #[test]
    fn gathers_ranked_systems_surfaces() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();

        let output = gather_systems_context(
            temp.path(),
            &SystemsHuntInput::from_tool_input(&json!({})).unwrap(),
        )
        .unwrap();

        assert_eq!(output.surfaces.len(), 1);
        assert_eq!(output.surfaces[0].file_path, "src/parser.c");
        assert!(output.surfaces[0]
            .domains
            .iter()
            .any(|domain| domain == "unsafe-memory"));
    }

    #[test]
    fn runs_systems_hunt_through_runtime_and_writes_artifact() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let runtime = FakeRuntime::new();

        let report =
            run_systems_hunt_report(&json!({"maxFindings": 5}), &ctx, Some(&runtime)).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.findings[0].tool, "systems-hunt");
        assert_eq!(report.findings[0].rule_id, "systems-hunt/cwe-787");
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
        assert_eq!(report.artifacts.len(), 1);
        assert!(temp.path().join(&report.artifacts[0]).exists());
    }

    #[test]
    fn systems_hunt_requires_explicit_model_without_fallback() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, uint16_t len) { memcpy(packet, packet, len); }\n",
        )
        .unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };
        let runtime = FakeRuntime::new();

        let err = run_systems_hunt_report(&json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();

        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }
}
