use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::findings::{Finding, Severity, StaticProofState};
use crate::runtime::{AgentQueryRequest, AgentRuntime, AgentToolPolicy};
use crate::static_proof_validator::{
    static_proof_claim_from_whitebox_schema, validate_static_proof_claim, StaticProofValidation,
};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use crate::whitebox_static::{
    agent_tool_policy_for_input, mark_whitebox_static_findings, whitebox_static_profile_requested,
    whitebox_static_proof_state_from_input, whitebox_static_triage_prompt_block,
    whitebox_static_triage_system_prompt,
};

use super::generic_findings::normalize_reported_file_path;
use super::input::{optional_nonempty_string, string_list_input};
use super::json_fields::{read_object_string, read_object_u64};
use super::support::{resolve_tool_target, should_skip_path};
use super::ToolExecutionContext;

pub(in crate::modules) fn split_agentic_sast_tasks(
    tasks: Vec<String>,
) -> (Vec<String>, bool, bool, bool, bool, bool) {
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

    pub(in crate::modules) fn to_tool_json(&self) -> Value {
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

pub(in crate::modules) fn run_agentic_sast_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<AgenticSastReport> {
    let runtime = required_agentic_sast_runtime(runtime)?;
    let run = AgenticSastRun::from_input(input, ctx)?;
    let mut findings = query_agentic_sast_findings(runtime, &run, None)?;
    findings = maybe_review_agentic_sast_findings(runtime, &run, findings)?;
    if run.whitebox_static {
        mark_whitebox_static_findings(&mut findings, StaticProofState::CodeCited)?;
    }

    let persisted = persist_agentic_sast_findings(&run.target, &findings, ctx)?;
    Ok(AgenticSastReport {
        target: run.target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        cost_usd: 0.0,
    })
}

struct AgenticSastRun {
    target: PathBuf,
    options: AgenticSastInput,
    model: String,
    system_prompt: String,
    tool_policy: AgentToolPolicy,
    whitebox_static: bool,
    inventory: Vec<(String, String)>,
}

impl AgenticSastRun {
    fn from_input(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Self> {
        let target = resolve_agentic_sast_target(input, ctx)?;
        let options = AgenticSastInput::from_tool_input(input)?;
        let model = agentic_sast_model(input, ctx)?;
        let whitebox_static = whitebox_static_profile_requested(input)?;
        let system_prompt = agentic_sast_system_prompt(whitebox_static);
        let tool_policy = agent_tool_policy_for_input(input)?;
        let inventory = collect_agentic_repo_inventory(&target, 80, 2048)?;
        Ok(Self {
            target,
            options,
            model,
            system_prompt,
            tool_policy,
            whitebox_static,
            inventory,
        })
    }
}

fn required_agentic_sast_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "agentic-sast:scan requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

fn resolve_agentic_sast_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let target = resolve_tool_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "agentic-sast: target is not a directory: {}",
            target.display()
        );
    }
    Ok(target)
}

fn agentic_sast_model(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<String> {
    optional_nonempty_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context(
            "agentic-sast:scan requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
        )
}

fn agentic_sast_system_prompt(whitebox_static: bool) -> String {
    if whitebox_static {
        whitebox_static_triage_system_prompt().to_string()
    } else {
        AGENTIC_SAST_SYSTEM_PROMPT.to_string()
    }
}

fn query_agentic_sast_findings(
    runtime: &dyn AgentRuntime,
    run: &AgenticSastRun,
    review_context: Option<&str>,
) -> Result<Vec<Finding>> {
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            run.model.clone(),
            run.target.clone(),
            run.system_prompt.clone(),
            build_agentic_sast_prompt(
                &run.target,
                &run.options,
                &run.inventory,
                review_context,
                run.whitebox_static,
            ),
        )
        .with_tool_policy(run.tool_policy.clone()),
        StructuredJsonContract::new(
            "agentic-sast:scan",
            "AgenticSastFindings",
            findings_array_schema(),
        ),
        require_json_object,
    )?;
    normalize_agentic_sast_findings(
        raw,
        &run.target,
        run.options.max_findings,
        run.whitebox_static,
    )
}

fn maybe_review_agentic_sast_findings(
    runtime: &dyn AgentRuntime,
    run: &AgenticSastRun,
    findings: Vec<Finding>,
) -> Result<Vec<Finding>> {
    if run.options.passes != 2 || findings.is_empty() {
        return Ok(findings);
    }
    let review_context = summarize_agentic_findings_for_review(&findings);
    let review_findings = query_agentic_sast_findings(runtime, run, Some(&review_context))?;
    Ok(merge_agentic_sast_findings(
        findings,
        review_findings,
        run.options.max_findings,
    ))
}

fn merge_agentic_sast_findings(
    first_pass: Vec<Finding>,
    review_pass: Vec<Finding>,
    max_findings: usize,
) -> Vec<Finding> {
    let mut merged = BTreeMap::new();
    for finding in first_pass.into_iter().chain(review_pass) {
        merged.entry(finding.fingerprint.clone()).or_insert(finding);
    }
    merged.into_values().take(max_findings).collect()
}

pub(in crate::modules) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("structured output parse failed: expected a JSON object")
    }
}

pub(in crate::modules) fn findings_array_schema() -> Value {
    json!({
        "type": "object",
        "required": ["findings"],
        "additionalProperties": true,
        "properties": {
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}

pub(in crate::modules) fn collect_agentic_repo_inventory(
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

pub(in crate::modules) fn is_agentic_context_file(path: &Path) -> bool {
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

pub(in crate::modules) fn normalize_agentic_sast_findings(
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
            normalize_reported_file_path(resolve_agentic_schema_file_path(&object), target);
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

pub(in crate::modules) fn agentic_severity(value: &str) -> Severity {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "ERROR" | "HIGH" => Severity::High,
        "WARNING" | "MEDIUM" => Severity::Medium,
        "INFO" | "LOW" => Severity::Low,
        _ => Severity::Unknown,
    }
}

pub(in crate::modules) fn persist_agentic_sast_findings(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::{FindingStore, StaticProofState};
    use crate::workspace::WorkspaceTarget;
    use tempfile::tempdir;

    #[test]
    fn whitebox_triage_response_normalizes_static_schema_fields() {
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
}
