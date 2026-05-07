use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::findings::{Finding, StaticProofState};
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use crate::whitebox_static::{
    agent_tool_policy_for_input, mark_whitebox_static_findings, whitebox_static_profile_requested,
};
use crate::workspace::WorkspaceTarget;

use super::agentic_sast::{
    agentic_severity, collect_agentic_repo_inventory, findings_array_schema, require_json_object,
};
use super::generic_findings::normalize_reported_file_path;
use super::input::{
    optional_nonempty_string, positive_f64_input, positive_usize_input,
    resolve_prompt_override_for_key,
};
use super::json_fields::{read_object_string, read_object_u64, read_object_value};
use super::support::resolve_tool_target;
use super::ToolExecutionContext;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintCweSelection {
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
pub(in crate::modules) struct TaintIrisReport {
    pub(in crate::modules) target: String,
    pub(in crate::modules) count: usize,
    pub(in crate::modules) cwes: Vec<TaintCweSelection>,
    pub(in crate::modules) findings: Vec<Finding>,
    pub(in crate::modules) persisted: Option<TaintIrisPersistedRun>,
    pub(in crate::modules) cost_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::modules) degradation: Option<Value>,
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

    pub(in crate::modules) fn to_tool_json(&self) -> Value {
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
pub(in crate::modules) struct TaintIrisPersistedRun {
    pub(in crate::modules) run_id: String,
    pub(in crate::modules) findings_db: String,
}

const TAINT_CWE_SELECT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Taint CWE selector.
Return only JSON matching:
{"cwes":[{"id":"CWE-89","name":"SQL Injection","reason":"why this project should be checked"}]}.
Select only vulnerability classes that are plausible for the provided repository context."#;

const TAINT_IRIS_SYSTEM_PROMPT: &str = r#"You are Kuzushi's IRIS-style taint analysis agent.
Return only JSON matching:
{"findings":[{"title":"short title","cwe":"CWE-89","severity":"critical|high|medium|low","filePath":"relative/path","startLine":1,"message":"finding detail","sourceSinkTrace":"source -> sink proof","taintPath":[{"filePath":"relative/path","line":1,"message":"source|step|sink","snippet":"code"}],"confidence":"high|medium|low","exploitPreconditions":"required conditions"}]}.
Only report concrete source-to-sink vulnerabilities with code evidence. Omit uncertain or hypothetical findings."#;

pub(in crate::modules) fn run_taint_cwe_select(
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

pub(in crate::modules) fn run_taint_iris_report(
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
    let runtime = require_taint_iris_runtime(runtime)?;
    let model = require_taint_iris_model(input, ctx)?;

    let cwes = selected_taint_iris_cwes(input, &target, runtime, &model, options.max_cwes)?;

    if cwes.is_empty() {
        return empty_taint_iris_report(&target, cwes, ctx);
    }

    let raw = query_taint_iris_agent(input, &target, ctx, runtime, &model, &cwes, &options)?;
    let mut findings = normalize_taint_iris_findings(raw, &target, options.max_findings)?;
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SourceSinkLinked)?;
    }
    let persisted = persist_taint_iris_findings(&target, &findings, ctx)?;

    Ok(taint_iris_report(&target, cwes, findings, persisted, None))
}

fn require_taint_iris_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.context(
        "taint-iris:hunt requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

fn require_taint_iris_model(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<String> {
    optional_nonempty_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context(
            "taint-iris:hunt requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
        )
}

fn selected_taint_iris_cwes(
    input: &Value,
    target: &Path,
    runtime: &dyn AgentRuntime,
    model: &str,
    max_cwes: Option<usize>,
) -> Result<Vec<TaintCweSelection>> {
    let mut cwes = run_taint_cwe_select_value(input, target, Some(runtime), Some(model))?;
    if let Some(max_cwes) = max_cwes {
        cwes.truncate(max_cwes);
    }
    Ok(cwes)
}

fn empty_taint_iris_report(
    target: &Path,
    cwes: Vec<TaintCweSelection>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<TaintIrisReport> {
    let findings = Vec::new();
    let persisted = persist_taint_iris_findings(target, &findings, ctx)?;
    Ok(taint_iris_report(
        target,
        cwes,
        findings,
        persisted,
        Some(json!({
            "type": "legacy-inconclusive",
            "reason": "no-cwes-selected",
            "message": "No CWE classes were selected, so the IRIS taint agent did not run; treat as inconclusive, not clean.",
        })),
    ))
}

fn query_taint_iris_agent(
    input: &Value,
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    model: &str,
    cwes: &[TaintCweSelection],
    options: &TaintIrisInput,
) -> Result<Value> {
    let inventory = collect_agentic_repo_inventory(target, 80, 2048)?;
    let codeql_db = resolve_taint_codeql_db_path(target, ctx.workspace.map(WorkspaceTarget::root));
    query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            TAINT_IRIS_SYSTEM_PROMPT.to_string(),
            build_taint_iris_prompt(target, cwes, &inventory, codeql_db.as_deref(), options),
        )
        .with_tool_policy(agent_tool_policy_for_input(input)?),
        StructuredJsonContract::new(
            "taint-iris:hunt",
            "TaintIrisFindings",
            findings_array_schema(),
        ),
        require_json_object,
    )
}

fn taint_iris_report(
    target: &Path,
    cwes: Vec<TaintCweSelection>,
    findings: Vec<Finding>,
    persisted: Option<TaintIrisPersistedRun>,
    degradation: Option<Value>,
) -> TaintIrisReport {
    TaintIrisReport {
        target: target.display().to_string(),
        count: findings.len(),
        cwes,
        findings,
        persisted,
        cost_usd: 0.0,
        degradation,
    }
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
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            TAINT_CWE_SELECT_SYSTEM_PROMPT.to_string(),
            build_taint_cwe_select_prompt(target, &inventory),
        )
        .with_tool_policy(agent_tool_policy_for_input(input)?),
        StructuredJsonContract::new(
            "pipeline:taint-cwe-select",
            "TaintCweSelection",
            taint_cwe_selection_schema(),
        ),
        require_json_object,
    )?;
    parse_taint_cwe_select_raw(raw)
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

fn parse_taint_cwe_select_raw(raw: Value) -> Result<Vec<TaintCweSelection>> {
    let Value::Object(object) = raw else {
        anyhow::bail!("pipeline:taint-cwe-select output parse failed: expected a JSON object");
    };
    let Some(value) = object.get("cwes") else {
        return Ok(Vec::new());
    };
    parse_taint_cwes_value(value)
}

fn taint_cwe_selection_schema() -> Value {
    json!({
        "type": "object",
        "required": ["cwes"],
        "additionalProperties": true,
        "properties": {
            "cwes": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "type": "object",
                            "required": ["id"],
                            "additionalProperties": true,
                            "properties": {
                                "id": {"type": "string"},
                                "name": {"type": "string"},
                                "reason": {"type": "string"}
                            }
                        }
                    ]
                }
            }
        }
    })
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
        let file_path = normalize_reported_file_path(
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

pub(in crate::modules) fn summarize_taint_path(object: &Map<String, Value>) -> Option<String> {
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

pub(in crate::modules) fn sanitize_rule_segment(value: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use tempfile::tempdir;

    #[test]
    fn parses_operator_supplied_cwes_from_strings_and_objects() {
        let cwes = parse_taint_cwes_value(&json!("CWE-89, CWE-22")).unwrap();
        assert_eq!(
            cwes.iter().map(|cwe| cwe.id.as_str()).collect::<Vec<_>>(),
            vec!["CWE-89", "CWE-22"]
        );

        let cwes = parse_taint_cwes_value(&json!([
            "CWE-79",
            {"cwe": "CWE-918", "name": "SSRF", "reason": "fetches URLs"}
        ]))
        .unwrap();
        assert_eq!(cwes[0].reason, "operator-supplied");
        assert_eq!(cwes[1].id, "CWE-918");
        assert_eq!(cwes[1].name, "SSRF");
        assert_eq!(cwes[1].reason, "fetches URLs");
    }

    #[test]
    fn normalizes_taint_iris_findings_with_trace_summary() {
        let temp = tempdir().unwrap();
        let raw = json!({
            "findings": [{
                "title": "Request id reaches SQL query",
                "cwe": "CWE-89",
                "severity": "high",
                "filePath": "src/routes.ts",
                "startLine": 7,
                "message": "id is interpolated into SQL",
                "sourceSinkTrace": "req.query.id -> db.query",
                "taintPath": [{
                    "filePath": "src/routes.ts",
                    "line": 7,
                    "message": "sink",
                    "snippet": "db.query(sql)"
                }],
                "confidence": "high",
                "exploitPreconditions": "attacker controls id"
            }]
        });

        let findings = normalize_taint_iris_findings(raw, temp.path(), 10).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "taint-iris");
        assert_eq!(findings[0].rule_id, "taint-iris/cwe-89");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("Source-to-sink trace"));
        assert!(findings[0].message.contains("src/routes.ts:7"));
    }
}
