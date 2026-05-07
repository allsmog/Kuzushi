use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::findings::{Finding, Severity, StaticProofState};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolPolicy};
use crate::whitebox_static::{
    agent_tool_policy_for_input, mark_whitebox_static_findings, whitebox_static_profile_requested,
};

use super::agentic_sast::{agentic_severity, is_agentic_context_file};
use super::generic_findings::normalize_reported_file_path;
use super::input::{
    optional_nonempty_string, optional_taint_next_string, positive_f64_input, positive_usize_input,
    string_list_input,
};
use super::json_fields::{
    parse_json_object_from_agent_text, read_object_string, read_object_string_array,
    read_object_u64, read_object_value,
};
use super::support::{resolve_tool_target, should_skip_path};
use super::taint_iris::{sanitize_rule_segment, summarize_taint_path};
use super::ToolExecutionContext;

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
pub(in crate::modules) struct TaintIrisNextPersistedRun {
    pub(in crate::modules) run_id: String,
    pub(in crate::modules) findings_db: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextReport {
    pub(in crate::modules) target: String,
    pub(in crate::modules) status: String,
    pub(in crate::modules) mode: String,
    pub(in crate::modules) count: usize,
    pub(in crate::modules) findings: Vec<Finding>,
    pub(in crate::modules) review_candidates: Vec<Finding>,
    pub(in crate::modules) selected_cwes: Vec<Value>,
    pub(in crate::modules) persisted: Option<TaintIrisNextPersistedRun>,
    pub(in crate::modules) cost_usd: f64,
    #[serde(skip)]
    pub(in crate::modules) ok: bool,
    #[serde(skip)]
    pub(in crate::modules) output: String,
    #[serde(skip)]
    pub(in crate::modules) data: Value,
}

impl TaintIrisNextReport {
    pub(in crate::modules) fn to_tool_json(&self) -> Value {
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

pub(in crate::modules) fn run_taint_iris_next_report(
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
        return Ok(taint_iris_next_missing_context_report(&plan));
    }

    let evidence = extract_taint_iris_next_evidence(&plan)?;
    let agent_prompt = build_taint_iris_next_agent_prompt(&plan, &evidence);

    if plan.mode == TaintIrisNextMode::Plan {
        return Ok(taint_iris_next_planned_report(
            &plan,
            &evidence,
            &agent_prompt,
        ));
    }

    let runtime = require_taint_iris_next_runtime(runtime)?;
    let model = require_taint_iris_next_model(input, ctx)?;
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
    let status = taint_iris_next_hunt_status(&agent);
    let data = taint_iris_next_hunt_data(&plan, &evidence, status, &agent_prompt, &agent);

    Ok(taint_iris_next_hunt_report(
        &plan, &agent, status, persisted, output, data,
    ))
}

fn taint_iris_next_missing_context_report(plan: &TaintIrisNextPlan) -> TaintIrisNextReport {
    let output = render_taint_iris_next_missing_context(plan);
    TaintIrisNextReport {
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
    }
}

fn taint_iris_next_planned_report(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
) -> TaintIrisNextReport {
    TaintIrisNextReport {
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
        output: render_taint_iris_next_output(plan, evidence, None),
        data: taint_iris_next_base_data(plan, evidence, "planned", agent_prompt),
    }
}

fn require_taint_iris_next_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.context(
        "taint-iris-next:hunt requires the pi-agent-core runtime in hunt mode. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

fn require_taint_iris_next_model(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<String> {
    optional_nonempty_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context(
            "taint-iris-next:hunt requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
        )
}

fn taint_iris_next_hunt_status(agent: &TaintIrisNextAgentResult) -> &'static str {
    if agent.outcome == "agent-output-invalid" && agent.findings.is_empty() {
        "agent-output-invalid"
    } else if agent.outcome == "agent-output-invalid" {
        "hunted-with-agent-output-invalid"
    } else {
        "hunted"
    }
}

fn taint_iris_next_hunt_data(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    status: &str,
    agent_prompt: &str,
    agent: &TaintIrisNextAgentResult,
) -> Value {
    let mut data = taint_iris_next_base_data(plan, evidence, status, agent_prompt);
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
    data
}

fn taint_iris_next_hunt_report(
    plan: &TaintIrisNextPlan,
    agent: &TaintIrisNextAgentResult,
    status: &str,
    persisted: Option<TaintIrisNextPersistedRun>,
    output: String,
    data: Value,
) -> TaintIrisNextReport {
    TaintIrisNextReport {
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
    }
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
    agent_tool_policy: AgentToolPolicy,
) -> Result<TaintIrisNextAgentResult> {
    let (raw, retry_count) = match query_taint_iris_next_agent(
        plan,
        evidence,
        agent_prompt,
        runtime,
        model,
        agent_tool_policy,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Ok(invalid_taint_iris_next_agent_result(
                plan, evidence, error, 1,
            ))
        }
    };
    normalized_taint_iris_next_agent_result(plan, evidence, raw, retry_count)
}

fn query_taint_iris_next_agent(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent_prompt: &str,
    runtime: &dyn AgentRuntime,
    model: &str,
    agent_tool_policy: AgentToolPolicy,
) -> Result<(Value, usize)> {
    let response = run_taint_iris_next_agent_prompt(
        plan,
        runtime,
        model,
        agent_prompt.to_string(),
        agent_tool_policy.clone(),
    )?;
    match parse_taint_iris_next_agent_response(response) {
        Ok(raw) => Ok((raw, 0)),
        Err(_) => {
            let repair = run_taint_iris_next_agent_prompt(
                plan,
                runtime,
                model,
                build_taint_iris_next_repair_prompt(plan, evidence),
                agent_tool_policy,
            )?;
            parse_taint_iris_next_agent_response(repair).map(|raw| (raw, 1))
        }
    }
}

fn run_taint_iris_next_agent_prompt(
    plan: &TaintIrisNextPlan,
    runtime: &dyn AgentRuntime,
    model: &str,
    prompt: String,
    agent_tool_policy: AgentToolPolicy,
) -> Result<AgentQueryResponse> {
    runtime.query_blocking(
        AgentQueryRequest::new(
            model.to_string(),
            plan.repo_root.clone(),
            TAINT_IRIS_NEXT_SYSTEM_PROMPT.to_string(),
            prompt,
        )
        .with_tool_policy(agent_tool_policy),
    )
}

fn invalid_taint_iris_next_agent_result(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    error: anyhow::Error,
    retry_count: usize,
) -> TaintIrisNextAgentResult {
    let (findings, selections, triage) = deterministic_taint_iris_next_fallback(plan, evidence);
    let warnings = vec![
        "agent returned no structured JSON output".to_string(),
        format!("parse error: {error}"),
        format!(
            "agent output invalid; returning {} deterministic linked finding candidate(s) for review",
            findings.len()
        ),
    ];
    TaintIrisNextAgentResult {
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
    }
}

fn normalized_taint_iris_next_agent_result(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    raw: Value,
    retry_count: usize,
) -> Result<TaintIrisNextAgentResult> {
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
    let mut outcome = evidence.outcome.clone();
    let agent_status = if selections.is_empty() {
        "no-selection".to_string()
    } else {
        "valid-json".to_string()
    };
    if let Some(result) = no_selection_taint_iris_next_result(
        plan,
        evidence,
        &selections,
        &findings,
        &mut warnings,
        &raw,
        retry_count,
    ) {
        return Ok(result);
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
        review_candidates: Vec::new(),
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

fn no_selection_taint_iris_next_result(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    selections: &[Value],
    findings: &[Finding],
    warnings: &mut Vec<String>,
    raw: &Value,
    retry_count: usize,
) -> Option<TaintIrisNextAgentResult> {
    if !selections.is_empty() || !findings.is_empty() || evidence.linked_stories.is_empty() {
        return None;
    }
    let (fallback_findings, fallback_selections, fallback_triage) =
        deterministic_taint_iris_next_fallback(plan, evidence);
    if fallback_findings.is_empty() {
        return None;
    }
    warnings.push(format!(
        "agent selected no CWEs; returning {} deterministic linked finding candidate(s) for review",
        fallback_findings.len()
    ));
    Some(TaintIrisNextAgentResult {
        agent_status: "no-selection-fallback".to_string(),
        selected_cwes: fallback_selections,
        findings: fallback_findings.clone(),
        review_candidates: fallback_findings,
        triage: fallback_triage.clone(),
        triage_summary: summarize_taint_iris_next_triage(&fallback_triage),
        outcome: "agent-no-selection".to_string(),
        raw_output: raw.clone(),
        structured_output_valid: true,
        structured_output_retry_count: retry_count,
        parse_error: None,
        result_text_excerpt: None,
        warnings: warnings.clone(),
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
        let file_path = normalize_reported_file_path(
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use crate::config::V2Config;
    use crate::findings::{FindingStore, TriageOutcome};
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, TriageRequest};
    use crate::workspace::WorkspaceTarget;
    use tempfile::tempdir;

    struct TaintNextRuntime {
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    impl TaintNextRuntime {
        fn new() -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
            }
        }

        fn queries(&self) -> Vec<AgentQueryRequest> {
            self.queries.lock().unwrap().clone()
        }
    }

    #[test]
    fn deterministic_taint_iris_next_severity_and_priority_cover_known_cwes() {
        assert_eq!(
            deterministic_taint_iris_next_severity("CWE-78"),
            Severity::High
        );
        assert_eq!(
            deterministic_taint_iris_next_severity("CWE-502"),
            Severity::Medium
        );
        assert_eq!(
            deterministic_taint_iris_next_severity("CWE-999"),
            Severity::Low
        );

        assert_eq!(cwe_priority("CWE-89"), 3);
        assert_eq!(cwe_priority("CWE-918"), 2);
        assert_eq!(cwe_priority("CWE-999"), 1);
    }

    impl AgentRuntime for TaintNextRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.queries.lock().unwrap().push(request);
            Ok(AgentQueryResponse {
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
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            Ok(TriageOutcome::default())
        }
    }

    fn write_js_taint_fixture(root: &Path) {
        fs::create_dir(root.join("src")).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            root.join("src/routes.ts"),
            "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
        )
        .unwrap();
    }

    fn evidence_row(cwe: &str, evidence_level: &str) -> TaintIrisNextEvidence {
        TaintIrisNextEvidence {
            cwe: cwe.to_string(),
            taint_class: "injection".to_string(),
            track: "web".to_string(),
            role: "sink".to_string(),
            pattern: "query".to_string(),
            file_path: "src/app.ts".to_string(),
            line: 1,
            snippet: "db.query(input)".to_string(),
            language: "typescript".to_string(),
            confidence: "medium".to_string(),
            catalog_signal: "sink: query".to_string(),
            evidence_level: evidence_level.to_string(),
            source: "test".to_string(),
            candidate_id: format!("{cwe}-{evidence_level}"),
            linked_story_id: None,
        }
    }

    fn evidence_result(evidence: Vec<TaintIrisNextEvidence>) -> TaintIrisNextEvidenceResult {
        TaintIrisNextEvidenceResult {
            backend: "static".to_string(),
            tool: "test".to_string(),
            evidence,
            candidates: Vec::new(),
            linked_stories: Vec::new(),
            labeled_specs: Vec::new(),
            query_count: 0,
            candidate_counts: BTreeMap::new(),
            labeled_spec_counts: BTreeMap::new(),
            linked_story_count: 0,
            backend_path_count: 0,
            structural_engine: "test".to_string(),
            triage_summary: json!({}),
            outcome: "ok".to_string(),
            warnings: Vec::new(),
            artifacts: json!({}),
        }
    }

    #[test]
    fn strongest_taint_iris_next_evidence_level_prefers_path_then_linked() {
        let result = evidence_result(vec![
            evidence_row("CWE-89", "candidate"),
            evidence_row("CWE-89", "linked"),
            evidence_row("CWE-79", "path"),
        ]);
        assert_eq!(
            strongest_taint_iris_next_evidence_level("CWE-89", &result),
            "linked"
        );
        assert_eq!(
            strongest_taint_iris_next_evidence_level("CWE-79", &result),
            "path"
        );
        assert_eq!(
            strongest_taint_iris_next_evidence_level("CWE-22", &result),
            "candidate"
        );
    }

    #[test]
    fn collect_taint_iris_next_cwes_walks_nested_json() {
        let cwes = collect_taint_iris_next_cwes(Some(&json!({
            "title": "CWE-89 and cwe-79",
            "nested": [
                {"message": "also CWE-22"},
                123,
                null
            ]
        })));

        assert!(cwes.contains("CWE-89"));
        assert!(cwes.contains("CWE-79"));
        assert!(cwes.contains("CWE-22"));
    }

    #[test]
    fn plan_mode_is_deterministic_and_does_not_require_runtime() {
        let temp = tempdir().unwrap();
        write_js_taint_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = run_taint_iris_next_report(
            &json!({"mode": "plan", "maxCatalogEntries": 1}),
            &ctx,
            None,
        )
        .unwrap()
        .to_tool_json();

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
    fn hunt_uses_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        write_js_taint_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = TaintNextRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = run_taint_iris_next_report(
            &json!({
                "mode": "hunt",
                "maxCatalogEntries": 3,
                "maxAgentFindings": 5,
                "minEvidenceLevel": "candidate"
            }),
            &ctx,
            Some(&runtime),
        )
        .unwrap()
        .to_tool_json();

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
    fn hunt_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "db.query(req.query.id)\n",
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

        let err = run_taint_iris_next_report(
            &json!({"mode": "hunt", "maxCatalogEntries": 5}),
            &ctx,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = TaintNextRuntime::new();
        let err = run_taint_iris_next_report(
            &json!({"mode": "hunt", "maxCatalogEntries": 5}),
            &ctx,
            Some(&runtime),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }
}
