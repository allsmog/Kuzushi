use std::path::PathBuf;
use std::sync::mpsc::Sender;

use anyhow::{Context, Result};
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    default_scan_engines, AgentQueryRequest, AgentRuntime, Finding, FindingStore, ModuleRegistry,
    ScanCancellation, ScanEngine, ScanRunOptions, Severity, V2Config, WorkspaceTarget,
};
use kuzushi_openai::PiAgentCoreRuntime;
use uuid::Uuid;

use super::{PlanChange, PlanProposal, ThreatPatch, ASK_SYSTEM_PROMPT};

#[derive(Debug)]
pub(super) enum ScanEvent {
    Started {
        run_id: String,
        target: PathBuf,
    },
    Stage(String),
    FindingStored {
        fingerprint: String,
        severity: Severity,
        title: String,
    },
    Finished {
        run_id: String,
        findings_count: usize,
    },
    Failed {
        error: String,
    },
    Cancelled {
        run_id: String,
    },
}

#[derive(Debug)]
pub(super) enum ToolEvent {
    Finished {
        tool_name: String,
        result: serde_json::Value,
    },
    Failed {
        tool_name: String,
        error: String,
    },
}

#[derive(Debug)]
pub(super) enum AgentEvent {
    Answered { text: String },
    Failed { error: String },
}

#[derive(Debug)]
pub(super) enum PlanEvent {
    Proposed(PlanProposal),
    Failed { error: String },
}

#[derive(Debug)]
pub(super) enum ThreatPatchEvent {
    Proposed(ThreatPatch),
    Answer { text: String },
    Failed { error: String },
}

pub(super) fn background_tool_worker(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: serde_json::Value,
    thinking_level: Option<String>,
    tx: Sender<ToolEvent>,
) {
    let result = run_background_tool(
        registry,
        config,
        &workspace,
        &tool_name,
        input,
        thinking_level,
    );
    let event = match result {
        Ok(result) => ToolEvent::Finished { tool_name, result },
        Err(error) => ToolEvent::Failed {
            tool_name,
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}

fn run_background_tool(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: serde_json::Value,
    thinking_level: Option<String>,
) -> Result<serde_json::Value> {
    let store = if tool_requires_findings_store(tool_name) {
        Some(FindingStore::open(workspace.findings_db_path())?)
    } else {
        None
    };
    let runtime = if tool_uses_agent_runtime(tool_name) {
        Some(
            PiAgentCoreRuntime::from_config(
                &config,
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            )?
            .with_thinking_level(thinking_level),
        )
    } else {
        None
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: store.as_ref(),
    };
    registry.execute_tool_with_runtime(
        tool_name,
        input,
        &ctx,
        runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
    )
}

fn tool_requires_findings_store(tool_name: &str) -> bool {
    tool_name.starts_with("findings:")
        || tool_name.starts_with("systems-hunt:")
        || tool_name.starts_with("chrome-rce:")
        || matches!(
            tool_name,
            "triage:run"
                | "verify:finding"
                | "verify:exploit"
                | "patch:finding"
                | "agentic-sast:scan"
                | "carlini-threat-hunt:run"
                | "vuln-scout:audit"
                | "tob:audit"
                | "shinsa:scan"
                | "shinsa:quick-check"
                | "shinsa:nist-scan"
                | "shinsa:nist-quick-check"
                | "prompt-armor:scan"
                | "prompt-armor:analyze"
                | "prompt-armor:attack"
                | "variant:lift-pattern"
                | "variant:hunt"
                | "ndiff:hunt-variants"
                | "taint-iris:hunt"
                | "taint-iris-next:hunt"
                | "sast:scan"
                | "semgrep:scan"
                | "codeql:scan"
                | "iac-scan:scan"
        )
}

fn tool_uses_agent_runtime(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "triage:run"
            | "verify:finding"
            | "patch:finding"
            | "agentic-sast:scan"
            | "carlini-threat-hunt:run"
            | "vendor-assessment:assess"
            | "vuln-scout:audit"
            | "tob:audit"
            | "shinsa:scan"
            | "shinsa:quick-check"
            | "shinsa:nist-scan"
            | "shinsa:nist-quick-check"
            | "prompt-armor:scan"
            | "prompt-armor:analyze"
            | "prompt-armor:attack"
            | "variant:lift-pattern"
            | "variant:hunt"
            | "ndiff:extract-fix-pattern"
            | "ndiff:hunt-variants"
            | "systems-hunt:systems-invariant-extract"
            | "systems-hunt:systems-trigger-synth"
            | "systems-hunt:systems-hunt"
            | "systems-hunt:deep-semantic-cwe-select"
            | "systems-hunt:deep-semantic-hunt"
            | "taint-iris:hunt"
            | "taint-iris-next:hunt"
            | "sast:scan"
            | "threat-model:build"
            | "randori:pasta"
            | "x-ray:run"
            | "x-ray:x-ray"
    )
}

pub(super) fn tool_run_status(tool_name: &str) -> &'static str {
    match tool_name {
        "context:build" | "context-lite:index" => "indexing repository context",
        "semgrep:scan" | "codeql:scan" | "iac-scan:scan" | "secret-scan:scan" => "running scanner",
        "sast:scan" => "running SAST pipeline",
        "findings:list" => "reading persisted findings",
        "recon:http-fingerprint" | "recon:nmap" => "collecting recon evidence",
        "triage:run" => "asking model to triage persisted findings",
        "verify:finding" | "verify:exploit" => "validating finding evidence",
        "patch:finding" => "preparing remediation patch",
        _ if tool_uses_agent_runtime(tool_name) => "asking model-backed tool",
        _ => "running tool",
    }
}

pub(super) fn agent_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    question: String,
    tx: Sender<AgentEvent>,
) {
    let result = run_agent_worker(config, model, thinking_level, cwd, question);
    let event = match result {
        Ok(text) => AgentEvent::Answered { text },
        Err(error) => AgentEvent::Failed {
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}

fn run_agent_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    question: String,
) -> Result<String> {
    let runtime =
        PiAgentCoreRuntime::from_config(&config, &cwd)?.with_thinking_level(thinking_level);
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        cwd,
        ASK_SYSTEM_PROMPT.to_string(),
        question,
    ))?;
    let answer = response.text.trim();
    if answer.is_empty() {
        anyhow::bail!(
            "agent returned an empty answer. The bridge accepted the request but produced no text — usually a credential issue (missing OAuth / API key) or a model that filtered the response. Next: `auth` to check credentials, then re-run."
        );
    }
    Ok(answer.to_string())
}

const PLAN_SYSTEM_PROMPT: &str = r#"You are Kuzushi's planning assistant.
Translate the operator's natural-language goal into a strict JSON proposal.
Output ONLY JSON, starting with '{'. No prose, no code fences.
Schema:
{
  "summary": "one-sentence restatement of the goal",
  "changes": [
    {"kind": "set_option", "tool": "<tool name or null>", "global": false, "name": "<key>", "value": "<value>"},
    {"kind": "ask", "question": "<question to /ask the agent>"},
    {"kind": "note", "text": "<short operator-facing note>"}
  ],
  "unsupported": ["<natural-language reason something cannot be encoded>"]
}
Rules:
- Only emit set_option changes you are confident map to existing tool options.
- Otherwise add a string to "unsupported" instead.
- Prefer at most 6 changes."#;

pub(super) fn planner_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: String,
    tx: Sender<PlanEvent>,
) {
    let event = match run_planner_worker(config, model, thinking_level, cwd, &goal) {
        Ok(plan) => PlanEvent::Proposed(plan),
        Err(error) => PlanEvent::Failed {
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}

fn run_planner_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: &str,
) -> Result<PlanProposal> {
    let runtime =
        PiAgentCoreRuntime::from_config(&config, &cwd)?.with_thinking_level(thinking_level);
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        cwd,
        PLAN_SYSTEM_PROMPT.to_string(),
        goal.to_string(),
    ))?;
    let body = response.text.trim();
    if body.is_empty() {
        anyhow::bail!("planner returned no content");
    }
    parse_plan_json(goal, body)
}

pub(super) fn parse_plan_json(goal: &str, body: &str) -> Result<PlanProposal> {
    let json_start = body
        .find('{')
        .context("planner response had no JSON object")?;
    let json_end = body
        .rfind('}')
        .context("planner response had no closing JSON brace")?;
    if json_end <= json_start {
        anyhow::bail!("planner response had unbalanced JSON");
    }
    let json_slice = &body[json_start..=json_end];
    let parsed: serde_json::Value =
        serde_json::from_str(json_slice).context("planner JSON did not parse")?;
    let summary = parsed
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(goal)
        .to_string();
    let mut changes = Vec::new();
    if let Some(items) = parsed.get("changes").and_then(serde_json::Value::as_array) {
        for item in items {
            let kind = item
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            match kind {
                "set_option" => {
                    let name = item
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string);
                    let value = item.get("value").map(plan_value_to_string);
                    let global = item
                        .get("global")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    let tool = item
                        .get("tool")
                        .and_then(serde_json::Value::as_str)
                        .filter(|tool| !tool.is_empty())
                        .map(str::to_string);
                    if let (Some(name), Some(value)) = (name, value) {
                        changes.push(PlanChange::SetOption {
                            global,
                            tool,
                            name,
                            value,
                        });
                    }
                }
                "ask" => {
                    if let Some(question) = item
                        .get("question")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                    {
                        changes.push(PlanChange::Ask { question });
                    }
                }
                "note" => {
                    if let Some(text) = item
                        .get("text")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                    {
                        changes.push(PlanChange::Note { text });
                    }
                }
                _ => {}
            }
        }
    }
    let unsupported = parsed
        .get("unsupported")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(PlanProposal {
        goal: goal.to_string(),
        summary,
        changes,
        unsupported,
    })
}

fn plan_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

const THREAT_PATCH_SYSTEM_PROMPT: &str = r#"You are Kuzushi's threat-model patcher.
Given the current threat-model JSON and operator intent, output STRICT JSON:
{
  "summary": "one-sentence change description",
  "patch": { ... },         // deep-merge object — only changed/added keys
  "unsupported": [ ... ]    // operator-facing notes for changes you cannot encode
}
Rules:
- Output ONLY JSON, starting with '{'.
- Preserve existing fields you do not touch — the patch is a deep-merge, not a replacement.
- Set fields to null to delete them.
- Prefer additive changes."#;

const THREAT_REGEN_PROMPT: &str = "Regenerate the threat model with sharper coverage of likely attack surface, while preserving operator-edited stages and elements.";

pub(super) fn threat_regen_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    tx: Sender<ThreatPatchEvent>,
) {
    let event = match run_threat_regen_worker(config, model, thinking_level, cwd, existing) {
        Ok(patch) => ThreatPatchEvent::Proposed(patch),
        Err(error) => ThreatPatchEvent::Failed {
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}

fn run_threat_regen_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
) -> Result<ThreatPatch> {
    let runtime =
        PiAgentCoreRuntime::from_config(&config, &cwd)?.with_thinking_level(thinking_level);
    let prompt = format!(
        "OPERATOR INTENT:\n{}\n\nCURRENT THREAT MODEL JSON:\n{}",
        THREAT_REGEN_PROMPT,
        serde_json::to_string_pretty(&existing).unwrap_or_else(|_| "null".to_string())
    );
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        cwd,
        THREAT_PATCH_SYSTEM_PROMPT.to_string(),
        prompt,
    ))?;
    let body = response.text.trim();
    if body.is_empty() {
        anyhow::bail!("threat regen returned no content");
    }
    parse_threat_patch_json(THREAT_REGEN_PROMPT, body)
}

pub(super) fn threat_ask_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    question: String,
    tx: Sender<ThreatPatchEvent>,
) {
    let event = match run_threat_ask_worker(config, model, thinking_level, cwd, existing, &question)
    {
        Ok(answer) => ThreatPatchEvent::Answer { text: answer },
        Err(error) => ThreatPatchEvent::Failed {
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}

fn run_threat_ask_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    question: &str,
) -> Result<String> {
    let runtime =
        PiAgentCoreRuntime::from_config(&config, &cwd)?.with_thinking_level(thinking_level);
    let prompt = format!(
        "OPERATOR QUESTION:\n{question}\n\nCURRENT THREAT MODEL JSON:\n{}",
        serde_json::to_string_pretty(&existing).unwrap_or_else(|_| "null".to_string())
    );
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        cwd,
        ASK_SYSTEM_PROMPT.to_string(),
        prompt,
    ))?;
    let answer = response.text.trim();
    if answer.is_empty() {
        anyhow::bail!("threat-ask returned no content");
    }
    Ok(answer.to_string())
}

pub(super) fn parse_threat_patch_json(goal: &str, body: &str) -> Result<ThreatPatch> {
    let json_start = body
        .find('{')
        .context("threat-patch response had no JSON object")?;
    let json_end = body
        .rfind('}')
        .context("threat-patch response had no closing JSON brace")?;
    if json_end <= json_start {
        anyhow::bail!("threat-patch response had unbalanced JSON");
    }
    let json_slice = &body[json_start..=json_end];
    let parsed: serde_json::Value =
        serde_json::from_str(json_slice).context("threat-patch JSON did not parse")?;
    let summary = parsed
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(goal)
        .to_string();
    let patch = parsed
        .get("patch")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if !matches!(
        patch,
        serde_json::Value::Object(_) | serde_json::Value::Null
    ) {
        anyhow::bail!("threat-patch must be a JSON object");
    }
    let unsupported = parsed
        .get("unsupported")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(ThreatPatch {
        goal: goal.to_string(),
        summary,
        patch,
        unsupported,
    })
}

pub(super) fn merge_json(target: &mut serde_json::Value, patch: &serde_json::Value) {
    use serde_json::Value;
    match patch {
        Value::Object(patch_map) => {
            if !target.is_object() {
                *target = Value::Object(serde_json::Map::new());
            }
            let target_map = target.as_object_mut().expect("ensured object above");
            for (key, value) in patch_map {
                if value.is_null() {
                    target_map.remove(key);
                } else if let Some(existing) = target_map.get_mut(key) {
                    merge_json(existing, value);
                } else {
                    target_map.insert(key.clone(), value.clone());
                }
            }
        }
        _ => {
            *target = patch.clone();
        }
    }
}

pub(super) fn scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    tx: Sender<ScanEvent>,
    cancel: ScanCancellation,
    options: ScanRunOptions,
) {
    if let Err(error) = run_scan_worker(target, db_path, &tx, &cancel, &options) {
        let _ = tx.send(ScanEvent::Failed {
            error: error.to_string(),
        });
    }
}

fn run_scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    options: &ScanRunOptions,
) -> Result<()> {
    let session = start_scan_worker_session(target, db_path, tx)?;
    run_scan_worker_session(session, tx, cancel, options)
}

fn run_scan_worker_session(
    session: ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    options: &ScanRunOptions,
) -> Result<()> {
    let scanners = scan_worker_engines(options)?;
    run_scan_worker_scanners(session, tx, cancel, options, scanners)
}

fn run_scan_worker_scanners(
    session: ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    options: &ScanRunOptions,
    scanners: Vec<Box<dyn ScanEngine>>,
) -> Result<()> {
    let Some(findings) = collect_scan_worker_findings(&session, tx, cancel, scanners)? else {
        return Ok(());
    };
    finish_scan_worker_findings(session, tx, options, findings)
}

fn finish_scan_worker_findings(
    session: ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    options: &ScanRunOptions,
    mut findings: Vec<Finding>,
) -> Result<()> {
    apply_scan_worker_severity_filter(&mut findings, options);
    persist_scan_worker_findings(&session, tx, &findings)?;
    finish_scan_worker_session(session, tx, findings.len())
}

struct ScanWorkerSession {
    workspace: WorkspaceTarget,
    store: FindingStore,
    run_id: String,
}

fn start_scan_worker_session(
    target: PathBuf,
    db_path: PathBuf,
    tx: &Sender<ScanEvent>,
) -> Result<ScanWorkerSession> {
    let (workspace, store) = start_scan_worker_resources(target, db_path)?;
    let run_id = create_scan_worker_run(&store, workspace.root())?;
    announce_scan_worker_started(tx, &run_id, workspace.root());

    Ok(ScanWorkerSession {
        workspace,
        store,
        run_id,
    })
}

fn start_scan_worker_resources(
    target: PathBuf,
    db_path: PathBuf,
) -> Result<(WorkspaceTarget, FindingStore)> {
    let workspace = prepare_scan_worker_workspace(target)?;
    let store = FindingStore::open(db_path)?;
    Ok((workspace, store))
}

fn prepare_scan_worker_workspace(target: PathBuf) -> Result<WorkspaceTarget> {
    let workspace = WorkspaceTarget::new(&target)?;
    workspace.ensure_state_dir()?;
    Ok(workspace)
}

fn create_scan_worker_run(store: &FindingStore, target: &std::path::Path) -> Result<String> {
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    Ok(run_id)
}

fn announce_scan_worker_started(tx: &Sender<ScanEvent>, run_id: &str, target: &std::path::Path) {
    let _ = tx.send(ScanEvent::Started {
        run_id: run_id.to_string(),
        target: target.to_path_buf(),
    });
    let _ = tx.send(ScanEvent::Stage("running scan".to_string()));
}

fn scan_worker_engines(options: &ScanRunOptions) -> Result<Vec<Box<dyn ScanEngine>>> {
    if let Some(tasks) = options.tasks.as_ref() {
        return kuzushi_core::scan_engines_for_tasks(tasks);
    }
    Ok(default_scan_engines())
}

fn collect_scan_worker_findings(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    scanners: Vec<Box<dyn ScanEngine>>,
) -> Result<Option<Vec<Finding>>> {
    let mut findings = Vec::new();
    for scanner in scanners {
        if scan_worker_step(session, tx, cancel, scanner, &mut findings)? {
            return Ok(None);
        }
    }
    Ok(Some(findings))
}

fn scan_worker_step(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    scanner: Box<dyn ScanEngine>,
    findings: &mut Vec<Finding>,
) -> Result<bool> {
    cancel.wait_if_paused();
    if cancel_scan_worker_if_requested(session, tx, cancel, findings.len())? {
        return Ok(true);
    }
    run_scan_worker_engine(session, tx, cancel, scanner, findings)
}

fn cancel_scan_worker_if_requested(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    findings_count: usize,
) -> Result<bool> {
    if !cancel.is_cancelled() {
        return Ok(false);
    }
    session
        .store
        .complete_scan_run(&session.run_id, "cancelled", findings_count)?;
    let _ = tx.send(ScanEvent::Cancelled {
        run_id: session.run_id.clone(),
    });
    Ok(true)
}

fn run_scan_worker_engine(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    scanner: Box<dyn ScanEngine>,
    findings: &mut Vec<Finding>,
) -> Result<bool> {
    let _ = tx.send(ScanEvent::Stage(format!("running {}", scanner.id())));
    match scanner.scan(session.workspace.root(), cancel) {
        Ok(mut scanner_findings) => {
            findings.append(&mut scanner_findings);
            Ok(false)
        }
        Err(error) => handle_scan_worker_engine_error(session, tx, cancel, findings.len(), error),
    }
}

fn handle_scan_worker_engine_error(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    findings_count: usize,
    error: anyhow::Error,
) -> Result<bool> {
    if cancel.is_cancelled() {
        return cancel_scan_worker_if_requested(session, tx, cancel, findings_count);
    }
    Err(error)
}

fn apply_scan_worker_severity_filter(findings: &mut Vec<Finding>, options: &ScanRunOptions) {
    if let Some(allowed) = &options.severity {
        findings.retain(|finding| allowed.contains(&finding.severity));
    }
}

fn persist_scan_worker_findings(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    findings: &[Finding],
) -> Result<()> {
    let _ = tx.send(ScanEvent::Stage(format!(
        "persisting {} finding(s)",
        findings.len()
    )));

    for finding in findings {
        session.store.insert_finding(&session.run_id, finding)?;
        let _ = tx.send(ScanEvent::FindingStored {
            fingerprint: finding.fingerprint.clone(),
            severity: finding.severity,
            title: finding.title.clone(),
        });
    }
    Ok(())
}

fn finish_scan_worker_session(
    session: ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    findings_count: usize,
) -> Result<()> {
    session
        .store
        .complete_scan_run(&session.run_id, "completed", findings_count)?;
    let _ = tx.send(ScanEvent::Finished {
        run_id: session.run_id,
        findings_count,
    });
    Ok(())
}
