use super::prelude::*;
use super::*;

pub(crate) fn tool_run_status(tool_name: &str) -> &'static str {
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

pub(crate) fn agent_worker(
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

pub(crate) fn run_agent_worker(
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

pub(crate) const PLAN_SYSTEM_PROMPT: &str = r#"You are Kuzushi's planning assistant.
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

pub(crate) fn planner_worker(
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

pub(crate) fn run_planner_worker(
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
