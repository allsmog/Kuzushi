use super::*;

pub(crate) fn tool_run_status(tool_name: &str) -> &'static str {
    match tool_name {
        "context:build" | "context-lite:index" => "indexing repository context",
        "semgrep:scan" | "codeql:scan" | "iac-scan:scan" | "license-scan:scan"
        | "cargo-audit:scan" | "govulncheck:scan" | "secret-scan:scan" => "searching with scanner",
        "sast:scan" => "searching SAST pipeline",
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
    sink: JobEventSink,
    cancel: ScanCancellation,
) {
    let audit = AgentCallAudit::for_prompt(&model, ASK_SYSTEM_PROMPT, &question);
    let result = run_agent_worker(config, model, thinking_level, cwd, question, cancel);
    let event = match result {
        Ok(answer) => AgentEvent::Answered {
            text: answer.text,
            audit: audit.with_cost_usd(answer.cost_usd),
        },
        Err(error) => AgentEvent::Failed {
            error: error.to_string(),
            audit,
        },
    };
    sink.send(ShellEvent::Agent(event));
}

pub(crate) struct AgentWorkerAnswer {
    pub(crate) text: String,
    pub(crate) cost_usd: f64,
}

pub(crate) fn run_agent_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    question: String,
    cancel: ScanCancellation,
) -> Result<AgentWorkerAnswer> {
    let runtime = LangGraphRuntime::from_config(&config, &cwd)?
        .with_thinking_level(thinking_level)
        .with_cancellation(cancel);
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
    Ok(AgentWorkerAnswer {
        text: answer.to_string(),
        cost_usd: response.cost_usd,
    })
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
    sink: JobEventSink,
    cancel: ScanCancellation,
) {
    let event = match run_planner_worker(config, model, thinking_level, cwd, &goal, cancel) {
        Ok(plan) => PlanEvent::Proposed(plan),
        Err(error) => PlanEvent::Failed {
            error: error.to_string(),
        },
    };
    sink.send(ShellEvent::Plan(event));
}

pub(crate) fn run_planner_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: &str,
    cancel: ScanCancellation,
) -> Result<PlanProposal> {
    let runtime = planner_runtime(&config, &cwd, thinking_level, cancel)?;
    let body = planner_response_text(runtime, model, cwd, goal)?;
    parse_plan_json(goal, &body)
}

fn planner_runtime(
    config: &V2Config,
    cwd: &PathBuf,
    thinking_level: Option<String>,
    cancel: ScanCancellation,
) -> Result<LangGraphRuntime> {
    Ok(LangGraphRuntime::from_config(config, cwd)?
        .with_thinking_level(thinking_level)
        .with_cancellation(cancel))
}

fn planner_response_text(
    runtime: LangGraphRuntime,
    model: String,
    cwd: PathBuf,
    goal: &str,
) -> Result<String> {
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        cwd,
        PLAN_SYSTEM_PROMPT.to_string(),
        goal.to_string(),
    ))?;
    non_empty_planner_response(response.text.trim())
}

fn non_empty_planner_response(text: &str) -> Result<String> {
    if text.is_empty() {
        anyhow::bail!("planner returned no content");
    }
    Ok(text.to_string())
}
