use super::*;

pub(crate) fn threat_regen_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    sink: JobEventSink,
    cancel: ScanCancellation,
) {
    let prompt = threat_regen_prompt(&existing);
    let audit = AgentCallAudit::for_prompt(&model, THREAT_PATCH_SYSTEM_PROMPT, &prompt);
    let event = match run_threat_regen_worker(config, model, thinking_level, cwd, existing, cancel)
    {
        Ok((patch, cost)) => ThreatPatchEvent::Proposed {
            patch,
            audit: audit.with_cost(cost),
        },
        Err(error) => ThreatPatchEvent::Failed {
            error: error.error.to_string(),
            audit: audit.with_outcome(error.cost, error.call_attempted),
        },
    };
    sink.send(ShellEvent::Threat(event));
}

pub(crate) fn run_threat_regen_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    cancel: ScanCancellation,
) -> CostedWorkerResult<ThreatPatch> {
    let runtime = worker_runtime(&config, &cwd, thinking_level, cancel)
        .map_err(CostedWorkerError::before_call)?;
    let prompt = threat_regen_prompt(&existing);
    let (body, cost) = worker_response_text(
        runtime,
        model,
        cwd,
        THREAT_PATCH_SYSTEM_PROMPT.to_string(),
        prompt,
        "threat regen returned no content",
    )?;
    let patch = parse_threat_patch_json(THREAT_REGEN_PROMPT, &body)
        .map_err(|error| CostedWorkerError::observed(error, cost))?;
    Ok((patch, cost))
}

fn threat_regen_prompt(existing: &serde_json::Value) -> String {
    format!(
        "OPERATOR INTENT:\n{}\n\nCURRENT THREAT MODEL JSON:\n{}",
        THREAT_REGEN_PROMPT,
        pretty_threat_json(existing)
    )
}

pub(crate) fn threat_ask_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    question: String,
    sink: JobEventSink,
    cancel: ScanCancellation,
) {
    let prompt = threat_ask_prompt(&question, &existing);
    let audit = AgentCallAudit::for_prompt(&model, ASK_SYSTEM_PROMPT, &prompt);
    let event = match run_threat_ask_worker(
        config,
        model,
        thinking_level,
        cwd,
        existing,
        &question,
        cancel,
    ) {
        Ok((answer, cost)) => ThreatPatchEvent::Answer {
            text: answer,
            audit: audit.with_cost(cost),
        },
        Err(error) => ThreatPatchEvent::Failed {
            error: error.error.to_string(),
            audit: audit.with_outcome(error.cost, error.call_attempted),
        },
    };
    sink.send(ShellEvent::Threat(event));
}

pub(crate) fn run_threat_ask_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    question: &str,
    cancel: ScanCancellation,
) -> CostedWorkerResult<String> {
    let runtime = worker_runtime(&config, &cwd, thinking_level, cancel)
        .map_err(CostedWorkerError::before_call)?;
    let prompt = threat_ask_prompt(question, &existing);
    let answer = worker_response_text(
        runtime,
        model,
        cwd,
        ASK_SYSTEM_PROMPT.to_string(),
        prompt,
        "threat-ask returned no content",
    )?;
    Ok((answer.0.to_string(), answer.1))
}

fn threat_ask_prompt(question: &str, existing: &serde_json::Value) -> String {
    format!(
        "OPERATOR QUESTION:\n{question}\n\nCURRENT THREAT MODEL JSON:\n{}",
        pretty_threat_json(existing)
    )
}

fn pretty_threat_json(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_string())
}

fn worker_runtime(
    config: &V2Config,
    cwd: &PathBuf,
    thinking_level: Option<String>,
    cancel: ScanCancellation,
) -> Result<LangGraphRuntime> {
    Ok(LangGraphRuntime::from_config(config, cwd)?
        .with_thinking_level(thinking_level)
        .with_cancellation(cancel))
}

fn worker_response_text(
    runtime: LangGraphRuntime,
    model: String,
    cwd: PathBuf,
    system_prompt: String,
    prompt: String,
    empty_message: &str,
) -> CostedWorkerResult<String> {
    let response = kuzushi_core::runtime::query_blocking_checked(
        &runtime,
        AgentQueryRequest::new(model, cwd, system_prompt, prompt),
    )
    .map_err(CostedWorkerError::unresolved)?;
    let cost = response
        .checked_cost_report()
        .map_err(CostedWorkerError::unresolved)?;
    let body = non_empty_worker_response(response.text.trim(), empty_message)
        .map_err(|error| CostedWorkerError::observed(error, cost))?;
    Ok((body, cost))
}

fn non_empty_worker_response(text: &str, empty_message: &str) -> Result<String> {
    if text.is_empty() {
        anyhow::bail!("{empty_message}");
    }
    Ok(text.to_string())
}
