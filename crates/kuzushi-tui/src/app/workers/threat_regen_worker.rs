use super::*;

pub(crate) fn threat_regen_worker(
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

pub(crate) fn run_threat_regen_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
) -> Result<ThreatPatch> {
    let runtime = worker_runtime(&config, &cwd, thinking_level)?;
    let prompt = threat_regen_prompt(&existing);
    let body = worker_response_text(
        runtime,
        model,
        cwd,
        THREAT_PATCH_SYSTEM_PROMPT.to_string(),
        prompt,
        "threat regen returned no content",
    )?;
    parse_threat_patch_json(THREAT_REGEN_PROMPT, &body)
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

pub(crate) fn run_threat_ask_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    question: &str,
) -> Result<String> {
    let runtime = worker_runtime(&config, &cwd, thinking_level)?;
    let prompt = threat_ask_prompt(question, &existing);
    let answer = worker_response_text(
        runtime,
        model,
        cwd,
        ASK_SYSTEM_PROMPT.to_string(),
        prompt,
        "threat-ask returned no content",
    )?;
    Ok(answer.to_string())
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
) -> Result<PiAgentCoreRuntime> {
    Ok(PiAgentCoreRuntime::from_config(config, cwd)?.with_thinking_level(thinking_level))
}

fn worker_response_text(
    runtime: PiAgentCoreRuntime,
    model: String,
    cwd: PathBuf,
    system_prompt: String,
    prompt: String,
    empty_message: &str,
) -> Result<String> {
    let response =
        runtime.query_blocking(AgentQueryRequest::new(model, cwd, system_prompt, prompt))?;
    non_empty_worker_response(response.text.trim(), empty_message)
}

fn non_empty_worker_response(text: &str, empty_message: &str) -> Result<String> {
    if text.is_empty() {
        anyhow::bail!("{empty_message}");
    }
    Ok(text.to_string())
}
