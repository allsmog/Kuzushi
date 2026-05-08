use super::prelude::*;
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
