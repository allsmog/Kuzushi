use super::*;
use kuzushi_core::run_artifacts::FailureToLlmContext;

pub(crate) struct AgentDispatch {
    pub(super) config: V2Config,
    pub(super) model: String,
    pub(super) thinking_level: Option<String>,
    pub(super) cwd: PathBuf,
    pub(super) prior: AgentChatView,
    pub(super) operator_question: String,
    pub(super) agent_prompt: String,
    pub(super) run_id: String,
    pub(super) started_secs: u64,
    pub(super) screen_context_scope: Option<String>,
    pub(super) failure_context: Option<FailureToLlmContext>,
    pub(super) attached_failure_context: bool,
    pub(super) attached_screen_context: bool,
}

pub(super) fn spawn_agent_dispatch(
    dispatch: AgentDispatch,
    ticket: JobTicket,
) -> std::thread::JoinHandle<()> {
    spawn_job_worker("agent", ticket, move |sink, cancel| {
        agent_worker(
            dispatch.config,
            dispatch.model,
            dispatch.thinking_level,
            dispatch.cwd,
            dispatch.agent_prompt,
            sink,
            cancel,
        )
    })
}

pub(super) fn next_agent_run_id() -> (String, u64) {
    let started_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    (format!("agent-{started_secs}"), started_secs)
}

pub(super) fn agent_cwd(target: Option<&PathBuf>) -> PathBuf {
    target
        .cloned()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

pub(super) fn agent_target_label(target: Option<&PathBuf>) -> String {
    target
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| ".".to_string())
}

pub(super) fn thinking_level_suffix(thinking_level: Option<&str>) -> String {
    thinking_level
        .map(|level| format!(" / {level}"))
        .unwrap_or_default()
}
