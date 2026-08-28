use super::*;
use kuzushi_core::run_artifacts::FailureToLlmContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AskExecutionMode {
    Interactive,
    AuxiliaryReadOnly,
}

impl AskExecutionMode {
    pub(super) fn is_auxiliary(self) -> bool {
        self == Self::AuxiliaryReadOnly
    }
}

pub(crate) struct AgentDispatch {
    pub(super) config: V2Config,
    pub(super) model: String,
    pub(super) thinking_level: Option<String>,
    pub(super) cwd: PathBuf,
    pub(super) artifact_target: PathBuf,
    pub(super) prior: AgentChatView,
    pub(super) operator_question: String,
    pub(super) agent_prompt: String,
    pub(super) run_id: String,
    pub(super) started_secs: u64,
    pub(super) origin_phase: Option<WorkflowPhase>,
    pub(super) screen_context_scope: Option<String>,
    pub(super) failure_context: Option<FailureToLlmContext>,
    pub(super) attached_failure_context: bool,
    pub(super) attached_screen_context: bool,
    pub(super) attachment: AskAttachment,
    pub(super) thread_context_key: ThreadContextKey,
    pub(super) attached_turn_count: usize,
    pub(super) thread_reset_reason: Option<String>,
    pub(super) execution_mode: AskExecutionMode,
    pub(super) tool_policy_authorization:
        Option<kuzushi_core::runtime::AgentToolPolicyAuthorization>,
    pub(super) tool_policy_receipt: Option<kuzushi_core::runtime::AgentToolPolicyReceipt>,
}

pub(super) fn spawn_agent_dispatch(
    dispatch: AgentDispatch,
    ticket: JobTicket,
) -> std::thread::JoinHandle<()> {
    spawn_job_worker("agent", ticket, move |sink, cancel| {
        if dispatch.execution_mode.is_auxiliary() {
            read_only_agent_worker(
                dispatch.config,
                dispatch.model,
                dispatch.thinking_level,
                dispatch.cwd,
                dispatch.agent_prompt,
                dispatch.run_id,
                dispatch
                    .tool_policy_authorization
                    .expect("auxiliary Ask requires an authorized policy"),
                sink,
                cancel,
            );
        } else {
            agent_worker(
                dispatch.config,
                dispatch.model,
                dispatch.thinking_level,
                dispatch.cwd,
                dispatch.agent_prompt,
                dispatch.run_id,
                sink,
                cancel,
            );
        }
    })
}

pub(super) fn next_agent_run_id() -> (String, u64) {
    let started_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    (kuzushi_core::new_run_id("agent"), started_secs)
}

pub(super) fn thinking_level_suffix(thinking_level: Option<&str>) -> String {
    thinking_level
        .map(|level| format!(" / {level}"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::next_agent_run_id;

    #[test]
    fn agent_run_ids_do_not_collide_within_one_second() {
        let (first, first_started) = next_agent_run_id();
        let (second, second_started) = next_agent_run_id();

        assert_ne!(first, second);
        assert!(first.starts_with("agent-"));
        assert!(second.starts_with("agent-"));
        assert!(second_started >= first_started);
    }
}
