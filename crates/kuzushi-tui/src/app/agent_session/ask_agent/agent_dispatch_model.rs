use super::*;
use kuzushi_core::run_artifacts::FailureToLlmContext;

pub(crate) struct AgentDispatch {
    pub(super) config: V2Config,
    pub(super) model: String,
    pub(super) thinking_level: Option<String>,
    pub(super) cwd: PathBuf,
    pub(super) operator_question: String,
    pub(super) agent_prompt: String,
    pub(super) run_id: String,
    pub(super) attached_failure_context: bool,
    pub(super) attached_screen_context: bool,
    pub(super) tx: mpsc::Sender<StampedEvent<AgentEvent>>,
    pub(super) generation: WorkerGeneration,
    pub(super) cancel: ScanCancellation,
}

pub(super) struct AgentDispatchStart {
    pub(super) state: AgentDispatchState,
    pub(super) parts: AgentDispatchParts,
}

impl AgentDispatchStart {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        prior: AgentChatView,
        operator_question: String,
        model: String,
        agent_prompt: String,
        run_id: String,
        started_secs: u64,
        screen_context_scope: Option<String>,
        failure_context: Option<FailureToLlmContext>,
        tx: mpsc::Sender<StampedEvent<AgentEvent>>,
        rx: mpsc::Receiver<StampedEvent<AgentEvent>>,
        generation: WorkerGeneration,
        cancel: ScanCancellation,
    ) -> Self {
        let attached_failure_context = failure_context.is_some();
        let state = AgentDispatchState {
            prior,
            operator_question: operator_question.clone(),
            run_id: run_id.clone(),
            started_secs,
            screen_context_scope,
            failure_context,
            generation,
            rx,
            cancel: cancel.clone(),
        };
        let parts = AgentDispatchParts {
            model,
            operator_question,
            agent_prompt,
            run_id,
            attached_failure_context,
            tx,
            generation,
            cancel,
        };
        Self { state, parts }
    }
}

pub(super) struct AgentDispatchParts {
    pub(super) model: String,
    pub(super) operator_question: String,
    pub(super) agent_prompt: String,
    pub(super) run_id: String,
    pub(super) attached_failure_context: bool,
    pub(super) tx: mpsc::Sender<StampedEvent<AgentEvent>>,
    pub(super) generation: WorkerGeneration,
    pub(super) cancel: ScanCancellation,
}

pub(super) struct AgentDispatchState {
    pub(super) prior: AgentChatView,
    pub(super) operator_question: String,
    pub(super) run_id: String,
    pub(super) started_secs: u64,
    pub(super) screen_context_scope: Option<String>,
    pub(super) failure_context: Option<FailureToLlmContext>,
    pub(super) generation: WorkerGeneration,
    pub(super) rx: mpsc::Receiver<StampedEvent<AgentEvent>>,
    pub(super) cancel: ScanCancellation,
}

pub(super) fn spawn_agent_dispatch(
    dispatch: AgentDispatch,
    wake: Option<TerminalLoopWake>,
) -> std::thread::JoinHandle<()> {
    let failure_audit =
        AgentCallAudit::for_prompt(&dispatch.model, ASK_SYSTEM_PROMPT, &dispatch.agent_prompt);
    let failure_tx = dispatch.tx.clone();
    spawn_panic_safe_worker(
        "agent",
        failure_tx,
        dispatch.generation,
        wake.clone(),
        move || {
            agent_worker(
                dispatch.config,
                dispatch.model,
                dispatch.thinking_level,
                dispatch.cwd,
                dispatch.agent_prompt,
                dispatch.tx,
                dispatch.generation,
                dispatch.cancel,
                wake,
            )
        },
        move |error| AgentEvent::Failed {
            error,
            audit: failure_audit,
        },
    )
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
