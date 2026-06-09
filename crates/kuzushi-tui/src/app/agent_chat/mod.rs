pub(crate) use super::*;
use kuzushi_core::run_artifacts::FailureToLlmContext;

#[derive(Debug, Clone, PartialEq)]
pub struct AgentChatView {
    pub question: String,
    pub answer: Option<String>,
    pub running: bool,
    pub abort_requested: bool,
    pub error: Option<String>,
    pub history: Vec<ChatTurn>,
    /// Synthetic run id used for `<target>/.kuzushi/runs/<run_id>/trace.jsonl`.
    pub run_id: Option<String>,
    /// Wall-clock seconds since epoch when the active turn was dispatched.
    pub started_secs: u64,
    pub(crate) failure_context: Option<FailureToLlmContext>,
    pub(crate) pending_failure_context: Option<FailureToLlmContext>,
}

impl Default for AgentChatView {
    fn default() -> Self {
        Self {
            question: String::new(),
            answer: None,
            running: false,
            abort_requested: false,
            error: None,
            history: Vec::new(),
            run_id: None,
            started_secs: 0,
            failure_context: None,
            pending_failure_context: None,
        }
    }
}

impl AgentChatView {
    pub fn fold_for_next_turn(&self, question: String) -> Self {
        let mut history = self.history.clone();
        if !self.question.is_empty()
            && (self.answer.is_some() || self.error.is_some() || !self.running)
        {
            history.push(ChatTurn {
                question: self.question.clone(),
                answer: self.answer.clone(),
                error: self.error.clone(),
            });
        }
        let drop = history.len().saturating_sub(12);
        if drop > 0 {
            history.drain(..drop);
        }
        Self {
            question,
            answer: None,
            running: false,
            abort_requested: false,
            error: None,
            history,
            run_id: None,
            started_secs: 0,
            failure_context: None,
            pending_failure_context: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatTurn {
    pub question: String,
    pub answer: Option<String>,
    pub error: Option<String>,
}
