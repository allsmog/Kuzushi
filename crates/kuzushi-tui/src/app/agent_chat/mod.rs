pub(crate) use super::*;
use kuzushi_core::run_artifacts::FailureToLlmContext;
pub use kuzushi_core::session_transcript::{ChatTurn, ThreadContextKey};

#[derive(Debug, Clone, PartialEq)]
pub struct AgentChatView {
    pub question: String,
    pub answer: Option<String>,
    /// Unfinished public response text, excluded from model history.
    pub partial_answer: String,
    pub running: bool,
    pub abort_requested: bool,
    pub error: Option<String>,
    pub(crate) recovery_note: Option<String>,
    pub history: Vec<ChatTurn>,
    /// Run id used for `<target>/.kuzushi/v3/runs/<run_id>/items.jsonl`.
    pub run_id: Option<String>,
    /// Wall-clock seconds since epoch when the active turn was dispatched.
    pub started_secs: u64,
    pub screen_context_scope: Option<String>,
    pub thread_context_key: Option<ThreadContextKey>,
    pub attached_turn_count: usize,
    /// True only while this turn occupies the narrow Run + read-only Ask lane.
    pub auxiliary_read_only: bool,
    pub(crate) failure_context: Option<FailureToLlmContext>,
    pub(crate) pending_failure_context: Option<FailureToLlmContext>,
}

impl Default for AgentChatView {
    fn default() -> Self {
        Self {
            question: String::new(),
            answer: None,
            partial_answer: String::new(),
            running: false,
            abort_requested: false,
            error: None,
            recovery_note: None,
            history: Vec::new(),
            run_id: None,
            started_secs: 0,
            screen_context_scope: None,
            thread_context_key: None,
            attached_turn_count: 0,
            auxiliary_read_only: false,
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
                partial_answer: self.partial_answer.clone(),
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
            partial_answer: String::new(),
            running: false,
            abort_requested: false,
            error: None,
            recovery_note: None,
            history,
            run_id: None,
            started_secs: 0,
            screen_context_scope: None,
            thread_context_key: self.thread_context_key.clone(),
            attached_turn_count: 0,
            auxiliary_read_only: false,
            failure_context: None,
            pending_failure_context: None,
        }
    }

    pub(crate) fn completed_turns(&self) -> Vec<ChatTurn> {
        let mut turns = self.history.clone();
        if self.current_turn_is_complete() {
            turns.push(ChatTurn {
                question: self.question.clone(),
                answer: self.answer.clone(),
                partial_answer: self.partial_answer.clone(),
                error: self.error.clone(),
            });
        }
        let drop = turns.len().saturating_sub(12);
        turns.drain(..drop);
        turns
    }

    pub(crate) fn bind_to_context(
        mut self,
        context_key: ThreadContextKey,
    ) -> (Self, Option<String>) {
        let reset_reason = self.context_reset_reason(&context_key);
        if reset_reason.is_some() {
            self = Self::default();
        }
        self.thread_context_key = Some(context_key);
        (self, reset_reason)
    }

    fn context_reset_reason(&self, next: &ThreadContextKey) -> Option<String> {
        match &self.thread_context_key {
            Some(current) if current == next => None,
            Some(current) => Some(current.changed_dimensions(next).join(", ")),
            None if self.has_contextual_state() => {
                Some("prior conversation had no context receipt".to_string())
            }
            None => None,
        }
    }

    fn current_turn_is_complete(&self) -> bool {
        !self.question.is_empty()
            && !self.running
            && (self.answer.is_some() || self.error.is_some())
    }

    fn has_contextual_state(&self) -> bool {
        !self.question.is_empty()
            || !self.history.is_empty()
            || self.answer.is_some()
            || self.error.is_some()
            || self.failure_context.is_some()
            || self.pending_failure_context.is_some()
    }
}
