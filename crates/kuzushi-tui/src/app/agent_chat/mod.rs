pub(crate) use super::*;
use kuzushi_core::capabilities::ThreatModelRef;
use kuzushi_core::run_artifacts::FailureToLlmContext;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreadContextKey {
    pub canonical_target: PathBuf,
    pub target_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_model_ref: Option<ThreatModelRef>,
    /// Exact digest named by the threat-model attachment captured for this
    /// thread. Legacy mirrors have no truthful lineage ref, so this remains
    /// populated even when `threat_model_ref` is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_model_sha256: Option<String>,
    pub policy_version: String,
}

impl ThreadContextKey {
    pub(crate) fn changed_dimensions(&self, next: &Self) -> Vec<&'static str> {
        [
            (
                self.canonical_target != next.canonical_target,
                "target changed",
            ),
            (
                self.target_revision != next.target_revision,
                "target revision changed",
            ),
            (
                self.threat_model_ref != next.threat_model_ref
                    || self.attached_model_sha256 != next.attached_model_sha256,
                "threat model changed",
            ),
            (
                self.policy_version != next.policy_version,
                "Ask tool policy changed",
            ),
        ]
        .into_iter()
        .filter_map(|(changed, label)| changed.then_some(label))
        .collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentChatView {
    pub question: String,
    pub answer: Option<String>,
    pub running: bool,
    pub abort_requested: bool,
    pub error: Option<String>,
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
            running: false,
            abort_requested: false,
            error: None,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatTurn {
    pub question: String,
    pub answer: Option<String>,
    pub error: Option<String>,
}
