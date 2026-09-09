use super::AgentChatView;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub(crate) struct AgentChatState {
    current: Option<AgentChatView>,
    artifact_target: Option<PathBuf>,
    history: Vec<AgentChatView>,
    generation: u64,
    pub(super) recovery: super::answer_recovery::AnswerRecovery,
}

impl AgentChatState {
    pub(crate) fn current(&self) -> Option<&AgentChatView> {
        self.current.as_ref()
    }

    pub(crate) fn current_mut(&mut self) -> Option<&mut AgentChatView> {
        self.generation = self.generation.wrapping_add(1);
        self.current.as_mut()
    }

    pub(crate) fn set(&mut self, current: Option<AgentChatView>) {
        self.archive_changed_context(current.as_ref());
        self.current = current;
        self.artifact_target = None;
        self.generation = self.generation.wrapping_add(1);
    }

    pub(crate) fn clear(&mut self) {
        self.current = None;
        self.artifact_target = None;
        self.history.clear();
        self.generation = self.generation.wrapping_add(1);
    }

    pub(crate) fn artifact_target(&self) -> Option<&Path> {
        self.artifact_target.as_deref()
    }

    pub(crate) fn set_artifact_target(&mut self, target: Option<PathBuf>) {
        self.artifact_target = target;
    }

    pub(crate) fn get_or_insert_default(&mut self) -> &mut AgentChatView {
        self.generation = self.generation.wrapping_add(1);
        self.current.get_or_insert_with(AgentChatView::default)
    }

    pub(crate) fn history(&self) -> &[AgentChatView] {
        &self.history
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    fn archive_changed_context(&mut self, next: Option<&AgentChatView>) {
        let (Some(prior), Some(next)) = (&self.current, next) else {
            return;
        };
        if prior.question.is_empty() || prior.thread_context_key == next.thread_context_key {
            return;
        }
        self.history.push(prior.clone());
        let excess = self.history.len().saturating_sub(12);
        self.history.drain(..excess);
    }
}
