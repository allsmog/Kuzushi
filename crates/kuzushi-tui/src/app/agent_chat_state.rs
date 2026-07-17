use super::AgentChatView;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub(crate) struct AgentChatState {
    current: Option<AgentChatView>,
    artifact_target: Option<PathBuf>,
}

impl AgentChatState {
    pub(crate) fn current(&self) -> Option<&AgentChatView> {
        self.current.as_ref()
    }

    pub(crate) fn current_mut(&mut self) -> Option<&mut AgentChatView> {
        self.current.as_mut()
    }

    pub(crate) fn set(&mut self, current: Option<AgentChatView>) {
        self.current = current;
        self.artifact_target = None;
    }

    pub(crate) fn clear(&mut self) {
        self.current = None;
        self.artifact_target = None;
    }

    pub(crate) fn artifact_target(&self) -> Option<&Path> {
        self.artifact_target.as_deref()
    }

    pub(crate) fn set_artifact_target(&mut self, target: Option<PathBuf>) {
        self.artifact_target = target;
    }

    pub(crate) fn get_or_insert_default(&mut self) -> &mut AgentChatView {
        self.current.get_or_insert_with(AgentChatView::default)
    }
}
