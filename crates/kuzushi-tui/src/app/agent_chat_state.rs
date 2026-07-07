use super::AgentChatView;

#[derive(Debug, Clone, Default)]
pub(crate) struct AgentChatState {
    current: Option<AgentChatView>,
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
    }

    pub(crate) fn clear(&mut self) {
        self.current = None;
    }

    pub(crate) fn get_or_insert_default(&mut self) -> &mut AgentChatView {
        self.current.get_or_insert_with(AgentChatView::default)
    }
}
