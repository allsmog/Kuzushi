use super::failure_handoff::{failure_handoff_model_from_context, FailureHandoffModel};
use crate::{AgentChatView, ShellApp};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AgentChatModel {
    pub(crate) model: String,
    pub(crate) session: Option<AgentChatSession>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AgentChatSession {
    pub(crate) status: &'static str,
    pub(crate) question: String,
    pub(crate) answer: Option<String>,
    pub(crate) running: bool,
    pub(crate) abort_requested: bool,
    pub(crate) error: Option<String>,
    pub(crate) history: Vec<AgentChatTurn>,
    pub(crate) failure_context: Option<FailureHandoffModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentChatTurn {
    pub(crate) question: String,
    pub(crate) answer: Option<String>,
    pub(crate) error: Option<String>,
}

pub(crate) fn agent_chat_model(app: &ShellApp) -> AgentChatModel {
    AgentChatModel {
        model: agent_model_label(app),
        session: app.agent_chat.as_ref().map(AgentChatSession::from_view),
    }
}

fn agent_model_label(app: &ShellApp) -> String {
    app.config
        .model
        .as_deref()
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "unconfigured".to_string())
}

impl AgentChatSession {
    fn from_view(agent: &AgentChatView) -> Self {
        Self {
            status: agent_status_label(agent),
            question: agent.question.clone(),
            answer: agent.answer.clone(),
            running: agent.running,
            abort_requested: agent.abort_requested,
            error: agent.error.clone(),
            history: agent.history.iter().map(AgentChatTurn::from).collect(),
            failure_context: agent
                .failure_context
                .as_ref()
                .map(failure_handoff_model_from_context),
        }
    }
}

impl From<&crate::ChatTurn> for AgentChatTurn {
    fn from(turn: &crate::ChatTurn) -> Self {
        Self {
            question: turn.question.clone(),
            answer: turn.answer.clone(),
            error: turn.error.clone(),
        }
    }
}

fn agent_status_label(agent: &AgentChatView) -> &'static str {
    if agent.abort_requested {
        "abort requested"
    } else if agent.running {
        "running"
    } else if agent.error.is_some() {
        "failed"
    } else {
        "answered"
    }
}

#[cfg(test)]
mod tests;
