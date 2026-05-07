#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentChatView {
    pub question: String,
    pub answer: Option<String>,
    pub running: bool,
    pub abort_requested: bool,
    pub error: Option<String>,
    pub history: Vec<ChatTurn>,
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatTurn {
    pub question: String,
    pub answer: Option<String>,
    pub error: Option<String>,
}
