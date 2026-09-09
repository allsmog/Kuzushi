use super::*;

pub(super) fn capture(chat: &AgentChatView) -> Option<ConversationSnapshot> {
    Some(ConversationSnapshot {
        version: 1,
        context: chat.thread_context_key.clone()?,
        current: ChatTurn {
            question: chat.question.clone(),
            answer: chat.answer.clone(),
            partial_answer: chat.partial_answer.clone(),
            error: chat.error.clone(),
        },
        history: chat.history.clone(),
        run_id: chat.run_id.clone()?,
        started_secs: chat.started_secs,
        screen_context_scope: chat.screen_context_scope.clone(),
        interrupted: chat.running,
    })
}

pub(super) fn restore(saved: ConversationSnapshot) -> AgentChatView {
    let mut current = saved.current;
    if saved.interrupted {
        current.answer = None;
        current.error = Some("Ask was interrupted before a final answer was saved. Review the question before sending it again.".into());
    }
    AgentChatView {
        question: current.question,
        answer: current.answer,
        partial_answer: current.partial_answer,
        error: current.error,
        history: saved.history,
        run_id: Some(saved.run_id),
        started_secs: saved.started_secs,
        screen_context_scope: saved.screen_context_scope,
        thread_context_key: Some(saved.context),
        recovery_note: Some(
            "Restored Ask history · captured context is checked again before your next question."
                .into(),
        ),
        ..Default::default()
    }
}
